import 'dart:io';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:flutter/foundation.dart';
import 'package:test/test.dart';
import 'package:convert/convert.dart';
import 'package:cbor/cbor.dart';
import 'package:dart_base45/dart_base45.dart';
import 'package:dart_cose/dart_cose.dart';
import 'package:x509b/x509.dart';


const _KID_HEADER = 4;

enum DCCType{
  vaccination,
  test,
  recovery
}

List<int> unChain(String input) {
  // trim HC1
  // Compressed COSE (Base45) (548 chars):
  final trimmedQrString = input.substring(input.indexOf(':') + 1);

  if ('HC1' != input.substring(0, input.indexOf(':'))) {
    throw Exception('Invalid prefix');
  }
  //print(trimmedQrString);
  //print('');

  // Base45 decode
  // COSE (Hex) (712 chars):
  //
  final compressedCose = Base45.decode(trimmedQrString);
  //print(hex.encode(compressedCose));
  //print('');

  // unzip
  // Cose
  ZLibCodec zlib = new ZLibCodec();
  final List<int> cose = zlib.decode(compressedCose);
  return cose;
}

String extractKid(List<int> cose) {
  var inst = Cbor();
  inst.decodeFromList(cose);
  List? data = inst.getDecodedData();
  // take the first element
  var element = data!.first;
  List items = element as List;

  // extract the useful information.
  final protectedHeader = items[0];
  final unprotectedHeader = items[1];

  var kidBuffer;
  // parse headers.
  var headers = Cbor();
  headers.decodeFromBuffer(protectedHeader);
  var headerList = headers.getDecodedData();
  if (headerList != null) {
    var header = headerList.first;
    kidBuffer = header[_KID_HEADER];
  }

  // kid could not be retreived from protected header.
  kidBuffer ??= unprotectedHeader[_KID_HEADER];
  var kid = Uint8List.view(kidBuffer.buffer, 0, kidBuffer.length);
  if (kid.length > 8) {
    kid = kid.sublist(0, 8);
  }
  if (null == kid) {
    throw Exception('kid could not be extracted');
  }

  var bkid = base64.encode(kid);
  return bkid;
}

var zlib = ZLibCodec();

dynamic toDart(ASN1Object obj) {
  if (obj is ASN1Null) return null;
  if (obj is ASN1Sequence) return obj.elements.map(toDart).toList();
  if (obj is ASN1Set) return obj.elements.map(toDart).toSet();
  if (obj is ASN1Integer) return obj.valueAsBigInteger;
  if (obj is ASN1ObjectIdentifier) return ObjectIdentifier.fromAsn1(obj);
  if (obj is ASN1BitString) return obj.stringValue;
  if (obj is ASN1Boolean) return obj.booleanValue;
  if (obj is ASN1OctetString) return obj.stringValue;
  if (obj is ASN1PrintableString) return obj.stringValue;
  if (obj is ASN1UtcTime) return obj.dateTimeValue;
  if (obj is ASN1IA5String) return obj.stringValue;
  if (obj is ASN1UTF8String) return obj.utf8StringValue;
  if( obj.valueBytes().isNotEmpty){
  switch (obj.tag) {
    case 0xa0:
      return toDart(ASN1Parser(obj.valueBytes()).nextObject());
    case 161:
      return toDart(ASN1Parser(obj.valueBytes()).nextObject());
    case 162:
      return toDart(ASN1Parser(obj.valueBytes()).nextObject());
    case 0x86:
      return utf8.decode(obj.valueBytes());
  }
  }
  throw ArgumentError(
      'Cannot convert $obj (${obj.runtimeType}) to dart object.');
}

printSeq(ASN1Sequence seq){
  print("SEQUENCE (${seq.elements.length})");
  seq.elements.forEach((element){
    printObject(element);
  });
}

printSet(ASN1Set set){
  print("SET (${set.elements.length})");
  set.elements.forEach((element) {
    printObject(element);
  });
}

printObjectIdentifier(ASN1ObjectIdentifier oid){
  print("OBJECT IDENTIFIER");
  ObjectIdentifier objectIdentifier = ObjectIdentifier.fromAsn1(oid);
  print(objectIdentifier.toString() + " (${oid.identifier})");
}

printObject(ASN1Object obj){
  print("OBJECT with tag: ${obj.tag}");
  try{
    var d = toDart(obj);
    print(d);
  }
  on Error catch(e){
    print(e);
  }
  if( obj is ASN1ObjectIdentifier){
    printObjectIdentifier(obj as ASN1ObjectIdentifier);
  }
  if( obj is ASN1Set ){
    printSet(obj as ASN1Set);
  }
  if( obj is ASN1Sequence ){
    printSeq(obj as ASN1Sequence);
  }

}

void main() {
  var dir = Directory('dgc-testdata');
  var entries = dir.listSync(recursive: true).toList();

  entries
      .where((element) => element.path.endsWith('.json'))
      .forEach((element) {
    test(element, () {
      //print(element);

      Map? testfile;

      try {
        try {
          print('----');
          print(element.uri);
          testfile = jsonDecode(File.fromUri(element.uri).readAsStringSync());
        } on Exception catch (e) {
          print(e);
          expect(null, e, reason: 'Invalid Json!');
        }

        var expectedResults = testfile!['EXPECTEDRESULTS'];
        bool? expectedValidObject = expectedResults['EXPECTEDVALIDOBJECT'];
        bool? expectedSchemaValidation =
            expectedResults['EXPECTEDSCHEMAVALIDATION'];
        bool? expectedDecode = expectedResults['EXPECTEDDECODE'];
        bool? expectedVerify = expectedResults['EXPECTEDVERIFY'];
        bool? expectedUnprefix = expectedResults['EXPECTEDUNPREFIX'];
        bool? expectedDecompression = expectedResults['EXPECTEDCOMPRESSION'];
        bool? expectedBase45Decode = expectedResults['EXPECTEDB45DECODE'];
        bool? expectedPictureDecode = expectedResults['EXPECTEDPICTUREDECODE'];
        bool? expectedKeyUsage = expectedResults['EXPECTEDKEYUSAGE'];

        var unprefixed; // output of next step
        var input;
        if (testfile['PREFIX'] != null) {
          input = testfile['PREFIX'];
        }
        if (expectedUnprefix != null) {
          // PROCESS PREFIX
          if ('HC1' == input.substring(0, input.indexOf(':'))) {
            unprefixed = testfile['PREFIX'].substring(input.indexOf(':') + 1);
          }

          if (expectedUnprefix) {
            expect(unprefixed, testfile['BASE45'], reason: 'HC1 known prefix');
          } else {
            expect(unprefixed, null, reason: 'expected prefix mismatch');
            return; // next file
          }
        }

        if (testfile['BASE45'] != null) {
          unprefixed = testfile['BASE45'];
        } else {
          unprefixed = testfile['PREFIX'].substring(input.indexOf(':') + 1);
        }
        var compressedCose; // output of next step
        if (null != expectedBase45Decode) {
          // PROCESS BASE45
          try {
            compressedCose = Base45.decode(unprefixed);
          } on Exception catch (e) {
            print(e);
            if (expectedBase45Decode) {
              fail('expected Base45 decode, but exception occured');
            } else {
              return; // expected to fail, so process next file.
            }
          }

          if (expectedBase45Decode) {
            var expected = testfile['COMPRESSED'];
            if (null == expected) {
              print(
                  'Warning: Invalid spec: expected base45 decode, but COMPRESSED input missing.: ' +
                      element.toString());
            } else {
              expected = expected.toString().toLowerCase();
              expect(hex.encode(compressedCose), expected,
                  reason: 'base45 decode');
            }
          } else {
            expect(compressedCose, null,
                reason: 'expected base45 decode to fail.');
            // next file
          }
        }

        if (testfile['COMPRESSED'] != null) {
          compressedCose = hex.decode(testfile['COMPRESSED']);
        } else {
          compressedCose = Base45.decode(unprefixed);
        }

        List<int> cose; // output of the next step
        if (expectedDecompression != null) {
          // PROCESS DECOMPRESSION
          try {
            cose = zlib.decode(compressedCose);

            if( compressedCose.length > cose.length ){
              print('Warning: useless compression. Compressed size (${compressedCose.length}) is larger than raw COSE (${cose.length}).');
            }
          } on Exception catch (e) {
            print(e);
            if (expectedDecompression) {
              fail('expected zlib decompression, but exception occured: $e');
            } else {
              return; // next file
            }
          }

          if (expectedDecompression) {
            expect(
                hex.encode(cose), (testfile['COSE']).toString().toLowerCase(),
                reason: 'match cose');
          } else {
            expect(cose, null, reason: 'expected decompression to fail.');
            return; // next file
          }
        }

        var types = new List<DCCType>.empty(growable: true);
        if (expectedDecode != null) {
          try {
            var cbor = hex.decode(testfile['CBOR']);
            var inst = Cbor();
            inst.decodeFromList(cbor);
            var data = inst.getDecodedData();
            var result;
            if (data is List) {
              result = data.first;
            } else {
              result = data;
            }
            if (expectedDecode) {
              expect(result[-260][1], testfile['JSON'],
                  reason: 'json mismatch');

              var dgc = result[-260][1] as Map;
              if( dgc.containsKey('v')){
                types.add(DCCType.vaccination);
              }
              else if( dgc.containsKey('t')){
                types.add(DCCType.test);
              }
              else if( dgc.containsKey('r')){
                types.add(DCCType.recovery);
              }
            } else {
              expect(result, null);
              return; // next file
            }
          } on Error catch (e) {
            if (!expectedDecode) {
              expect(true, true, reason: 'decoding failed');
              return; // next file
            }
          }
        }

        if (testfile['COSE'] != null) {
          cose = hex.decode(testfile['COSE']);
        } else {
          cose = zlib.decode(compressedCose);
        }

        CoseResult result1;
        if (expectedVerify != null) {

          try {
            var kid = extractKid(cose);

            // first decode to get the KID.
            result1 = Cose.decodeAndVerify(
                cose, {kid: testfile['TESTCTX']['CERTIFICATE']});

            if (expectedVerify) {
              if (!result1.verified) {
                print(result1.errorCode);
              }
              expect(result1.verified, true, reason: 'verified');
            } else {
              expect(result1.verified, false,
                  reason: 'expected verify to fail');
              return; // next file
            }
          } on Exception catch (e) {
            if (expectedVerify) {
              expect(true, false, reason: 'Expect verify, but got exception');
            } else {
              expect(true, true, reason: 'Expect verify to fail');
              return; // next file
            }
          }
        }

        // check if the certificate has extensions enabled.
        X509Certificate cert = X509Certificate.fromAsn1(ASN1Sequence.fromBytes( base64Decode(testfile['TESTCTX']['CERTIFICATE'])));
        if( (cert.tbsCertificate.extensions?.length ?? 0) > 0) {
          //print(cert);
          //print('Allowed issuers:');
          var allowed =
          cert.tbsCertificate.extensions?.where((e) => e.extnId.name == 'extKeyUsage')
          .map((e) => e.extnValue).cast<ExtendedKeyUsage>().expand((e) => e.ids).toList(growable: false);

          if( null != allowed && allowed.length > 0 && expectedKeyUsage != null ){
            if( types.contains(DCCType.vaccination)){
              expect(allowed.where((oid) => oid.name == 'Vaccination Issuers').isNotEmpty, expectedKeyUsage,reason: 'Key does not support signing vaccination DCCs. Allowed: ' + allowed.toString());
            }
            if( types.contains(DCCType.test)){
              expect(allowed.where((oid) => oid.name == 'Test Issuers').isNotEmpty, expectedKeyUsage, reason: 'Key does not support signing test DCCs. Allowed: ' + allowed.toString());
            }
            if( types.contains(DCCType.recovery)){
              expect(allowed.where((oid) => oid.name == 'Recovery Issuers').isNotEmpty, expectedKeyUsage, reason: 'Key does not support recovery DCCs. Allowed: ' + allowed.toString());
            }
          }
        }
      } on Exception catch (e) {
        print('EXCEPTION');
        print(e);
        fail('Unexpected exception');
      } on Error catch (e) {
        print('ERROR');
        print(e);
        print(e.stackTrace);
        fail('Unexpected Error');
      }
    });
  });





  test('trust', () async {
    return; // diable test.
    var trustrootpem = '''-----BEGIN CERTIFICATE-----
MIIFQTCCAymgAwIBAgIULTspcOgGgEEdJECdg/XQe4gDp5kwDQYJKoZIhvcNAQEL
BQAwUjELMAkGA1UEBhMCQkUxFzAVBgNVBAoTDkV1cm9wZWFuIFVuaW9uMSowKAYD
VQQDEyFEaWdpdGFsIEdyZWVuIENlcnRpZmljYXRlIEdhdGV3YXkwHhcNMjEwNTIw
MDczMjMzWhcNMjIwNTIwMDczMjMzWjBSMQswCQYDVQQGEwJCRTEXMBUGA1UEChMO
RXVyb3BlYW4gVW5pb24xKjAoBgNVBAMTIURpZ2l0YWwgR3JlZW4gQ2VydGlmaWNh
dGUgR2F0ZXdheTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALO1AtMH
57pU/PfFvqdJwIMPCiavPizzl0V6ehDugn13USn2iKO2MUcucL2m5tc8AnqhIXtu
gitGai43llHF0qq39uCmuK5GKjmi4tu9aVOTypPxRaRSjmiuZrEtcL0AAj9x93t5
DKjyXsTez6buldrVjpwFTlUcwbTxZfEgDRx+Bgt4U3x/1ZBjIjETGU2c3AlztqeB
yxYeaBi6lfa5FNRdhPkD6T/OkiadLmLllhGTnSHQZMpi8oYl0f+IawOnmx3d4AtF
zWIi8TGCwaCtv87AvYBwnTy3ufR81KvN2GPneEo2whY3+y7SNY2IWMTYhluQ8mDr
3bn+xRRLBF5JQVttqLCAtQj8pb219E65xETegncDtE65uVmOgZmQkBwvtIoyxQMw
K7sK+2ZuARk7cLVOddVxIkQ19EAEsumlYN9gS02iIE06BtszeVMQ9iFn4sZu6n7J
i7gECxven1CtaXuCuRvsTco7LOlnrvcpSiwFKqskh0sEpYffGJkaP74xJup4EG8Q
cYZA1PREXyceQFL7uvrLSWSk5pMxUq/fU9bBE7quLQrUIIC8JfGgQFTv/rxjPvE/
Pbf5qMZsEdLcNBkY/eEt9vlZ6InrY6VEBurzWAAp+GHA9b8M4o/7vqwYwItOxtnm
tCAHK9DHFnumONig26ibqJ/kd2gIBylmvO7rAgMBAAGjDzANMAsGA1UdDwQEAwIH
gDANBgkqhkiG9w0BAQsFAAOCAgEAlM01JmCqeBHevidzJdnOcywIaoEOzGnWJ8rg
DWOhIam5y2kxGQsdYUE6ssLMXp3msMf9K86itBn1UX2bhV/OvvVeVMi5FRaIjRkn
b2+U3MhSgOffvJtqRtMGwQY4dDGyqt/M5ktEl3INNSklli9tUm8CtgAYEcJhSmVr
G0DSlXb9B7esbZcYSqfuGx8nP+mwhflfH10v8GQcYKwUNN2KHL3/6SP15WfvXPPr
y+gGKLw8gOwa1b9EYiNGCFJANERL+SuF64AZZFBEN4PjD5ZA8M53pmM8DiDB8ism
F7DYX0j1AZECHr9DG1lco4LhRf3GHYcVYLYDDNBm/HVp7klt4JwWGYzDsstzY133
JgPUPjs38qj+yBGgolgVyaaz2PIGy7S9VBVN2JLlsCHFqWZoNSTWM8JSL+7XI9F+
zgdf0n9Fx0sBMcDKt+InOb9YHxbPMnHaVlznEpaIJJjgpyZQ3tHWnxsOCyY9sXgc
ezfqBCauJi63YNAPgyDvE4P9HGRwdcxMAjgwQm3k2zfHT/fhcrX8inM2wFXQ/AFS
n0JTcCKXd4el35J3drLnfkV4r/aV/zt8C+WfLdjGaBx1rBB4tgeHeXAO/Tt6MDla
Z/AjYumq/z7rP/EMHdEpamouG+c/lCNdZA30jqDEIh+DYlNjo/ByDjqhRe3/+bg/
K3XfzZs=
-----END CERTIFICATE-----''';

    var httpClient = HttpClient();
      var request = await httpClient.getUrl(Uri.parse('https://cert-app.be/trustList/DSC.json'));
      var response = await request.close();
      var dscBytes = await consolidateHttpClientResponseBytes(response);
      var DSCs = jsonDecode(utf8.decode(dscBytes));

      request = await httpClient.getUrl(Uri.parse('https://cert-app.be/trustList/CSCA.json'));
      response = await request.close();
      var cscaBytes = await consolidateHttpClientResponseBytes(response);
      var CSCAs = jsonDecode(utf8.decode(cscaBytes));

      expect(DSCs, isA<List>());
      expect(CSCAs, isA<List>());

      X509Certificate trustRoot = parsePem(trustrootpem).first;
    print('trustRoot rawData parsed:');
    print(trustRoot);

      CSCAs.where((csca) => csca['country'] == 'BE').forEach((csca){


          X509Certificate cscaCert = X509Certificate.fromAsn1(ASN1Sequence.fromBytes(base64Decode(csca['rawData'])));
          print('cscaCert rawData parsed:');
          print(cscaCert);

          var p = ASN1Parser(base64Decode(csca['signature']));
          var i = 0;
          while (p.hasNext()) {
            i++;
            var o1 = p.nextObject();

            printObject(o1);


          }

      });




  });


}
