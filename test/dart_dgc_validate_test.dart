import 'dart:io';
import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:convert/convert.dart';
import 'package:cbor/cbor.dart';
import 'package:dart_base45/dart_base45.dart';
import 'package:dart_cose/dart_cose.dart';

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
    kidBuffer = header[HeaderParameters['kid']];
  }

  // kid could not be retreived from protected header.
  kidBuffer ??= unprotectedHeader[HeaderParameters['kid']];
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

void main() {
  var dir = Directory('dgc-testdata');
  var entries = dir.listSync(recursive: true).toList();

  entries
      .where((element) => element.path.endsWith('.json'))
      .where((element) => element.path.contains('BE'))
      .forEach((element) {
    test(element, () {
      //print(element);

      Map? testfile;

      try {
        try {
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
                  'Illegal spec: expected base45 decode, but COMPRESSED input missing.: ' +
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

        if (expectedVerify != null) {
          CoseResult result1;
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
}
