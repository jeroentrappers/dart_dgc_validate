import 'dart:convert';

import 'dart:io';

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

  var kid;
  // parse headers.
  var headers = Cbor();
  headers.decodeFromBuffer(protectedHeader);
  var headerList = headers.getDecodedData();
  if (headerList != null) {
    var header = headerList.first;
    kid = header[HeaderParameters['kid']];
  }

  // kid could not be retreived from protected header.
  kid ??= unprotectedHeader[HeaderParameters['kid']];

  if (null == kid) {
    throw Exception('kid could not be extracted');
  }

  var bkid = base64.encode(kid);
  return bkid;
}

void main(List<String> arguments) {
  var dir = Directory('dgc-testdata');
  var entries = dir.listSync(recursive: true).toList();

  var count = 0;
  var invalid = 0;
  var success = 0;

  entries.where((element) => element.path.endsWith('.json')).forEach((element) {
    Map? testfile;

    try {
      try {
        testfile = jsonDecode(File.fromUri(element.uri).readAsStringSync());
        count++;
      } on Exception catch (e) {
        invalid++;
        print(e);
        print('!!! JSON INVALID');
        return;
      }

      var expectedResults = testfile!['EXPECTEDRESULTS'];
      bool expectedValidObject =
          expectedResults['EXPECTEDVALIDOBJECT'] ?? false;
      bool expectedSchemaValidation =
          expectedResults['EXPECTEDSCHEMAVALIDATION'] ?? false;
      bool expectedDecode = expectedResults['EXPECTEDDECODE'] ?? false;
      bool expectedVerify = expectedResults['EXPECTEDVERIFY'] ?? false;
      bool expectedUnprefix = expectedResults['EXPECTEDUNPREFIX'] ?? false;
      bool expectedDecompression =
          expectedResults['EXPECTEDCOMPRESSION'] ?? false;
      bool expectedBase45Decode = expectedResults['EXPECTEDB45DECODE'] ?? false;
      bool expectedPictureDecode =
          expectedResults['EXPECTEDPICTUREDECODE'] ?? false;

      var input = testfile!['PREFIX'];
      var unprefixed;
      if (expectedUnprefix) {
        if ('HC1' != input.substring(0, input.indexOf(':'))) {
          print('INVALID PREFIX');
        }
        unprefixed = testfile['PREFIX'].substring(input.indexOf(':') + 1);
      } else {
        return; // process next file.
      }

      var cose;
      try {
        cose = unChain(testfile['PREFIX']);
      } on Exception catch (e) {
        print(e);
        print('!!! UNCHAIN ISSUE');

        return;
      }

      var kid = extractKid(cose);

      // first decode to get the KID.
      var result1 =
          Cose.decodeAndVerify(cose, {kid: testfile['TESTCTX']['CERTIFICATE']});

      print(result1.verified);

      if (testfile['EXPECTEDRESULTS']['EXPECTEDVERIFY']) {
        if (result1.verified) {
          success++;
          print('SUCCESS VERIFIED');
        } else {
          print('FAIL: expected verification');
        }
      } else {
        if (!result1.verified) {
          success++;
          print('SUCCESS UNVERIFIED');
        } else {
          print('FAIL expected unverified');
        }
      }
    } on Exception catch (e) {
      print('EXCEPTION');
      print(e);
      if (null == testfile) {
        print('INPUT ERROR');
      } else {
        if (!(testfile['EXPECTEDRESULTS']['EXPECTEDVERIFY'] ?? false)) {
          success++;
          print('SUCCESS UNVERIFIED');
        }
      }
    } on Error catch (e) {
      print('ERROR');
      print(e);
      if (!(testfile!['EXPECTEDRESULTS']['EXPECTEDVERIFY'] ?? false)) {
        success++;
        print('SUCCESS UNVERIFIED');
      }
    }
  });

  print(
      "Ran $count tests of which $success succesfully. $invalid invalid test spec files.");
}
