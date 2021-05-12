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
  List data = inst.getDecodedData();
  // take the first element
  var element = data.first;
  List items = element as List;

  // extract the useful information.
  final protectedHeader = items[0];

  // parse headers.
  var headers = Cbor();
  headers.decodeFromBuffer(protectedHeader);
  var headerList = headers.getDecodedData();
  if (headerList == null) {
    return 'nokid';
  }
  var header = headerList.first;

  var kid = header[HeaderParameters['kid']];
  if (null != kid) {
    var bkid = base64.encode(kid);
    return bkid;
  }
  return 'nokid';
}

Future main(List<String> arguments) {
  Directory dir = Directory('dgc-testdata');
  List<FileSystemEntity> entries = dir.listSync(recursive: true).toList();

  int count = 0;
  int success = 0;

  entries.where((element) => element.path.endsWith('.json')).forEach((element) {
    print(element);
    count++;

    Map testfile;

    try {
      testfile = jsonDecode(File.fromUri(element.uri).readAsStringSync());
      var cose = unChain(testfile['PREFIX']);
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
          print('FAIL');
        }
      } else {
        if (!result1.verified) {
          success++;
          print('SUCCESS UNVERIFIED');
        } else {
          print('FAIL');
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
      if (!(testfile['EXPECTEDRESULTS']['EXPECTEDVERIFY'] ?? false)) {
        success++;
        print('SUCCESS UNVERIFIED');
      }
    }
  });

  print("Ran $count tests of which $success succesfully.");
}
