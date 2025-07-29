import 'dart:async';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:mobile_scanner/mobile_scanner.dart';

void main() {
  runApp(const MaterialApp(home: SASLinkerApp()));
}

class SASLinkerApp extends StatefulWidget {
  const SASLinkerApp({super.key});

  @override
  State<SASLinkerApp> createState() => _SASLinkerAppState();
}

class _SASLinkerAppState extends State<SASLinkerApp> {
  String status = "Scan the QR code on your PC";
  String sasCode = "";
  String enteredSAS = "";
  String confirmResult = "";

  final String serverIP = "http://192.168.0.102:8889";
  String myPublicKey = "";
  String myNonce = "";
  bool hasSentToThisQR = false;
  Timer? pollingTimer;
  BuildContext? awaitingContext;

  @override
  void initState() {
    super.initState();
    generateDHKeyAndNonce();
  }

  void generateDHKeyAndNonce() {
    BigInt p = BigInt.parse(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A36210000000000090563",
        radix: 16);
    BigInt g = BigInt.two;
    BigInt priv = BigInt.parse(DateTime.now().microsecondsSinceEpoch.toString());
    BigInt pub = g.modPow(priv, p);
    myPublicKey = pub.toString();
    myNonce = DateTime.now().microsecondsSinceEpoch.toString();
  }

  void onQRCodeScanned(String data) async {
    if (hasSentToThisQR) return;
    hasSentToThisQR = true;

    try {
      List<String> parts = data.split(":");
      String desktopPub = parts[0];
      String desktopNonce = parts[1];

      var response = await http.post(
        Uri.parse('$serverIP/start'),
        headers: {"Content-Type": "text/plain"},
        body: "$myPublicKey:$myNonce",
      );

      if (response.statusCode == 200) {
        setState(() {
          sasCode = response.body;
          status = "SAS from server: $sasCode\nEnter it below.";
        });
      } else {
        setState(() {
          status = "Error: ${response.statusCode} ${response.body}";
        });
      }
    } catch (e) {
      setState(() {
        status = "❌ Error scanning QR: $e";
      });
    }
  }

  void verifySAS() async {
    final response = await http.post(
      Uri.parse('$serverIP/verify'),
      headers: {"Content-Type": "text/plain"},
      body: enteredSAS,
    );
    if (response.body.contains("Awaiting confirmation")) {
      showAwaitingDialog();
      startPolling();
    } else {
      setState(() {
        status = response.body;
      });
    }
  }

  void showAwaitingDialog() {
    showDialog(
      barrierDismissible: false,
      context: context,
      builder: (context) {
        awaitingContext = context;
        return AlertDialog(
          title: const Text("✅ SAS Matched"),
          content: const Text("Awaiting confirmation from desktop..."),
        );
      },
    );
  }

  void startPolling() {
    pollingTimer = Timer.periodic(const Duration(seconds: 2), (_) async {
      try {
        final response = await http.get(Uri.parse('$serverIP/poll'));
        if (response.body == "accepted") {
          pollingTimer?.cancel();
          if (awaitingContext != null) {
            Navigator.of(awaitingContext!).pop(); // Close dialog
          }
          setState(() {
            confirmResult = "✅ Confirmed by desktop!";
          });
        }
      } catch (_) {}
    });
  }

  @override
  void dispose() {
    pollingTimer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text("SASLinker Mobile")),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          children: [
            Text(status),
            const SizedBox(height: 16),
            SizedBox(
              width: 300,
              height: 300,
              child: MobileScanner(
                onDetect: (capture) {
                  final barcode = capture.barcodes.first;
                  if (barcode.rawValue != null) {
                    onQRCodeScanned(barcode.rawValue!);
                  }
                },
              ),
            ),
            const SizedBox(height: 16),
            TextField(
              onChanged: (val) => enteredSAS = val,
              decoration: const InputDecoration(labelText: "Enter SAS here"),
            ),
            ElevatedButton(onPressed: verifySAS, child: const Text("Submit SAS")),
            const SizedBox(height: 20),
            Text("Final result: $confirmResult", style: const TextStyle(fontWeight: FontWeight.bold)),
          ],
        ),
      ),
    );
  }
}
