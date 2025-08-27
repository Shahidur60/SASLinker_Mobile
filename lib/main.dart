// File: lib/main.dart
// Primary Device app: scan → /pd_init → /pd_reveal → compute SAS locally → HMAC proof → /pd_verify
import 'dart:convert';
import 'dart:math';

import 'package:cryptography/cryptography.dart' as crypto;
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:mobile_scanner/mobile_scanner.dart';

void main() => runApp(const MaterialApp(home: SASLinkerApp()));

class SASLinkerApp extends StatefulWidget {
  const SASLinkerApp({super.key});
  @override State<SASLinkerApp> createState() => _SASLinkerAppState();
}

class _SASLinkerAppState extends State<SASLinkerApp> {
  // ⚠️ Set this to your desktop's LAN IP & port (not localhost)
  String server = 'http://10.246.239.175:8889';

  // Session values
  String? sid, cSDHex;
  BigInt? sdPub;

  BigInt? pdPriv, pdPub;
  List<int>? rPD;
  String? cPDHex;

  List<int>? rSD;
  String sas = '';

  bool scanned = false, proofSent = false, accepted=false, rejected=false;
  String statusMsg = '';

  final _rnd = Random.secure();

  List<int> randBytes(int n) => List<int>.generate(n, (_) => _rnd.nextInt(256));
  String hexFromBytes(List<int> b){ final sb=StringBuffer(); for(final x in b){ sb.write(x.toRadixString(16).padLeft(2,'0')); } return sb.toString(); }
  String base32(List<int> data){
    const alph='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    var out=StringBuffer(); int curr=0,bits=0;
    for(final x in data){ curr=(curr<<8)|(x&0xff); bits+=8; while(bits>=5){ out.write(alph[(curr>>(bits-5))&31]); bits-=5; } }
    if(bits>0) out.write(alph[(curr<<(5-bits)) & 31]);
    return out.toString();
  }

  Future<void> handleScan(String payload) async {
    try {
      // QR payload: sid|sdPub|cSDHex
      final parts = payload.split('|');
      if (parts.length != 3) { throw 'Bad QR'; }
      sid = parts[0];
      sdPub = BigInt.parse(parts[1]);
      cSDHex = parts[2];

      // PD: DH + nonce + commitment
      pdPriv = BigInt.parse(hexFromBytes(randBytes(64)), radix: 16) % P;
      pdPub  = G.modPow(pdPriv!, P);
      rPD    = randBytes(16);
      final cpd = await sha256Hex([...rPD!, ...utf8.encode(pdPub.toString())]);
      cPDHex = cpd;

      // /pd_init
      final init = await http.post(Uri.parse('$server/pd_init'), body: '${sid}|${pdPub}|${cPDHex}');
      if (init.statusCode != 200) throw 'pd_init failed: ${init.body}';

      // /pd_reveal  -> returns rSD (base64)
      final rev = await http.post(Uri.parse('$server/pd_reveal'), body: '${sid}|${base64Encode(rPD!)}');
      if (rev.statusCode != 200) throw 'pd_reveal failed: ${rev.body}';
      rSD = base64Decode(rev.body);

      // Verify SD commitment (optional but good)
      final checkSD = await sha256Hex([...rSD!, ...utf8.encode(sdPub.toString())]);
      if (checkSD.toLowerCase() != cSDHex!.toLowerCase()) throw 'commit mismatch (SD)';

      // Compute SAS locally
      final shared = sdPub!.modPow(pdPriv!, P);
      final kBytes = (await crypto.Sha256().hash(utf8.encode(shared.toString()))).bytes;
      final macSas = await crypto.Hmac.sha256().calculateMac(
        <int>[...utf8.encode('SAS|'), ...rPD!, ...rSD!],
        secretKey: crypto.SecretKey(kBytes.sublist(0, 32)),
      );
      final b32 = base32(macSas.bytes).replaceAll('=','');
      final six = b32.substring(0,6);
      sas = six.replaceAll('2','0').replaceAll('3','1').replaceAll('4','2').replaceAll('5','3').replaceAll('6','4').replaceAll('7','5');

      setState((){ scanned = true; statusMsg = 'Compare the SAS on both devices.'; });

    } catch (e) {
      setState(()=>statusMsg = 'Scan error: $e');
    }
  }

  Future<void> sendProof() async {
    try {
      if (sid==null || rPD==null || rSD==null || pdPub==null || sdPub==null) return;

      final shared = sdPub!.modPow(pdPriv!, P);
      final kBytes = (await crypto.Sha256().hash(utf8.encode(shared.toString()))).bytes;

      // transcript = sid|sdPub|pdPub|cSD|cPD|rSD|rPD|SAS
      final transcript = '${sid}|${sdPub}|${pdPub}|${cSDHex}|${cPDHex}|'
                         '${base64Encode(rSD!)}|${base64Encode(rPD!)}|${sas}';
      final mac = await crypto.Hmac.sha256().calculateMac(
        utf8.encode(transcript),
        secretKey: crypto.SecretKey(kBytes.sublist(0,32)),
      );
      final proofB64 = base64Encode(mac.bytes);

      final resp = await http.post(Uri.parse('$server/pd_verify'), body: '${sid}|$proofB64');
      if (resp.statusCode != 200) throw 'verify failed: ${resp.body}';

      setState((){ proofSent = true; statusMsg = 'Proof sent. Complete final check on desktop.'; });
      poll();

    } catch (e) {
      setState(()=>statusMsg = 'Proof error: $e');
    }
  }

  Future<void> poll() async {
    while(mounted && !accepted && !rejected){
      await Future.delayed(const Duration(seconds: 2));
      try {
        final r = await http.get(Uri.parse('$server/state'));
        if (r.statusCode != 200) continue;
        final j = jsonDecode(r.body);
        if (j['status'] == 'accepted') { setState(()=>accepted=true); return; }
        if (j['status'] == 'rejected' || j['status'] == 'expired') { setState(()=>rejected=true); return; }
      } catch(_) {}
    }
  }

  @override
  Widget build(BuildContext context) {
    if (accepted) {
      return const Scaffold(body: Center(child: Text('🎉 Linked!', style: TextStyle(fontSize: 28, fontWeight: FontWeight.bold))));
    }
    if (rejected) {
      return const Scaffold(body: Center(child: Text('❌ Rejected / Expired', style: TextStyle(fontSize: 22, color: Colors.red))));
    }

    return Scaffold(
      appBar: AppBar(title: const Text('SASLinker — Phone')),
      body: Padding(
        padding: const EdgeInsets.all(20),
        child: Center(
          child: scanned
            ? Column(mainAxisAlignment: MainAxisAlignment.center, children: [
                const Text('Short Authentication String', style: TextStyle(fontSize: 16)),
                const SizedBox(height: 8),
                Container(
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(border: Border.all(color: Colors.blue, width: 2), borderRadius: BorderRadius.circular(12)),
                  child: Text(sas, style: const TextStyle(fontSize: 34, fontWeight: FontWeight.bold)),
                ),
                const SizedBox(height: 12),
                ElevatedButton(onPressed: proofSent ? null : sendProof, child: const Text('I see this code — Send Proof')),
                const SizedBox(height: 10),
                Text(statusMsg, textAlign: TextAlign.center),
              ])
            : Column(mainAxisAlignment: MainAxisAlignment.center, children: [
                const Text('📷 Scan the QR on your desktop', style: TextStyle(fontSize: 18)),
                const SizedBox(height: 16),
                SizedBox(width: 260, height: 260, child: ClipRRect(
                  borderRadius: BorderRadius.circular(12),
                  child: MobileScanner(onDetect: (cap){
                    for (final b in cap.barcodes) {
                      final v = b.rawValue; if (v != null) { handleScan(v); break; }
                    }
                  }),
                )),
                const SizedBox(height: 8),
                Text(statusMsg, textAlign: TextAlign.center),
              ]),
        ),
      ),
    );
  }

  // ---- crypto constants (same as server) ----
  final BigInt P = BigInt.parse(
      'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A36210000000000090563',
      radix: 16);
  final BigInt G = BigInt.from(2);

  Future<String> sha256Hex(List<int> data) async {
    final h = await crypto.Sha256().hash(data);
    final b = h.bytes; final sb = StringBuffer();
    for(final x in b){ sb.write(x.toRadixString(16).padLeft(2,'0')); }
    return sb.toString();
  }
}
