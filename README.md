# SASLinker Mobile (Flutter)

A Flutter app that links a phone to a desktop session using a **Short Authentication String (SAS)**.  
It scans a desktop QR, shows a large SAS preview, and asks the user to **manually type** the SAS.  
After a match, the app waits for the desktop to confirm and then shows a **full-screen result**.

---

## Features

- **Tight scanner window** for faster QR detection (centered 250×250 view).
- **Standard keyboard** (letters + numbers) — **no auto-fill** of the SAS input.
- Large, legible **SAS preview card**.
- **Manual SAS entry** (6 characters, alphanumeric).
- **Bottom sheet** while awaiting desktop confirmation.
- **Full-screen success/rejection** screen once finalized.
- Works with either:
  - `ip|<desktop_pubkey>:<desktop_nonce>` (preferred; auto-finds server),
  - or legacy `"<desktop_pubkey>:<desktop_nonce>"` with a fallback server URL.

---

## Requirements

- Flutter 3.x+
- Android device or emulator (camera required for QR)
- Desktop server from this project running on the **same LAN** (see the Java server)

---

## Quick Start

1. **Install deps**
   ```bash
   flutter pub get
2. Run

    flutter run

3. On desktop, run the Java server and open its web UI (serves a QR).

4. Point the phone at the QR. The camera view will disappear once scanned.