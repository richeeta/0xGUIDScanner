# 0xGUID Scanner: UUID/GUID Detection, Classification & Weakness Analysis  
**Author**: Richard Hyunho Im ([@richeeta](https://github.com/richeeta)) at [Route Zero Security](https://routezero.security)

## Description

0xGUID Scanner is a Burp Suite **Professional Edition** extension that passively detects and classifies UUIDs (versions 1 through 5 and malformed variants) embedded in HTTP traffic. It identifies weak, insecure, or predictable UUIDs through detailed analysis of time-based patterns, MAC addresses, name+namespace reversal attacks (v3/v5), entropy weakness, and more. It is designed for AppSec professionals, red teams, and bug bounty researchers who need to detect UUID leakage or insecure identifier generation in real-world web traffic.

### Issues Reported by 0xGUID Scanner  
![ScannerReport](https://github.com/richeeta/0xGUIDScanner/blob/main/screenshot.png)

## Features

### Core Capabilities

* Full support for UUID **versions 1–5**, plus malformed/fake variants
* MAC address & timestamp analysis (v1)
* Clock sequence & DCE domain flagging (v2)
* Reversal attempts of MD5/SHA-1 hashes to guess name+namespace (v3/v5)
* Duplicate and randomness detection for v4
* Decoding support: Base64 + URL-encoded
* MAC vendor identification from static and dynamic OUI prefix maps
* Findings integrated directly into Burp’s Scanner issue list


## ⚠️ Requirements
- **Burp Suite Professional Edition**
- **Java 17 or later**
- **Apache Maven** (for building from source)

Burp Suite Community Edition is not supported since Burp Scanner is a Pro-exclusive feature. (Sorry!) 

## Installation

### Option 1: Download from Releases

Visit the [Releases](https://github.com/richeeta/0xGUIDScanner/releases) tab and download the latest `.jar`.  
Then in Burp Suite Professional:

1. Go to **Extender → Extensions**
2. Click **Add**, select **Java**, and upload the `.jar`

### Option 2: Build from Source

```bash
git clone https://github.com/richeeta/0xGUIDScanner.git
cd 0xGUIDScanner
mvn clean package
```

Then load the JAR from `target/zeroxguidscanner-1.0-SNAPSHOT-jar-with-dependencies.jar`.

## Usage

Once installed, 0xGUID Scanner passively analyzes all HTTP traffic in Burp.
It flags UUIDs and provides detailed context, including:
- Raw UUID and version
- Time, MAC, and vendor data (v1)
- Clock sequence / domain info (v2)
- Hash source reversal attempt (v3/v5)
- Repetition or entropy failure (v4)
- Confidence and severity ratings
- Full advisory with markers

## License

This project is released under the GNU Affero General Public License v3.0.

## Disclaimer

This extension is intended for **legal** and **authorized** penetration testing, red teaming, and security research only. You are solely responsible for ensuring its use complies with all applicable laws and ethical guidelines. If you're a criminal, please use a different tool (or no tool).
