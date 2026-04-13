# BWF Toolkit

## Bluetooth & Wireless Forensics Toolkit
Real-time wireless monitoring · Threat detection · Forensic analysis  
Offensive simulation (lab-only) + defensive detection  

[Overview](#overview) | [Features](#key-features) | [Architecture](#architecture) | [Tech Stack](#tech-stack) | [Quick Start](#quick-start) | [Screenshots](#screenshots)

---

## Overview

BWF Toolkit is a modular cybersecurity platform for real-time wireless monitoring, threat detection, and forensic analysis of Wi-Fi and Bluetooth environments.

It bridges offensive simulation (lab only) with defensive detection to identify and respond to wireless threats like rogue access points, MAC spoofing, and protocol anomalies.

---

## Key Features

- 📡 **Real-time scanning** – Wi-Fi (Scapy/PyShark) + Bluetooth (Bleak)
- 🚨 **Rogue AP & MAC spoofing detection** – Rule-based + behavioural analysis
- 📊 **Live packet capture & protocol analysis** – Inspect 802.11, BLE, and higher layers
- 🤖 **ML-based anomaly detection** – Scikit-learn models for traffic outliers
- 📑 **Forensic logging & reporting** – PDF reports (ReportLab) + structured logs
- 🛡️ **Alerting & simulated response** – WebSocket alerts, automated actions (lab)
- 🔍 **Endpoint Detection & Response (EDR)** – Monitor wireless endpoints, auto-respond

---

## Architecture
Wireless Devices (Wi-Fi / Bluetooth)
↓
Scanner Module (Scapy + PyShark + Bleak)
↓
Detection Engine (Rule Engine + ML Model)
↓
FastAPI Backend (WebSockets + REST API)
↓
Dashboard UI + Alerts / Reports / Response

text

---

## Tech Stack

| Layer | Technology |
|-------|-------------|
| Backend | FastAPI |
| Networking | Scapy, PyShark |
| Bluetooth | Bleak |
| Machine Learning | Scikit-learn |
| Communication | WebSockets |
| Reporting | ReportLab |
| Frontend | HTML, CSS, JavaScript |

---

## Quick Start

```bash
git clone https://github.com/noumanali1248/BWF-Toolkit.git
cd BWF-Toolkit
pip install -r setup/requirements.txt
cd backend
python main.py
🌐 Access: http://localhost:8000
🔐 Default credentials: admin / admin123 (change after login)

Screenshots
1. Landing Page	2. Login Page
https://images/landing.png	https://images/login.png
3. Dashboard	4. Wi-Fi & Bluetooth Scanner
https://images/dashboard.png	https://images/scanner.png
5. Rogue Device Detector	6. Packet Sniffer
https://images/rogue_detector.png	https://images/packet_sniffer.png
7. Attack Detection	8. ML Anomaly Detection
https://images/attack_detection.png	https://images/ml_anomaly.png
9. Mitigation Panel	10. Endpoint Detection & Response
https://images/mitigation.png	https://images/edr.png
License
MIT License © 2025 Nouman Ali

text

**Just copy everything above and paste it into your README.md file on GitHub, then commit.** Your screenshots will appear at the bottom once the `images` folder with those 10 files exists in your repository root.
