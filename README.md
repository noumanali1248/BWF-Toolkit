<!-- README.md for BWF Toolkit – Wireless Forensics & Threat Detection Platform -->

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-blue?style=for-the-badge" alt="Version 1.0.0">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="MIT License">
  <img src="https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge" alt="Active">
</p>

<h1 align="center">🛰️ BWF Toolkit</h1>
<h3 align="center">Bluetooth & Wireless Forensics Toolkit</h3>

<p align="center">
  <strong>Real‑time wireless monitoring · Threat detection · Forensic analysis</strong><br>
  <em>Offensive simulation (lab‑only) + defensive detection</em>
</p>

<p align="center">
  <a href="#-overview">Overview</a> •
  <a href="#-key-features">Features</a> •
  <a href="#-architecture">Architecture</a> •
  <a href="#-tech-stack">Tech Stack</a> •
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-screenshots">Screenshots</a>
</p>

---

## 📌 Overview

**BWF Toolkit** is a modular cybersecurity platform for real‑time wireless monitoring, threat detection, and forensic analysis of **Wi‑Fi** and **Bluetooth** environments.

It bridges **offensive simulation** (lab only) with **defensive detection** to identify and respond to wireless threats like rogue access points, MAC spoofing, and protocol anomalies.

---

## 🎯 Key Features

- 📡 **Real‑time scanning** – Wi‑Fi (Scapy/PyShark) + Bluetooth (Bleak)
- 🚨 **Rogue AP & MAC spoofing detection** – Rule‑based + behavioural analysis
- 📊 **Live packet capture & protocol analysis** – Inspect 802.11, BLE, and higher layers
- 🤖 **ML‑based anomaly detection** – Scikit‑learn models for traffic outliers
- 📑 **Forensic logging & reporting** – PDF reports (ReportLab) + structured logs
- 🛡️ **Alerting & simulated response** – WebSocket alerts, automated actions (lab)
- 🔍 **Endpoint Detection & Response (EDR)** – Monitor wireless endpoints, auto‑respond

---

## 🏗️ Architecture

```mermaid
flowchart TD
    A[Wireless Devices<br/>Wi-Fi / Bluetooth] --> B[Scanner Module<br/>Scapy + PyShark + Bleak]
    B --> C[Detection Engine<br/>Rule Engine + ML Model]
    C --> D[FastAPI Backend<br/>WebSockets + REST API]
    D --> E[Dashboard UI<br/>HTML/CSS/JS]
    D --> F[Alerts / Reports / Response]
⚙️ Tech Stack
Layer	Technology
Backend	FastAPI
Networking	Scapy, PyShark
Bluetooth	Bleak
Machine Learning	Scikit‑learn
Communication	WebSockets
Reporting	ReportLab
Frontend	HTML, CSS, JavaScript
🚀 Quick Start
bash
git clone https://github.com/noumanali1248/BWF-Toolkit.git
cd BWF-Toolkit
pip install -r setup/requirements.txt
cd backend
python main.py
🌐 Access: http://localhost:8000
🔐 Default credentials: admin / admin123 (change after login)

📸 Screenshots
1. Landing Page	2. Login Page
https://images/landing.png	https://images/login.png
3. Dashboard	4. Wi‑Fi & Bluetooth Scanner
https://images/dashboard.png	https://images/scanner.png
5. Rogue Device Detector	6. Packet Sniffer
https://images/rogue_detector.png	https://images/packet_sniffer.png
7. Attack Detection	8. ML Anomaly Detection
https://images/attack_detection.png	https://images/ml_anomaly.png
9. Mitigation Panel	10. Endpoint Detection & Response
https://images/mitigation.png	https://images/edr.png
📜 License
MIT License © 2025 Nouman Ali
