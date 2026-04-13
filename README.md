🚀 BWF Toolkit
Wireless Forensics & Threat Detection Platform










📌 Overview

BWF Toolkit (Bluetooth & Wireless Forensics Toolkit) is a modular cybersecurity platform for real-time wireless monitoring, threat detection, and forensic analysis of Wi-Fi and Bluetooth environments.

It integrates offensive simulation (lab-only) with defensive detection to identify and respond to wireless threats.



🎯 Key Features
📡 Real-time Wi-Fi & Bluetooth scanning
🚨 Rogue access point & MAC spoofing detection
📊 Live packet capture & protocol analysis
🤖 ML-based anomaly detection
📑 Forensic logging & reporting
🛡️ Alerting & simulated response actions
🏗️ Architecture
Wireless Devices
      ↓
Scanner Module (WiFi + Bluetooth)
      ↓
Detection Engine (Rules + ML)
      ↓
FastAPI Backend
      ↓
Dashboard UI
      ↓
Alerts / Reports / Response
⚙️ Tech Stack
Layer	Technology
Backend	FastAPI
Networking	Scapy, PyShark
Bluetooth	Bleak
Machine Learning	Scikit-learn
Communication	WebSockets
Reporting	ReportLab
Frontend	HTML, CSS, JavaScript
🚀 Quick Start
git clone https://github.com/noumanali1248/BWF-Toolkit.git
cd BWF-Toolkit

pip install -r setup/requirements.txt

cd backend
python main.py
🌐 Access

👉 http://localhost:8000

🔐 Default Credentials
Username: admin
Password: admin123

⚠️ Change after first login

⚠️ Attack Simulation Policy
🔴 Purpose

Used for:

Testing detection systems
Simulating real attacks
Validating security modules
🚫 Do NOT Use
On unauthorized networks
For illegal activities
On production systems
✅ Allowed
Lab environments
Virtual networks
Authorized pentesting
Learning & research
🔐 Security Guidelines
Use isolated lab setup
Get proper authorization
Avoid real network exposure
Monitor impact during testing
🧪 Testing
python test_auth_protection_simple.py
python test_all_modules_auth.py
📊 Roadmap
 AI threat intelligence
 Docker deployment
 Cloud integration (AWS)
 Advanced analytics dashboard
 Automated incident response
📜 License

MIT License

👨‍💻 Author

Nouman Ali
Cybersecurity Analyst
