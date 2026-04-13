🚀 BWF Toolkit: Wireless Forensics & Threat Detection Platform
📌 Overview

BWF Toolkit (Bluetooth & Wireless Forensics Toolkit) is a modular cybersecurity platform designed for real-time wireless monitoring, threat detection, and forensic analysis of Wi-Fi and Bluetooth environments.

The system combines offensive testing (lab-controlled) and defensive detection mechanisms to simulate, identify, and respond to wireless threats.

🎯 Project Scope

This project focuses on:

📡 Wireless Device Discovery
Wi-Fi and Bluetooth scanning
Device identification and classification
Signal strength monitoring
🚨 Threat Detection & Analysis
Rogue access point detection
MAC spoofing detection
Suspicious traffic behavior
📊 Packet Capture & Inspection
Live traffic monitoring
Protocol-level analysis
PCAP-based forensic investigation
🤖 Anomaly Detection
Machine learning-based behavioral analysis
Detection of abnormal network patterns
📑 Digital Forensics
Evidence collection and logging
Report generation for investigations
🛡️ Mitigation & Response
Alert generation
Threat response mechanisms
Device quarantine (simulated)
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
Backend: FastAPI
Networking: Scapy, PyShark
Bluetooth: Bleak
Machine Learning: Scikit-learn
Communication: WebSockets
Reporting: ReportLab
Frontend: HTML, CSS, JavaScript
📂 Project Structure
BWF-Toolkit/
├── backend/                    # Core application & modules
├── Attack Scripts/             # Lab-based attack simulations
│   ├── Bluetooth Attacks/
│   └── WiFi Attacks/
├── templates/                  # UI templates
├── static/                     # CSS/JS assets
├── setup/                      # Installation scripts
└── README.md
🚀 Installation & Setup
git clone https://github.com/noumanali1248/BWF-Toolkit.git
cd BWF-Toolkit

pip install -r setup/requirements.txt

cd backend
python main.py
🌐 Access

Open in browser:

http://localhost:8000
🔐 Default Credentials
Username: admin
Password: admin123

⚠️ Change credentials after first login.

⚠️ CRITICAL: Attack Scripts Usage Policy
🔴 Purpose of Attack Scripts

The Attack Scripts directory contains simulated attack scenarios for:

Bluetooth attacks (L2Ping, RFCOMM, SDP testing)
Wi-Fi attacks (ARP spoofing, DoS, packet flooding)

👉 These are included to:

Test detection capabilities
Simulate real-world threats
Validate security monitoring modules
🚫 STRICT USAGE RESTRICTIONS

These scripts MUST NOT be used:

❌ On public or private networks without permission
❌ For unauthorized penetration testing
❌ For disrupting real systems
❌ For illegal or malicious activities
✅ ALLOWED USAGE

These scripts should ONLY be used in:

✔️ Controlled lab environments
✔️ Virtual test networks
✔️ Authorized penetration testing engagements
✔️ Educational cybersecurity practice
🔐 Safety Precautions

Before running any attack script:

Ensure explicit authorization
Use isolated lab network
Avoid real production systems
Monitor system impact carefully
Disable scripts immediately if instability occurs
⚠️ Legal Warning

Unauthorized use of these scripts may violate:

Cybercrime laws
Organizational security policies
Ethical hacking guidelines

👉 The user is fully responsible for compliance.

⚠️ General Security Precautions
Do not upload:
PCAP files
Real network logs
Sensitive IP/MAC data
Always sanitize data before sharing
Run the toolkit with proper permissions
⚠️ Disclaimer

This project is intended strictly for educational and ethical cybersecurity purposes.
The author is not responsible for any misuse, damage, or legal consequences resulting from improper use of this tool.

🧪 Testing
python test_auth_protection_simple.py
python test_all_modules_auth.py
📊 Future Enhancements
AI-driven threat intelligence
Cloud deployment (AWS / Docker)
Advanced visualization dashboard
Automated incident response
📜 License

This project is licensed under the MIT License.

👨‍💻 Author

Nouman Ali
Cybersecurity Analyst 
