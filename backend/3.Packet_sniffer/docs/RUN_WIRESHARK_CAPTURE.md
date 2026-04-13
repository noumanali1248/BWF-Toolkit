# 🚀 Advanced Wireshark Packet Capture - Quick Guide

## ✨ Features

This advanced capture system provides:

- 🔬 **Detailed Packet Analysis** - Full protocol, IP, MAC, ports, flags
- 🎨 **Beautiful Color Output** - Easy-to-read terminal display
- 📊 **Comprehensive Statistics** - Protocol distribution, top IPs, ports
- 💾 **Multiple Exports** - JSON file + Module 3 database integration
- ⚡ **Real-time Processing** - See packets as they arrive

---

## 🏃 How to Run

### **Option 1: Copy-Paste Command (Easiest)**

Open your terminal and paste this:

```bash
cd "/home/floki/Downloads/Complete Project (2)/Complete Project/Module 1 - Bluetooth & Wi-Fi Discovery Scanner/backend" && sudo python3 advanced_wireshark_capture.py
```

Then:
1. Enter your sudo password when prompted
2. Watch the beautiful packet capture in action!
3. Press Ctrl+C to stop early if needed

---

### **Option 2: Step by Step**

```bash
# 1. Navigate to backend directory
cd "/home/floki/Downloads/Complete Project (2)/Complete Project/Module 1 - Bluetooth & Wi-Fi Discovery Scanner/backend"

# 2. Run the script with sudo
sudo python3 advanced_wireshark_capture.py
```

---

## 📋 What You'll See

### 1. Beautiful Header
```
================================================================================
🔬 Advanced Wireshark Packet Capture & Analysis System
================================================================================

📡 Interface: enp0s31f6
⏰ Start Time: 2025-10-01 12:34:56

================================================================================
```

### 2. Real-Time Packet Details (First 25 shown in detail)
```
╔══════════════════════════════════════════════════════════════════════════════╗
║ 📦 Packet #001                                                               ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ ⏰ Time: 2025-10-01 12:34:56.123456                                          ║
║ 📡 Protocol: TCP                                                             ║
║ 🔹 Source: 192.168.1.100:443                                                 ║
║ 🔸 Dest:   192.168.1.1:54321                                                 ║
║ MAC Src:  aa:bb:cc:dd:ee:ff                                                  ║
║ MAC Dst:  11:22:33:44:55:66                                                  ║
║ 📏 Length: 1460 bytes                                                        ║
║ 🚩 Flags: ACK, PSH                                                           ║
║ TTL: 64                                                                      ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### 3. Comprehensive Statistics
```
📊 Comprehensive Packet Analysis
================================================================================

📦 Total Packets Captured: 100
⏱  Capture Duration: 15.45 seconds
📈 Packets/Second: 6.47

────────────────────────────────────────────────────────────────────────────────
📋 Protocol Distribution:

  TCP             ██████████████████████████████████████████     85 ( 85.0%)
  UDP             ████████                                        12 ( 12.0%)
  ICMP            ██                                               3 (  3.0%)

────────────────────────────────────────────────────────────────────────────────
🌐 Top 10 IP Addresses:

  192.168.1.100        45 packets
  192.168.1.1          40 packets
  8.8.8.8              15 packets

────────────────────────────────────────────────────────────────────────────────
🔌 Top 10 Ports:

  443        (HTTPS         )     35 packets
  80         (HTTP          )     25 packets
  53         (DNS           )     12 packets
```

### 4. Export Confirmation
```
✅ Exported to JSON: /path/to/wireshark_capture.json
✅ Exported to Database: 100 packets inserted

✅ All operations completed successfully!
```

---

## 📁 Output Files

After capture, you'll get:

1. **`wireshark_capture.json`** - Full packet details in JSON format
2. **Module 3 Database** - Packets integrated into `real_packet_capture.db`

---

## ⚙️ Configuration

To change capture settings, edit these lines in `advanced_wireshark_capture.py`:

```python
# Line 399: Change packet count (default: 100)
success = capture.capture_packets(count=100, timeout=60)

# Line 13: Change network interface (default: enp0s31f6)
capture = AdvancedWiresharkCapture(interface='enp0s31f6')
```

---

## 🛠️ Troubleshooting

### "Command 'tcpdump' not found"
```bash
sudo apt update && sudo apt install tcpdump
```

### "Permission denied"
Make sure you're using `sudo`:
```bash
sudo python3 advanced_wireshark_capture.py
```

### "No packets captured"
- Check your network interface name: `ip link show`
- Try a different interface
- Generate some network traffic (browse websites)

---

## 🎯 Quick Test Commands

### Test 1: Quick 20-packet capture
```bash
cd "/home/floki/Downloads/Complete Project (2)/Complete Project/Module 1 - Bluetooth & Wi-Fi Discovery Scanner/backend"
sudo tcpdump -i enp0s31f6 -c 20 -vvv
```

### Test 2: Full advanced capture
```bash
cd "/home/floki/Downloads/Complete Project (2)/Complete Project/Module 1 - Bluetooth & Wi-Fi Discovery Scanner/backend"
sudo python3 advanced_wireshark_capture.py
```

---

## 💡 Tips

- **Generate Traffic**: Open a web browser while capturing to see more packets
- **Stop Early**: Press `Ctrl+C` to stop before reaching 100 packets
- **View JSON**: Use `cat wireshark_capture.json | jq` for formatted output
- **Database Query**: 
  ```bash
  sqlite3 real_packet_capture.db "SELECT COUNT(*) FROM packet_metadata;"
  ```

---

## 🎨 Color Legend

- 🟢 Green = Success/Source
- 🟡 Yellow = Info/Warnings
- 🔵 Blue = Network details
- 🔴 Red = Errors/Flags
- 🟣 Cyan = Headers/Borders

---

**Ready to capture? Run the command and watch the packets flow! 🚀**

