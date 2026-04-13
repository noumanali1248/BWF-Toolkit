# 🔴 WiFi Attack Testing Guide

## 📋 **Overview**
This guide explains how to test the rogue device detection system using a second laptop to simulate WiFi attacks.

## 🖥️ **Setup for Second Laptop**

### **Requirements:**
- Windows laptop with Python installed
- No admin privileges required
- Internet connection to access the main dashboard

### **Files to Copy:**
Copy these files to your second laptop:
1. `simple_wifi_attack.py` - Main attack simulator
2. `wifi_attack_simulator.py` - Advanced attack simulator (requires admin)

## 🚀 **Quick Start (Recommended)**

### **Step 1: Run the Simple Attack Simulator**
```bash
# On the second laptop, run:
python simple_wifi_attack.py --quick
```

This will:
- Simulate an "Evil Twin Attack" with SSID "Free_WiFi_Here"
- Run for 30 seconds
- Show you what to expect on the main dashboard

### **Step 2: Check Main Dashboard**
1. Open browser on second laptop
2. Go to: `http://[MAIN_LAPTOP_IP]:8001/module2`
3. Click "Refresh Analysis" button
4. Look for the simulated attack in the device list

## 🎯 **Available Attack Scenarios**

### **1. Evil Twin Attack**
- **SSID**: "Free_WiFi_Here"
- **Password**: None (Open)
- **Threat Reasons**: Open network, Suspicious SSID, Evil twin pattern

### **2. Airport WiFi Spoof**
- **SSID**: "Airport_WiFi_Free"
- **Password**: None (Open)
- **Threat Reasons**: Open network, Public WiFi spoofing, Location-based SSID

### **3. Coffee Shop Spoof**
- **SSID**: "CoffeeShop_Guest"
- **Password**: None (Open)
- **Threat Reasons**: Open network, Business WiFi spoofing, Guest network pattern

### **4. Hotel WiFi Spoof**
- **SSID**: "Hotel_Lobby_WiFi"
- **Password**: None (Open)
- **Threat Reasons**: Open network, Hospitality WiFi spoofing, Lobby network pattern

### **5. Setup Required Attack**
- **SSID**: "WiFi_Setup_Required"
- **Password**: None (Open)
- **Threat Reasons**: Open network, Setup-related SSID, Social engineering

### **6. Security Alert Attack**
- **SSID**: "Security_Update_Required"
- **Password**: None (Open)
- **Threat Reasons**: Open network, Security-related SSID, Urgency-based social engineering

### **7. Router Admin Spoof**
- **SSID**: "Router_Admin_Panel"
- **Password**: None (Open)
- **Threat Reasons**: Open network, Admin panel SSID, Technical social engineering

### **8. Network Config Attack**
- **SSID**: "Network_Configuration"
- **Password**: None (Open)
- **Threat Reasons**: Open network, Configuration-related SSID, Technical manipulation

## 🔧 **Usage Instructions**

### **Interactive Mode:**
```bash
python simple_wifi_attack.py
```

**Menu Options:**
1. Show available attack scenarios
2. Simulate attack scenario
3. Show current attack status
4. Show simulated devices
5. Run random attack simulation
6. Clear simulated devices
7. Exit

### **Quick Test Mode:**
```bash
python simple_wifi_attack.py --quick
```

### **Help:**
```bash
python simple_wifi_attack.py --help
```

## 📊 **What to Expect on Main Dashboard**

### **When Attack is Detected:**
- **Device appears** in WiFi Networks section
- **Threat Level**: HIGH or CRITICAL
- **Rogue Status**: ROGUE
- **Threat Score**: > 0.7
- **Threat Reasons**: Listed why it's flagged

### **Example Detection:**
```
Device: Free_WiFi_Here
Type: WiFi
BSSID: 12:34:56:78:90:ab
Security: Open
Signal: -65 dBm
Threat Level: HIGH
Rogue Status: ROGUE
Threat Score: 0.85

Why it's ROGUE:
• Open network detected
• Suspicious SSID name
• Evil twin attack pattern
```

## 🔍 **Testing Process**

### **Step 1: Start Main System**
1. On main laptop, start the dashboard
2. Go to Module 2 dashboard
3. Ensure it's running and accessible

### **Step 2: Start Attack Simulation**
1. On second laptop, run attack simulator
2. Choose an attack scenario
3. Note the attack details

### **Step 3: Monitor Detection**
1. Check main dashboard every 30 seconds
2. Look for the attack in device analysis
3. Verify threat classification

### **Step 4: Verify Results**
1. Check if device is marked as ROGUE
2. Verify threat level is HIGH/CRITICAL
3. Confirm threat reasons are accurate

## 🚨 **Expected Results**

### **✅ Successful Detection:**
- Device appears in rogue device list
- Threat level: HIGH or CRITICAL
- Rogue status: ROGUE
- Threat score: > 0.7
- Accurate threat reasons listed

### **❌ If Not Detected:**
1. Check if main dashboard is accessible
2. Verify Module 2 is running
3. Try different attack scenarios
4. Check network connectivity

## 🔧 **Troubleshooting**

### **Connection Issues:**
- Ensure both laptops are on same network
- Check firewall settings
- Verify main laptop IP address

### **Detection Issues:**
- Try different attack scenarios
- Check if Module 2 is receiving data
- Verify threat thresholds

### **Script Issues:**
- Ensure Python is installed
- Check file permissions
- Run with `--help` for usage info

## 📱 **Alternative: Phone Testing**

If you prefer using your phone:

### **WiFi Hotspot Attack:**
1. Enable hotspot on phone
2. Set SSID to "Free_WiFi_Here"
3. Set NO password (open network)
4. Check main dashboard for detection

### **Bluetooth Attack:**
1. Enable Bluetooth on phone
2. Change device name to "Unknown Device"
3. Enable MAC randomization
4. Check main dashboard for detection

## 🎯 **Success Criteria**

The test is successful if:
- ✅ Attack device appears in Module 2 dashboard
- ✅ Device is classified as ROGUE
- ✅ Threat level is HIGH or CRITICAL
- ✅ Threat reasons are accurate
- ✅ Real-time detection works

## 📞 **Support**

If you encounter issues:
1. Check the main dashboard logs
2. Verify network connectivity
3. Try different attack scenarios
4. Check Python installation on second laptop

---

**Happy Testing! 🎯**
