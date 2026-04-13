# Manual Packet Capture Instructions

Since the automated scripts are waiting for password, here are the MANUAL commands to run:

## Option 1: Using TCPDump (Simple & Works)

Open your terminal and run these commands ONE BY ONE:

```bash
# 1. Go to the directory
cd "/home/floki/Downloads/Complete Project (2)/Complete Project/Module 1 - Bluetooth & Wi-Fi Discovery Scanner/backend"

# 2. Run tcpdump with sudo (it will ask for password - type it and press Enter)
sudo tcpdump -i enp0s31f6 -c 50 -vvv -nn

# You will see packets appearing on screen!
```

## Option 2: Using Python Script (Better Integration)

```bash
# 1. Go to the directory
cd "/home/floki/Downloads/Complete Project (2)/Complete Project/Module 1 - Bluetooth & Wi-Fi Discovery Scanner/backend"

# 2. Activate virtual environment
source .venv/bin/activate

# 3. Run with sudo (type password when asked)
sudo .venv/bin/python3 wireshark_backend_capture.py

# It will capture 50 packets and show details!
```

## Option 3: Quick Test (Captures 10 packets)

```bash
# Just run this ONE command:
sudo tcpdump -i enp0s31f6 -c 10 -vvv

# Type your password when asked
# You'll see 10 packets immediately!
```

## What Will Happen:

1. Terminal asks: `[sudo] password for floki:`
2. **You type your password** (won't show on screen - NORMAL!)
3. **Press Enter**
4. Packets start appearing with details like:
   ```
   12:34:56.789 IP 192.168.1.100.443 > 192.168.1.1.54321: tcp 1460
   12:34:56.790 IP 192.168.1.1.54321 > 192.168.1.100.443: tcp 0
   ```

## Why Scripts Were Hanging:

- They were waiting for **YOUR PASSWORD**
- Terminal doesn't show a clear prompt
- You need to **type password blind and press Enter**

## Try This Now:

**Copy and paste this single command:**

```bash
sudo tcpdump -i enp0s31f6 -c 20 -vvv -nn -e
```

Then:
1. Type your password (you won't see it)
2. Press Enter
3. Watch packets appear!

Press **Ctrl+C** to stop anytime.

