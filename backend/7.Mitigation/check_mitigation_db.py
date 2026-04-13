
import sqlite3
import os
import json

def check_db(db_name):
    base_dir = '/home/kali/Videos/Complete Project.100%/Module 1 - Bluetooth & Wi-Fi Discovery Scanner/backend/module7'
    db_path = os.path.join(base_dir, db_name)
    
    if not os.path.exists(db_path):
        print(f"Database not found at {db_path}")
        return

    print(f"\nChecking {db_path}...")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Check quarantine_actions
    try:
        cursor.execute("SELECT * FROM quarantine_actions")
        rows = cursor.fetchall()
        print(f"--- Quarantine Actions ({len(rows)}) ---")
        for row in rows:
            # action_id, timestamp, device_mac, device_ip, action_type, reason, status, details
            print(f"Action: {row[4]}, IP: {row[3]}, MAC: {row[2]}, Status: {row[6]}, Reason: {row[5]}")
    except Exception as e:
        print(f"Error reading quarantine_actions: {e}")
        
    conn.close()

if __name__ == "__main__":
    check_db('mitigation.db')
    check_db('module7_mitigation.db')
