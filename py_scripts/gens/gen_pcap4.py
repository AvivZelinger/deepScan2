#!/usr/bin/env python3
"""
Generates a PCAP file whose UDP payloads follow our new 11‐field protocol:
  1. header            : 4 bytes, char, constant ('BPRT')
  2. version           : 4 bytes, int (1–5)
  3. flags1            : 1 byte, bitfield
  4. flags2            : 1 byte, bitfield
  5. temperature       : 4 bytes, float
  6. pressure          : 8 bytes, double
  7. device_id         : 10 bytes, char
  8. sensor_readings   : 16 bytes, array of 4 floats
  9. message_length    : 4 bytes, int (5–20)
 10. message           : dynamic char (length=message_length)
 11. checksum          : 4 bytes, int
"""

import random, string, struct
from scapy.all import IP, UDP, Raw, wrpcap

# example source IPs
ENDPOINTS = ["192.168.50.1", "192.168.50.2", "192.168.50.3", "192.168.50.4", "192.168.50.5"]

def rand_flags():
    # random bitfield 0–255, occasionally sparse
    if random.randint(1,50) != 10:
        bits = random.sample(range(8), 4)
        v = 0
        for b in bits:
            v |= (1 << b)
        return v
    return random.randint(0, 255)

def create_payload():
    # 1) header
    header_bytes = b'BPRT'

    # 2) version
    version_bytes = random.randint(1,5).to_bytes(4, 'big')

    # 3+4) flags
    f1 = rand_flags().to_bytes(1, 'big')
    f2 = rand_flags().to_bytes(1, 'big')

    # 5) temperature
    temp = random.uniform(-50.0, 150.0)
    temp_b = struct.pack('!f', temp)

    # 6) pressure
    press = random.uniform(950.0, 1050.0)
    press_b = struct.pack('!d', press)

    # 7) device_id
    dev_id = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
    dev_b  = dev_id.encode('utf-8')

    # 8) sensor_readings (array of 4 floats, total 16 bytes)
    sensor_vals = [random.uniform(0, 100) for _ in range(4)]
    sensor_b = b''.join(struct.pack('!f', v) for v in sensor_vals)

    # 9) message_length
    msg_len = random.randint(5, 20)
    msg_len_b = msg_len.to_bytes(4, 'big')

    # 10) message
    msg = ''.join(random.choices(string.ascii_letters + string.digits, k=msg_len))
    msg_b = msg.encode('utf-8')

    # 11) checksum
    chk = random.randint(0, 0xFFFFFFFF)
    chk_b = chk.to_bytes(4, 'big')

    return (header_bytes + version_bytes + f1 + f2 +
            temp_b + press_b + dev_b + sensor_b +
            msg_len_b + msg_b + chk_b)

def generate_pcap(file_name, num_packets=10000):
    packets = []
    for _ in range(num_packets):
        payload = create_payload()
        src = random.choice(ENDPOINTS)
        pkt = IP(src=src, dst="192.168.60.100")/ \
              UDP(sport=random.randint(1024,65535), dport=10000)/ \
              Raw(load=payload)
        packets.append(pkt)
    wrpcap(file_name, packets)
    print(f"Created '{file_name}' with {num_packets} packets.")

if __name__ == '__main__':
    generate_pcap("test_data1.pcap", num_packets=1000)
    generate_pcap("test_data2.pcap", num_packets=500)
    generate_pcap("test_data3.pcap", num_packets=1500)
    
