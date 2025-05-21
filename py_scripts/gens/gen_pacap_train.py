#!/usr/bin/env python3
"""
Generates a PCAP file whose UDP payloads follow our new 35‐field protocol:
  1.  packet_id             : 4 bytes, int
  2.  sequence_number       : 4 bytes, int
  3.  timestamp             : 8 bytes, int
  4.  source_mac            : 6 bytes, char
  5.  dest_mac              : 6 bytes, char
  6.  source_ip             : 4 bytes, raw IPv4
  7.  dest_ip               : 4 bytes, raw IPv4
  8.  vlan_id               : 2 bytes, int
  9.  vlan_priority         : 1 byte, int
 10.  protocol_version      : 2 bytes, int
 11.  header_checksum       : 4 bytes, int
 12.  flags                 : 1 byte, bitfield
 13.  reserved_bits         : 3 bytes, bitfield
 14.  payload_type          : 1 byte, int
 15.  payload_length        : 4 bytes, int
 16.  payload               : dynamic char (length=payload_length)
 17.  num_hops              : 1 byte, int
 18.  hop_addresses         : dynamic char (length=num_hops)
 19.  error_codes           : 12 bytes, array of 3 ints (4 bytes each)
 20.  sensor_count          : 2 bytes, int
 21.  sensor_ids            : 8 bytes, array of 4 ints (2 bytes each)
 22.  sensor_values         : 32 bytes, array of 8 floats
 23.  altitude              : 8 bytes, double
 24.  temperature           : 4 bytes, float
 25.  pressure              : 8 bytes, double
 26.  humidity              : 4 bytes, float
 27.  battery_voltage       : 4 bytes, float
 28.  device_name           : 20 bytes, char
 29.  device_id             : 10 bytes, char
 30.  log_count             : 2 bytes, int
 31.  logs                  : dynamic char (length=log_count)
 32.  signature_length      : 2 bytes, int
 33.  signature             : dynamic char (length=signature_length)
 34.  footer                : 4 bytes, char (constant 'FTR!')
 35.  message_checksum      : 4 bytes, int
"""

import random
import string
import struct
import socket
from scapy.all import IP, UDP, Raw, wrpcap

# example source IPs
ENDPOINTS = [
    "10.0.0.1", "10.0.0.2", "10.0.0.3",
    "10.0.0.4", "10.0.0.5", "10.0.0.6"
]

def rand_int(num_bytes):
    return random.getrandbits(8 * num_bytes).to_bytes(num_bytes, 'big')

def rand_bitfield(num_bytes):
    return random.getrandbits(8 * num_bytes).to_bytes(num_bytes, 'big')

def rand_mac():
    return bytes(random.getrandbits(8) for _ in range(6))

def rand_ascii(length):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length)).encode('utf-8')

def create_payload():
    parts = []
    # 1. packet_id
    parts.append(rand_int(4))
    # 2. sequence_number
    parts.append(rand_int(4))
    # 3. timestamp (seconds since epoch)
    ts = int(random.uniform(1_600_000_000, 1_700_000_000))
    parts.append(ts.to_bytes(8, 'big'))
    # 4. source_mac
    parts.append(rand_mac())
    # 5. dest_mac
    parts.append(rand_mac())
    # 6. source_ip (raw 4 bytes)
    sip = random.choice(ENDPOINTS)
    parts.append(socket.inet_aton(sip))
    # 7. dest_ip (raw 4 bytes)
    dip = random.choice(ENDPOINTS)
    parts.append(socket.inet_aton(dip))
    # 8. vlan_id
    parts.append(rand_int(2))
    # 9. vlan_priority
    parts.append(rand_int(1))
    # 10. protocol_version
    parts.append(rand_int(2))
    # 11. header_checksum
    parts.append(rand_int(4))
    # 12. flags
    parts.append(rand_bitfield(1))
    # 13. reserved_bits
    parts.append(rand_bitfield(3))
    # 14. payload_type
    parts.append(rand_int(1))
    # 15. payload_length + 16. payload
    payload_length = random.randint(10, 50)
    parts.append(payload_length.to_bytes(4, 'big'))
    parts.append(rand_ascii(payload_length))
    # 17. num_hops + 18. hop_addresses
    num_hops = random.randint(0, 8)
    parts.append(num_hops.to_bytes(1, 'big'))
    parts.append(rand_ascii(num_hops))
    # 19. error_codes (3 ints, 4 bytes each)
    ec = b''.join(random.randint(0, 0xFFFFFFFF).to_bytes(4, 'big') for _ in range(3))
    parts.append(ec)
    # 20. sensor_count
    sc = random.randint(1, 4)
    parts.append(sc.to_bytes(2, 'big'))
    # 21. sensor_ids (4 ints, 2 bytes each)
    si = b''.join(random.randint(0, 0xFFFF).to_bytes(2, 'big') for _ in range(4))
    parts.append(si)
    # 22. sensor_values (8 floats)
    sv = b''.join(struct.pack('!f', random.uniform(0, 100)) for _ in range(8))
    parts.append(sv)
    # 23. altitude (double)
    parts.append(struct.pack('!d', random.uniform(0, 20000)))
    # 24. temperature (float)
    parts.append(struct.pack('!f', random.uniform(-40, 85)))
    # 25. pressure (double)
    parts.append(struct.pack('!d', random.uniform(950, 1050)))
    # 26. humidity (float)
    parts.append(struct.pack('!f', random.uniform(0, 100)))
    # 27. battery_voltage (float)
    parts.append(struct.pack('!f', random.uniform(3.0, 4.2)))
    # 28. device_name (20 bytes)
    dn = rand_ascii(20)
    parts.append(dn.ljust(20, b'\x00')[:20])
    # 29. device_id (10 bytes)
    did = rand_ascii(10)
    parts.append(did.ljust(10, b'\x00')[:10])
    # 30. log_count + 31. logs
    log_count = random.randint(0, 5)
    parts.append(log_count.to_bytes(2, 'big'))
    parts.append(rand_ascii(log_count))
    # 32. signature_length + 33. signature
    sig_len = random.randint(4, 16)
    parts.append(sig_len.to_bytes(2, 'big'))
    parts.append(rand_ascii(sig_len))
    # 34. footer
    parts.append(b'FTR!')
    # 35. message_checksum
    parts.append(rand_int(4))

    return b''.join(parts)

def generate_pcap(file_name, num_packets=1000):
    print(f"Creating '{file_name}' with {num_packets} packets.")
    pkts = []
    for _ in range(num_packets):
        print(f"\rCreating packet {_} of {num_packets}", end='')
        payload = create_payload()
        src = random.choice(ENDPOINTS)
        pkt = (
            IP(src=src, dst="10.0.1.100") /
            UDP(sport=random.randint(1024, 65535), dport=10000) /
            Raw(load=payload)
        )
        pkts.append(pkt)
    wrpcap(file_name, pkts)
    print(f"\nCreated '{file_name}' with {num_packets} packets.")

if __name__ == "__main__":
    generate_pcap("train.pcap", num_packets=10000)
    
