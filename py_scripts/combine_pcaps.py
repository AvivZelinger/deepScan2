import os
from scapy.all import rdpcap, wrpcap

def combine_and_cleanup_pcap_files(folder_path, output_file):
    # Get all .pcap and .pcapng files, sorted by name
    pcap_files = sorted(
        [f for f in os.listdir(folder_path) if f.endswith('.pcap') or f.endswith('.pcapng')]
    )
    
    if not pcap_files:
        print("No pcap files found.")
        return

    combined_packets = []

    for file in pcap_files:
        file_path = os.path.join(folder_path, file)
        try:
            print(f"Reading {file_path}...")
            packets = rdpcap(file_path)
            combined_packets.extend(packets)
        except Exception as e:
            print(f"Failed to read {file_path}: {e}")

    if not combined_packets:
        print("No packets were combined.")
        return

    output_path = os.path.join('/mnt/c/Users/aviv/Desktop/FinalProject_obj,array,bitfield/server', output_file)
    try:
        print(f"Writing combined packets to {output_path}...")
        wrpcap(output_path, combined_packets)
    except Exception as e:
        print(f"Failed to write output file: {e}")
        return

    for file in pcap_files:
        try:
            os.remove(os.path.join(folder_path, file))
            print(f"Deleted {file}")
        except Exception as e:
            print(f"Failed to delete {file}: {e}")

    print("Done!")

# Example usage
combine_and_cleanup_pcap_files(
    '/mnt/c/Users/aviv/Desktop/FinalProject_obj,array,bitfield/server/uploads',
    'runfile.pcapng'
)
