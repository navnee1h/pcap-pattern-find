from scapy.all import rdpcap
import re

def find_custom_texts_in_pcap(pcap_file, search_patterns):
    # Read the pcap file
    packets = rdpcap(pcap_file)
    matching_packets = []
    for packet in packets:
        matched = False
        
        # Check the Ethernet Layer (if present)
        if packet.haslayer('Ethernet'):
            ethernet_data = str(packet['Ethernet'])
            for pattern in search_patterns:
                if re.search(pattern, ethernet_data):
                    matching_packets.append({
                        'pattern': pattern,
                        'data': ethernet_data,
                        'type': 'Ethernet'
                    })
                    matched = True

        # Check the IP Layer (IPv4 or IPv6)
        if packet.haslayer('IP'):
            ip_data = str(packet['IP'])
            for pattern in search_patterns:
                if re.search(pattern, ip_data):
                    matching_packets.append({
                        'pattern': pattern,
                        'data': ip_data,
                        'type': 'IP'
                    })
                    matched = True
        elif packet.haslayer('IPv6'):
            ipv6_data = str(packet['IPv6'])
            for pattern in search_patterns:
                if re.search(pattern, ipv6_data):
                    matching_packets.append({
                        'pattern': pattern,
                        'data': ipv6_data,
                        'type': 'IPv6'
                    })
                    matched = True
        
        # Check the Transport Layer (TCP/UDP)
        if packet.haslayer('TCP'):
            tcp_data = str(packet['TCP'])
            for pattern in search_patterns:
                if re.search(pattern, tcp_data):
                    matching_packets.append({
                        'pattern': pattern,
                        'data': tcp_data,
                        'type': 'TCP'
                    })
                    matched = True
        elif packet.haslayer('UDP'):
            udp_data = str(packet['UDP'])
            for pattern in search_patterns:
                if re.search(pattern, udp_data):
                    matching_packets.append({
                        'pattern': pattern,
                        'data': udp_data,
                        'type': 'UDP'
                    })
                    matched = True

        # Check the DNS Layer (if present)
        if packet.haslayer('DNS'):
            dns_data = str(packet['DNS'])
            for pattern in search_patterns:
                if re.search(pattern, dns_data):
                    matching_packets.append({
                        'pattern': pattern,
                        'data': dns_data,
                        'type': 'DNS'
                    })
                    matched = True

        # Check the Raw Layer (if present)
        if packet.haslayer('Raw'):
            raw_data = packet['Raw'].load.decode(errors='ignore')
            for pattern in search_patterns:
                if re.search(pattern, raw_data):
                    matching_packets.append({
                        'pattern': pattern,
                        'data': raw_data,
                        'type': 'Raw'
                    })
                    matched = True

        # Check for other layers, such as HTTP or others
        if not matched:
            for layer in packet:
                if hasattr(layer, 'load'):
                    layer_data = layer.load.decode(errors='ignore')
                    for pattern in search_patterns:
                        if re.search(pattern, layer_data):
                            matching_packets.append({
                                'pattern': pattern,
                                'data': layer_data,
                                'type': layer.name
                            })
                            matched = True

    return matching_packets

pcap_file = input("Enter the path to the pcap file: ")  #Input pcap file path

search_patterns = [
    r'CCF',  # Replace
    r'pattern2',  # Replace
    r'pattern3'   # Replace
]

matching_packets = find_custom_texts_in_pcap(pcap_file, search_patterns)
if matching_packets:
    print("Found matching patterns:")
    for match in matching_packets:
        print(f"\nPattern: {match['pattern']}")
        print(f"Layer: {match['type']}")
        print(f"Data:\n{match['data']}")
else:
    print("No matching patterns found.")
