# Parse Ethernet header
def parse_ethernet_header(hex_data):
    dest_mac = ':'.join(hex_data[i:i+2] for i in range(0, 12, 2))
    source_mac = ':'.join(hex_data[i:i+2] for i in range(12, 24, 2))
    ether_type = hex_data[24:28]

    print(f"Ethernet Header:")
    print(f"  {'Destination MAC:':<25} {hex_data[0:12]:<20} | {dest_mac}")
    print(f"  {'Source MAC:':<25} {hex_data[12:24]:<20} | {source_mac}")
    print(f"  {'EtherType:':<25} {ether_type:<20} | {int(ether_type, 16)}")
    payload = hex_data[28:]

    # Route payload based on EtherType
    if ether_type == "0806":  # ARP (Doesnt have an IPV)
        parse_arp_header(payload)
    # IPv4
    elif ether_type == "0800":
        protocol = int(payload[18:20], 16)
        parse_IPV4(payload)
        if protocol == 6:  # TCP
            parse_tcp_header(payload)
        elif protocol == 17:  # UDP
            parse_udp_header(payload)
        elif protocol == 1:  # ICMP
            parse_icmp_header(payload)
    #IPv6
    elif ether_type == "86dd":
        parse_IPV6(payload)
    else:
        print(f"  {'Unknown EtherType:':<25} {ether_type:<20} | {int(ether_type, 16)}")
        print("  No parser available for this EtherType.")

    return ether_type, payload

# IPV4 Parser
def parse_IPV4(hex_data):

    ipv4 = int(hex_data[0:2], 16)
    ipv4_version = ipv4 >> 4 # Get the first bit from ipv4
    header_length = (ipv4 & 0x0F) * 4 # Get the second bit from ipv4
    total_length = int(hex_data[4:8], 16)
    flag_frag_offset = int(hex_data[12:16], 16)
    flags = (flag_frag_offset >> 13) & 0x07
    reserved_flag = (flags >> 2) & 0x01
    do_not_frag = (flags >> 1) & 0x01
    more_frag = (flags & 0x01)
    frag_offset = flag_frag_offset & 0x1FFF
    protocol = int(hex_data[18:20], 16)
    source_ip_hex = hex_data[24:32]
    source_ip = ".".join(str(int(source_ip_hex[i:i+2],16)) for i in range(0,8,2))
    dest_ip_hex = hex_data[32:40]
    dest_ip = ".".join(str(int(dest_ip_hex[i:i+2],16)) for i in range(0,8,2))

    print(f"IPv4 Header:")
    print(f"  {'Version:':<25} {hex_data[:1]:<20} | {ipv4_version}")
    print(f"  {'Header Length:':<25} {hex_data[1:2]:<20} | {header_length} bytes")
    print(f"  {'Total Length:':<25} {hex_data[4:8]:<20} | {total_length}")
    print(f"  {'Flags & Frag Offset:':<25} {hex_data[12:16]:<20} | 0b{flag_frag_offset:016b}")
    print(f"  {'Reserved:':<27} {reserved_flag:<20}")
    print(f"  {'DF (Do not Fragment):':<27} {do_not_frag:<20}")
    print(f"  {'MF (More Fragments):':<27} {more_frag:<20}")
    print(f"  {'Fragment Offset:':<27} 0x{frag_offset:04x} | {frag_offset}")
    print(f"  {'Protocol:':<25} {hex_data[18:20]:<20} | {protocol}")
    print(f"  {'Source IP:':<25} {hex_data[24:32]:<20} | {source_ip}")
    print(f"  {'Destination IP:':<25} {hex_data[32:40]:<20} | {dest_ip}")

# IPV6 Parser
def parse_IPV6(hex_data):
    first_word = int(hex_data[0:8], 16)
    version = (first_word >> 28) & 0x0F
    traffic_class = (first_word >> 20) & 0xFF
    flow_label = first_word & 0xFFFFF
    payload_length = int(hex_data[8:12], 16)
    next_header = int(hex_data[12:14], 16)
    hop_limit = int(hex_data[14:16], 16)

    source_ip_hex = hex_data[16:48]
    dest_ip_hex = hex_data[48:80]

    source_ip = ":".join(source_ip_hex[i:i+4] for i in range(0, 32, 4))
    dest_ip = ":".join(dest_ip_hex[i:i+4] for i in range(0, 32, 4))

    print(f"IPv6 Header:")
    print(f"  {'Version:':<25} {hex_data[0:1]:<20} | {version}")
    print(f"  {'Traffic Class:':<25} {hex(traffic_class):<20} | {traffic_class}")
    print(f"  {'Flow Label:':<25} {hex(flow_label):<20} | {flow_label}")
    print(f"  {'Payload Length:':<25} {hex_data[8:12]:<20} | {payload_length}")
    print(f"  {'Next Header:':<25} {hex_data[12:14]:<20} | {next_header}")
    print(f"  {'Hop Limit:':<25} {hex_data[14:16]:<20} | {hop_limit}")
    print(f"  {'Source IP:':<25} {source_ip_hex:<20} | {source_ip}")
    print(f"  {'Destination IP:':<25} {dest_ip_hex:<20} | {dest_ip}")

    transport_payload = hex_data[80:]

    if next_header == 6:  # TCP over IPv6
        parse_tcp_header(transport_payload)
    elif next_header == 17:  # UDP over IPv6
        parse_udp_header(transport_payload)
    elif next_header == 58:  # ICMPv6
        parse_icmpv6_header(transport_payload)


# Parse ARP header
def parse_arp_header(hex_data):
    hardware_type = int(hex_data[:4], 16)
    protocol_type = int(hex_data[4:8], 16)
    hardware_size = int(hex_data[8:10], 16)
    protocol_size = int(hex_data[10:12], 16)
    opcode = int(hex_data[12:16], 16)
    sender_mac_hex = hex_data[16:28]
    sender_mac = ":".join(sender_mac_hex[i:i+2] for i in range(0,12,2))
    sender_ip_hex = hex_data[28:36]
    sender_ip = ".".join(str(int(sender_ip_hex[i:i+2],16)) for i in range(0,8,2))
    target_mac_hex = hex_data[36:48]
    target_mac = ":".join(target_mac_hex[i:i+2] for i in range(0,12,2))
    target_ip_hex = hex_data[48:56]
    target_ip = ".".join(str(int(target_ip_hex[i:i+2],16)) for i in range(0,8,2))

    print(f"ARP Header:")
    print(f"  {'Hardware Type:':<25} {hex_data[:4]:<20} | {hardware_type}")
    print(f"  {'Protocol Type:' :<25} {hex_data[4:8]:<20} | {protocol_type}")
    print(f"  {'Hardware Size:' :<25} {hex_data[8:10]:<20} | {hardware_size}")
    print(f"  {'Protocol Size:' :<25} {hex_data[10:12]:<20} | {protocol_size}")
    print(f"  {'Operation:' :<25} {hex_data[12:16]:<20} | {opcode}")
    print(f"  {'Sender MAC:' :<25} {hex_data[16:28]:<20} | {sender_mac}")
    print(f"  {'Sender IP:' :<25} {hex_data[28:36]:<20} | {sender_ip}")
    print(f"  {'Target MAC:' :<25} {hex_data[36:48]:<20} | {target_mac}")
    print(f"  {'Target IP:' :<25} {hex_data[48:56]:<20} | {target_ip}")


# Parse UDP Header
def parse_udp_header(hex_data):

    source_port = int(hex_data[40:44], 16)
    dest_port = int(hex_data[44:48], 16)
    length = int(hex_data[48:52], 16)
    checksum = int(hex_data[52:56], 16)
    payload = hex_data[56:]

    is_dns = source_port == 53 or dest_port == 53

    print(f"UDP Header:")
    print(f"  {'Source Port:':<25} {hex_data[40:44]:<20} | {source_port}")
    print(f"  {'Destination Port:':<25} {hex_data[44:48]:<20} | {dest_port}")
    print(f"  {'Length:':<25} {hex_data[48:52]:<20} | {length}")
    print(f"  {'Checksum:':<25} {hex_data[52:56]:<20} | {checksum}")
    print(f"  {'Payload (hex):':<25} {payload[:32]}")

    if is_dns:
        parse_dns(payload)


# Parse TCP Header
def parse_tcp_header(hex_data):

    source_port = int(hex_data[40:44], 16)
    dest_port = int(hex_data[44:48], 16)
    seq_number = int(hex_data[48:56], 16)
    ack_number = int(hex_data[56:64], 16)

    tcp_byte = int(hex_data[64:66], 16)
    data_offset = (tcp_byte >> 4) & 0x0F
    reserved_flag_tcp = (tcp_byte >> 1) & 0x07

    tcp_flags = int(hex_data[66:68], 16)
    ns = tcp_byte & 0x01
    cwr = (tcp_flags >> 7) & 0x01
    ece = (tcp_flags >> 6) & 0x01
    urg = (tcp_flags >> 5) & 0x01
    ack = (tcp_flags >> 4) & 0x01
    psh = (tcp_flags >> 3) & 0x01
    rst = (tcp_flags >> 2) & 0x01
    syn = (tcp_flags >> 1) & 0x01
    fin = tcp_flags & 0x01

    window_size = int(hex_data[68:72], 16)
    checksum = int(hex_data[72:76], 16)
    urgent_pointer =  int(hex_data[76:80], 16)
    payload_index = 40 + data_offset*8

    payload = hex_data[payload_index:payload_index+64] if payload_index < len(hex_data) else ""

    is_dns = source_port == 53 or dest_port == 53

    print(f"TCP Header:")

    print(f"  {'Source Port:':<25} {hex_data[40:44]:<20} | {source_port}")
    print(f"  {'Destination Port:':<25} {hex_data[44:48]:<20} | {dest_port}")
    print(f"  {'Sequence Number:':<25} {hex_data[48:56]:<20} | {seq_number}")
    print(f"  {'Acknowledgement Number:':<25} {hex_data[56:64]:<20} | {ack_number}")
    print(f"  {'Data Offset:':<25} {data_offset:<20} | {data_offset * 4} bytes")

    print(f"  {'Reserved:':<25} {bin(reserved_flag_tcp):<20} | {reserved_flag_tcp}")
    print(f"  {'Flags:':<25} {bin(tcp_flags)[2:].zfill(8):<20} | {tcp_flags}")
    print(f"  {'NS:':<27} {ns:<20}")
    print(f"  {'CWR:':<27} {cwr:<20}")
    print(f"  {'ECE:':<27} {ece:<20}")
    print(f"  {'URG:':<27} {urg:<20}")
    print(f"  {'ACK:':<27} {ack:<20}")
    print(f"  {'PSH:':<27} {psh:<20}")
    print(f"  {'RST:':<27} {rst:<20}")
    print(f"  {'SYN:':<27} {syn:<20}")
    print(f"  {'FIN:':<27} {fin:<20}")

    print(f"  {'Window Size:':<25} {hex_data[68:72]:<20} | {window_size}")
    print(f"  {'Checksum:':<25} {hex_data[72:76]:<20} | {checksum}")
    print(f"  {'Urgent Pointer:':<25} {hex_data[76:80]:<20} | {urgent_pointer}")
    print(f"  {'Payload (hex):':<25} {hex_data[payload_index:payload_index+32]}")

    if is_dns:
        parse_dns(payload)

# Parse ICMP Header
def parse_icmp_header(hex_data):

    icmp_type = int(hex_data[40:42], 16)
    icmp_code = int(hex_data[42:44], 16)
    icmp_checksum = int(hex_data[44:48], 16)
    payload = hex_data[48:]

    print(f"ICMP Header:")
    print(f"  {'Type:':<25} {hex_data[40:42]:<20} | {icmp_type}")
    print(f"  {'Code:':<25} {hex_data[42:44]:<20} | {icmp_code}")
    print(f"  {'Checksum:':<25} {hex_data[44:48]:<20} | {icmp_checksum}")
    print(f"  {'Payload (hex):':<25} {payload[:64]}")

# Parse ICMPv6 Header
def parse_icmpv6_header(hex_data):
    icmp_type = int(hex_data[0:2], 16)
    icmp_code = int(hex_data[2:4], 16)
    checksum = int(hex_data[4:8], 16)

    print(f"ICMPv6 Header:")
    print(f"  {'Type:':<25} {hex_data[0:2]:<20} | {icmp_type}")
    print(f"  {'Code:':<25} {hex_data[2:4]:<20} | {icmp_code}")
    print(f"  {'Checksum:':<25} {hex_data[4:8]:<20} | {checksum}")

def parse_dns(hex_data):
    if len(hex_data) < 24:
        print("DNS payload too short to parse header")
        return
    transaction_id = hex_data[:4]
    flags = hex_data[4:8]
    qdcount = int(hex_data[8:12], 16)
    ancount = int(hex_data[12:16], 16)
    nscount = int(hex_data[16:20], 16)
    arcount = int(hex_data[20:24], 16)

    print(f"DNS Header:")
    print(f"  {'Transaction ID:':<25} {transaction_id}")
    print(f"  {'Flags:':<25} {flags}")
    print(f"  {'Questions:':<25} {qdcount}")
    print(f"  {'Answers:':<25} {ancount}")
    print(f"  {'Authority RRs:':<25} {nscount}")
    print(f"  {'Additional RRs:':<25} {arcount}")



# Testing each protocol commands
# (ARP)
# sudo python3 main.py -i any -c 1 -f arp
# arping -c 1 <target_IP>

#  sudo arping -c 1 192.168.0.9
# (IPV4 / TCP)
# sudo python3 main.py -i any -c 1 -f tcp
# curl http://<target_IP>
#
# (UDP)
# sudo python3 main.py -i any -c 1 -f udp
# echo "Hello" | ncat --udp 192.168.0.1 12345
#
# (DNS (UDP/TCP))
#  ping -c 1 google.com
#  dig +tcp google.com
#
# (ICMP)
# sudo python3 main.py -i any -c 1 -f icmp
# ping -c 1 8.8.8.8

# (IPV6 / ICMPv6)
# sudo python3 main.py -i any -c 1 -f ipv6
# ping6 -c 1 google.com






