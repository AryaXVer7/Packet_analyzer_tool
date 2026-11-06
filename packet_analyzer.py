from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, ARP
from colorama import Fore, Style, init
init(autoreset=True)

stats = {
    "total" : 0,
    "tcp" : 0,
    "udp" : 0,
    "icmp" : 0,
    "arp" : 0
}

icmp_name = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    8: "Echo Request",
    11: "Time Exceeded"
}

services = {
    22: "SSH",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    123: "NTP",
    137: "NetBIOS",
    443: "HTTPS",
    5353: "mDNS"
}

tcp_flags = {
    "S"  : "SYN",
    "A"  : "ACK",
    "F"  : "FIN",
    "R"  : "RST",
    "P"  : "PSH",
    "U"  : "URG"
}

alert = {
    "blacklisted_ip" : 0,
    "port_scan" : 0,
    "traffic_spike" : 0
}

blacklisted_ip = { # Only for Demo
    "192.0.2.1",  
    "192.0.2.55",
    "198.51.100.12",
    "198.51.100.200",
    "203.0.113.7",
    "203.0.113.44",
    "10.21.25.143",
    "10.21.255.255"
}

def check_blacklisted_ip(ip):
    if ip.src in blacklisted_ip:
        alert["blacklisted_ip"] += 1
        print(Fore.RED + f"[alert] Blacklisted Source IP found: {ip.src}")
        
    if ip.dst in blacklisted_ip:
        alert["blacklisted_ip"] += 1        
        print(Fore.RED + f"[alert] Blacklisted Destination IP found: {ip.dst}")

def analyze_ip(packet):
    ip = packet[IP]
    print(Fore.WHITE + Style.BRIGHT + """=================================""")
    print(Fore.WHITE + Style.BRIGHT + f"Source IP     : {ip.src}")
    print(Fore.LIGHTBLACK_EX + Style.BRIGHT + f"Destination IP: {ip.dst}")

    check_blacklisted_ip(ip)
  
def analyze_tcp(packet):
    tcp = packet[TCP]
    stats["tcp"] += 1
    service = services.get(tcp.dport)
    flags = tcp.flags
    flags_list = []
    for flag in flags:
        flags_list.append(tcp_flags.get(flag, flag))
    print(Fore.GREEN + f"""Flags           : {", ".join(flags_list)}""")
    
    if service is None:
        service = services.get(tcp.sport, "Unknown")
    
    print(Fore.GREEN + f"Service         : {service}")
        
    print(Fore.GREEN + f"""Protocol        : TCP
Source Port     : {tcp.sport}
Destination Port: {tcp.dport}
{Fore.WHITE + Style.BRIGHT}=================================""")    
    
def analyze_udp(packet):
    udp = packet[UDP]
    stats["udp"] += 1
    service = services.get(udp.dport)
    if service is None:
        service = services.get(udp.sport, "Unknown")
    
    print(Fore.CYAN + f"Service         : {service}")
    print(Fore.CYAN + f"""Protocol        : UDP
Source Port     : {udp.sport}
Destination Port: {udp.dport}
{Fore.WHITE + Style.BRIGHT}=================================""")

def analyze_dns(packet):
    dns = packet[DNS]
    
    print(Fore.BLUE + f"""---------------DNS---------------""")
    
    if dns.qr == 0:
        print(Fore.BLUE + f"Type             : Query")
    else:
        print(Fore.BLUE + f"Type             : Response")
    
    if packet.haslayer(DNSQR):
        print(Fore.BLUE + f"Domain           : {packet[DNSQR].qname.decode()}")  
        
    if dns.qr == 1 and packet.haslayer(DNSRR):
        print(Fore.BLUE + f"Answer           : {packet[DNSRR].rdata}")
        
    print(Fore.BLUE + f"""---------------------------------""")

def analyze_icmp(packet):
    icmp = packet[ICMP]
    stats["icmp"] += 1
    print(Fore.YELLOW + f"""Protocol        : ICMP
ICMP Code: {icmp.code}
ICMP Type: {icmp_name.get(icmp.type, f"Unknown ({icmp.type})")}
{Fore.WHITE + Style.BRIGHT}=================================""")
    
def analyze_arp(packet):
    
    stats["arp"] += 1
    
    arp = packet[ARP]
    
    print(Fore.MAGENTA + f"""---------------ARP---------------""")
    
    if arp.op == 1:
        print(Fore.MAGENTA + f"Type            : Request")
        print(Fore.MAGENTA + f"Sender IP       : {arp.psrc}")
        print(Fore.MAGENTA + f"Target IP       : {arp.pdst}")
        # print(f"Sender MAC      : {arp.hwsrc}")
        # print(f"Target MAC      : {arp.hwdst}")
        
    elif arp.op == 2:
        print(Fore.MAGENTA + f"Type            : Reply")
        print(Fore.MAGENTA + f"Sender IP       : {arp.psrc}")
        print(Fore.MAGENTA + f"Target IP       : {arp.pdst}")
        # print(f"Sender MAC      : {arp.hwsrc}")
        # print(f"Target MAC      : {arp.hwdst}")        
                   
    print(Fore.MAGENTA + f"""---------------------------------""")

def analyze_packet(packet):
    stats["total"] += 1
    
    if packet.haslayer(ARP):
        analyze_arp(packet)
        
    elif packet.haslayer(IP):
        analyze_ip(packet)
        
        if packet.haslayer(TCP):
            analyze_tcp(packet)
            
            if packet.haslayer(DNS):
                analyze_dns(packet)            
        
        elif packet.haslayer(UDP):
            analyze_udp(packet)
    
            if packet.haslayer(DNS):
                analyze_dns(packet)
        
        elif packet.haslayer(ICMP):   
            analyze_icmp(packet)

print(Fore.YELLOW + Style.BRIGHT + '''=============================================
              PACKET ANALYZER
             Network Security Tool
=============================================\n''')
count = int(input("Enter number of packets to capture: "))

print(f"Sniffing Packets...")

sniff(
    count = count,
    filter = "arp or tcp or udp or icmp",
    prn = analyze_packet,
    store = False
)
       
print(Fore.WHITE + Style.BRIGHT + f"""================== Statistics ==================
Total Packets: {stats['total']}

TCP          : {stats['tcp']}
UDP          : {stats['udp']}
ICMP         : {stats['icmp']}
ARP          : {stats['arp']}
================================================

================ Security Report ================
Blacklisted IP Alerts: {alert['blacklisted_ip']}
=================================================
""")