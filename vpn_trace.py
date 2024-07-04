from scapy.all import *
import pyfiglet
from ipwhois import IPWhois

# to delete file
# sudo rm -rf tracd_vpn_ips1.txt

banner = pyfiglet.figlet_format("PDT - 1", font="slant")
print(banner)

filename = "tracd_vpn_ips1.txt"
consecutive_count = 20
excluded_ips_prefix = ["10.", "142.250", "142.251", "157.240", "17.", "192.178", "54.240", "204.79", "119.30", "119.160", "172.217"]
current_consecutive_count = 0
last_ip = None
logged_ips = set()

included_asns = []  # Add the ASNs you want to inclde or emty if not want any chk on it
blocked_asns = {"15169", "16509", "32934", "13335", "13238"}  # Add the ASNs you want to block )(list of local and google and facebook)

def check_ip(ip):
    for prefix in excluded_ips_prefix:
        if ip.startswith(prefix):
            return False
    return True

def get_ip_info(ip):
    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap()

        hostname = result.get('network', {}).get('name', 'N/A')
        asn = result.get('asn', 'N/A')

        return hostname, asn
    except Exception as e:
        print(f"Error fetching information for {ip}: {e}")
        return 'N/A', 'N/A'

def pakt(packet):
    global current_consecutive_count, last_ip

    if packet.haslayer(IP):  # if u want to add protocol then add this before colon (:)  ->  and packet.haslayer(UDP)
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if check_ip(src_ip) or check_ip(dst_ip):
            current_consecutive_count += 1
            last_ip = src_ip if check_ip(src_ip) else dst_ip

            if current_consecutive_count == consecutive_count and check_ip(last_ip) and last_ip not in logged_ips:
                hostname, asn = get_ip_info(last_ip)

                # Check if ASN is in the included list and not in the blocked set
                if (not included_asns or asn in included_asns) and asn not in blocked_asns:
                    print(f"{last_ip} - Hostname: {hostname}, ASN: {asn}")

                    with open(filename, "a") as f:
                        f.write(f"{last_ip} - Hostname: {hostname}, ASN: {asn}\n")
                        logged_ips.add(last_ip)

                current_consecutive_count = 0
        else:
            last_ip = None
            current_consecutive_count = 0

sniff(iface="wlp0s20f3", prn=pakt)  # add your interface
