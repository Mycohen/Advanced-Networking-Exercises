from scapy.all import *
from scapy.layers.dns import *
import re
from scapy.layers.inet import IP


def is_valid_domain(domain_name):
    # Regular expression for validating domain names
    domain_regex = (
        r"^(?!-)"                      # Domain cannot start with a hyphen
        r"[A-Za-z0-9-]{1,63}"          # Labels can be up to 63 characters long
        r"(?<!-)\."                    # Labels cannot end with a hyphen and must be followed by a dot
        r"(?:[A-Za-z]{2,63})$"         # TLD must be 2-63 characters long
    )
    # Check if the domain name matches the regex
    return bool(re.match(domain_regex, domain_name))


def nslook():
    domain_name = input("Enter a domain name: ")
    if is_valid_domain(domain_name):
        dns_server = "8.8.8.8"
        query = IP(dst=dns_server) / UDP() / DNS(rd=1, qd=DNSQR(qname=domain_name))
        response = sr1(query, verbose=0, timeout=2)
        if response and response.haslayer(DNS):
            ip_addresses = []
            for i in range(response[DNS].ancount):
                if response[DNS].an[i].type == 1:  # Type 1 = A record (IPv4)
                    ip_addresses.append(response[DNS].an[i].rdata)

            if ip_addresses:
                print(f"The IP addresses of {domain_name} are: {', '.join(ip_addresses)}")
            else:
                print(f"Could not resolve the IP address of {domain_name}")
    else:
        print(f"{domain_name} is not a valid domain name.")


nslook()
