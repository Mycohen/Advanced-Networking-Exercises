
from scapy.all import sr1
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP



DOMAIN_NAME = "jct.ac.il"
DNS_SERVER = "8.8.8.8"
def soa_request(domain_name, dns_server):
    """
    Queries the SOA record for a given domain from the specified DNS server.

    Args:
        domain_name (str): The domain to query.
        dns_server (str): The DNS server to send the query to (default: 8.8.8.8).

    Returns:
        str: The primary name server if the SOA record is found, or None otherwise.
    """
    query = IP(dst=dns_server) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain_name, qtype="SOA"))
    print(f"Querying SOA for {domain_name} from DNS server {dns_server}...")

    try:
        # Send the query and wait for a response
        response = sr1(query, verbose=0, timeout=5)
        if response is None:
            print("No response received (timeout).")
            return None

        if response.haslayer(DNS):
            dns_layer = response[DNS]
            if dns_layer.ancount > 0:  # Check if the answer section has records
                for record in dns_layer.an:
                    if record.type == 6:  # Type 6 indicates an SOA record
                        print("SOA Record Found:")
                        print(f"Primary Name Server: {record.mname.decode()}")
                        return record.mname.decode()
            print("No SOA record found in the response.")
        else:
            print("Response does not contain a DNS layer.")
        return None

    except Exception as e:
        print(f"An error occurred: {e}")
        return None






def dns_enum(domain_name, dns_server, wordlist_file):
    """
    Enumerates subdomains of a domain using a wordlist and separates those with IPs from those without.

    Args:
        domain_name (str): The domain to query.
        dns_server (str): The DNS server to send the queries to.
        wordlist_file (str): Path to the wordlist file containing subdomain names.
    """
    not_found = []  # List to store subdomains without IPs
    found = {}  # Dictionary to store subdomains with their IPs

    # Get the domain's DNS server IP using SOA
    domain_ip = soa_request(domain_name, dns_server)
    if not domain_ip:
        print("Failed to retrieve the SOA record.")
        return

    # Read subdomains from the wordlist
    with open(wordlist_file, "r") as file:
        subdomains = file.read().splitlines()

    # Query for each subdomain
    for subdomain in subdomains:
        full_domain = f"{subdomain}.{domain_name}"
        query = IP(dst=domain_ip) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=full_domain, qtype="A"))

        response = sr1(query, verbose=0, timeout=2)

        if response and response.haslayer(DNS):
            dns_layer = response[DNS]
            if dns_layer.ancount > 0:  # Check if there are answers
                ips = [str(record.rdata) for record in dns_layer.an if record.type == 1]  # Extract A records
                found[full_domain] = ips
            else:
                not_found.append(full_domain)
        else:
            not_found.append(full_domain)

    # Print results
    print("\n--- Subdomains with IPs ---")
    count = 1
    for subdomain, ips in found.items():
        print(f"Subdomain {count}: {subdomain},{"\n"} IPs: {', '.join(ips)}")
        count+=1
    count=1
    print(f"{"\n"}{"\n"}{"\n"}")
    print("\n--- Subdomains without IPs ---")
    for subdomain in not_found:
        print(f"Subdomain {count}: {subdomain},{"\n"} No IPs Found")
        count+=1





dns_enum(DOMAIN_NAME,DNS_SERVER,"word_list.txt")