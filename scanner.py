import json

def load_vuln_db():
    try:
        with open('vuln_db.json', 'r') as file:
            return json.load(file)
    except:
        return {}

# to get targer from user
target = input("Enter the IP address or domain to scan: ")
vuln_db = load_vuln_db()
print("Target set to:", target)

#building of TCP SOCKET ( socket programming usking python)

import socket 

start_port = 0
end_port = 1023
print("Scanning ports", start_port, "to", end_port, "...\n")

from concurrent.futures import ThreadPoolExecutor

#Scanning of each port
def scan_port(port):
    try:
        s = socket.socket()
        s.settimeout(0.5)
        result = s.connect_ex((target, port))
        if result == 0:
            try:
                banner = s.recv(1024).decode().strip()
                if banner:
                    print("[+] Port", port, "is open → Banner:", banner)
                    # check for vulnerabilities from banner
                    for service, versions in vuln_db.items():
                        for version, desc in versions.items():
                            if version.lower() in banner.lower():
                                print(f"[!!] Vulnerability found: {desc}")
                else:
                    print("[+] Port", port, "is open → No banner")
            except:
                print("[+] Port", port, "is open → Banner not received")
        s.close()
    except:
        pass

with ThreadPoolExecutor(max_workers=100) as executor:
    executor.map(scan_port, range(start_port, end_port + 1))
