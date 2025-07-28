import os, sys, getpass, subprocess, shutil, ipaddress, socket, re
from datetime import datetime
from pathlib import Path
from utils import commands

# Init logging file
localusername = getpass.getuser()
current_date = datetime.now().strftime("%d-%m-%Y")
logs_dir = Path.home() / "/data/logs/scripts"
logs_dir.mkdir(parents=True, exist_ok=True)
LOG_FILE = logs_dir / f"EnumerationLog_Race_{current_date}.csv"

def check_required_files(inscope_file, outscope_file):
    if not os.path.exists(inscope_file):
        print(f"[-] In-scope file '{inscope_file}' not found.")
        sys.exit(1)
    if not os.path.exists(outscope_file):
        print(f"[-] Out-of-scope file '{outscope_file}' not found. If nothing is out of scope run:\ntouch outscope.txt")
        sys.exit(1)

def create_directories():
    os.makedirs("Scans/Nmap", exist_ok=True)
    os.makedirs("Scans/NXC", exist_ok=True)
    os.makedirs("ActiveDirectory/ADCS", exist_ok=True)
    os.makedirs("ActiveDirectory/Bloodhound", exist_ok=True)
    os.makedirs("Hosts", exist_ok=True)
    os.makedirs("Finds", exist_ok=True)

def get_local_ip_auto():
    try:
        result = subprocess.run(["ip", "route", "get", "1"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if "src" in line:
                return line.split("src")[1].split()[0]
    except Exception: 
        pass
    return "127.0.0.1"

def get_local_ip():
    try:
        result = subprocess.run(["ip", "a"], capture_output=True, text=True)
        output = result.stdout

        # Match all IPv4 addresses excluding 127.0.0.1
        ips = re.findall(r'inet (\d+\.\d+\.\d+\.\d+)/\d+', output)
        ips = [ip for ip in ips if not ip.startswith("127.")]

        if not ips:
            return "127.0.0.1"

        if len(ips) == 1:
            return ips[0]

        # Multiple IPs found, let user select
        print("Multiple local IPs found:")
        for idx, ip in enumerate(ips):
            print(f"{idx + 1}. {ip}")

        while True:
            choice = input("Select an IP by number: ")
            if choice.isdigit() and 1 <= int(choice) <= len(ips):
                return ips[int(choice) - 1]
            print("Invalid selection. Try again.")

    except Exception as e:
        print(f"Error occurred: {e}")

    return "127.0.0.1"

def clean_all():
    warning = "\033[91m[!] WARNING: This will permanently delete 'Hosts/', 'Finds/', 'Scans/', 'ActiveDirectory/', 'nxcGeneratedHosts', and 'AliveHosts.txt'.\033[0m"
    print(warning)
    confirm = input("Are you sure? Type 'y' to confirm: ")
    if confirm.lower() == 'y':
        shutil.rmtree("Scans", ignore_errors=True)
        shutil.rmtree("Hosts", ignore_errors=True)
        shutil.rmtree("Finds", ignore_errors=True)
        shutil.rmtree("ActiveDirectory", ignore_errors=True)
        if os.path.exists("AliveHosts.txt"):
            os.remove("AliveHosts.txt")
        if os.path.exists("nxcGeneratedHosts"):
            os.remove("nxcGeneratedHosts")
        if os.path.exists("Scope/ProcessedIpRanges.txt"):
            os.remove("Scope/ProcessedIpRanges.txt")
        print("\033[92m[+] Cleanup completed.\033[0m")
        sys.exit(0)
    else:
        print("[-] Cleanup cancelled.")
        sys.exit(0)
    
def parse_ip_lines(file_path):
    #Parses lines into ipaddress objects.
    entries = set()
    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                if '/' in line:
                    entries.add(ipaddress.ip_network(line, strict=False))
                else:
                    entries.add(ipaddress.ip_address(line))
            except ValueError:
                print(f"[-] Invalid IP or CIDR format: {line}")
    return entries

def subtract_outscope(inscope, outscope):
    #Subtracts outscope entries from inscope entries.
    result = set()
    for i in inscope:
        if isinstance(i, ipaddress.IPv4Address):
            if not any(i in o for o in outscope):
                result.add(i)
        elif isinstance(i, ipaddress.IPv4Network):
            temp = [i]
            for o in outscope:
                new_temp = []
                for subnet in temp:
                    if isinstance(o, ipaddress.IPv4Network) and subnet.overlaps(o):
                        new_temp.extend(subnet.address_exclude(o))
                    else:
                        new_temp.append(subnet)
                temp = new_temp
            result.update(temp)
    return result

def write_processed_ranges(entries, output_file):
    with open(output_file, "w") as f:
        for e in sorted(entries, key=lambda x: str(x)):
            f.write(f"{e}\n")

def check_ip(ip, scope_file):
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False  # Invalid IP format

    try:
        with open(scope_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    # Handle individual IP or CIDR
                    network = ipaddress.ip_network(line, strict=False)
                    if ip_obj in network:
                        return True
                except ValueError:
                    # If it's not a valid network, try direct IP comparison
                    if line == ip:
                        return True
    except FileNotFoundError:
        print(f"[!] Scope file not found: {scope_file}")
        return False

    return False

def write_valid_dcs(domain, scope):
    hostnames = get_dc_hostnames(domain)
    resolved = resolve_hostnames_to_ips(hostnames, domain)
    output_file = f"Hosts/{domain}_DCs.txt"
    with open(output_file, "w") as f:
        for hostname, ips in resolved.items():
            for ip in ips:
                if check_ip(ip, scope):
                    f.write(f"{hostname}:{ip}\n")

def get_dc_hostnames(domain):
    cmd = f"nslookup -type=SRV _ldap._tcp.dc._msdcs.{domain}"
    print(f"\033[90m [*] Running: {cmd}\033[0m")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    hostnames = []
    for line in result.stdout.splitlines():
        match = re.search(r'\s+service\s+=\s+\d+\s+\d+\s+\d+\s+([\w\.-]+)\.', line)
        if match:
            fqdn = match.group(1).strip()
            hostname = fqdn.split('.')[0]
            if hostname:
                hostnames.append(hostname)
    return hostnames

def resolve_hostnames_to_ips(hostnames, domain):
    resolved = {}
    for hostname in hostnames:
        try:
            fqdn = f"{hostname}.{domain}"
            ips = socket.gethostbyname_ex(fqdn)[2]
            resolved[hostname] = ips
        except socket.gaierror:
            resolved[hostname] = []
    return resolved

def populate_and_write_dcs(domain, scope_file):
    hostnames = get_dc_hostnames(domain)
    if not hostnames:
        print("[-] No DC hostnames found.")
        return None, None

    resolved = resolve_hostnames_to_ips(hostnames, domain)
    output_file = f"Hosts/{domain}_DCs.txt"
    first_ip, first_hostname = None, None

    with open(output_file, "w") as f:
        for hostname, ips in resolved.items():
            for ip in ips:
                if check_ip(ip, scope_file):
                    f.write(f"{hostname}:{ip}\n")
                    if first_ip is None:
                        first_ip, first_hostname = ip, hostname

    if first_ip is None:
        print("[-] No in-scope DC IPs found.")

    return first_ip, first_hostname
