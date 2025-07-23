import os, sys, csv, socket, getpass, subprocess, shutil, ipaddress
from datetime import datetime
from pathlib import Path
from shutil import which

# Init logging file
localusername = getpass.getuser()
current_date = datetime.now().strftime("%Y-%m-%d")
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

def get_local_ip():
    try:
        result = subprocess.run(["ip", "route", "get", "1"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if "src" in line:
                return line.split("src")[1].split()[0]
    except Exception:
        pass
    return "127.0.0.1"

def log_command(command, start_time, end_time, destination, status):
    duration = (end_time - start_time).total_seconds()
    username = getpass.getuser()
    hostname = socket.gethostname()
    ip = get_local_ip()

    header = ['Start Time', 'End Time', 'Duration (s)', 'Username', 'Hostname', 'IP', 'Command', 'Destination', 'Status']
    row = [start_time.isoformat(), end_time.isoformat(), duration, username, hostname, ip, command, destination, status]

    with open(LOG_FILE, mode='a', newline='') as f:
        writer = csv.writer(f)
        if f.tell() == 0:
            writer.writerow(header)
        writer.writerow(row)

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

def print_cmd(cmd):
    print(f"\033[94m[*] Running: {cmd}\n\033[0m")
    
def parse_ip_lines(file_path):
    """Parses lines into ipaddress objects."""
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
    """Subtracts outscope entries from inscope entries."""
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
