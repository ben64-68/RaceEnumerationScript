import csv, socket, getpass, subprocess, ipaddress, threading
from datetime import datetime
from modules import scan
from utils import general

def log_command(command, start_time, end_time, destination, status):
    duration = (end_time - start_time).total_seconds()
    username = getpass.getuser()
    hostname = socket.gethostname()
    ip = general.get_local_ip_auto()

    header = ['Start Time', 'End Time', 'Duration (s)', 'Username', 'Hostname', 'IP', 'Command', 'Destination', 'Status']
    row = [start_time.isoformat(), end_time.isoformat(), duration, username, hostname, ip, command, destination, status]
    
    with open(general.LOG_FILE, mode='a', newline='') as f:
        writer = csv.writer(f)
        if f.tell() == 0:
            writer.writerow(header)
        writer.writerow(row)

def print_cmd(cmd, color):
    color_codes = {
        "black": "30",
        "red": "31",
        "green": "32",
        "yellow": "33",
        "blue": "34",
        "magenta": "35",
        "cyan": "36",
        "white": "37",
        "bright_black": "90",
        "bright_red": "91",
        "bright_green": "92",
        "bright_yellow": "93",
        "bright_blue": "94",
        "bright_magenta": "95",
        "bright_cyan": "96",
        "bright_white": "97"
    }

    color_code = color_codes.get(color.lower(), "97")  # Default to white
    print(f"\033[{color_code}m[*] Running: {cmd}\033[0m")
    
def single_command(cmd, host_file, color):
    print_cmd(cmd, color)
    start = datetime.now()
    proc = subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    end = datetime.now()
    print(f"\033[32m[*] Completed: {cmd}\033[0m")
    log_command(cmd, start, end, host_file, "Success" if proc.returncode == 0 else "Failed")
    
def threaded_commands(cmds ,host_file, color):
    threads = []
    for cmd in cmds:
        t = threading.Thread(target=single_command, args=(cmd, host_file, color))
        t.start()
        threads.append(t)
        
    for t in threads:
        t.join()

def threaded_functions(args2, functions):
    threads = []
    for cmd in functions:
        t = threading.Thread(target=cmd, args=(args2,))
        t.start()
        threads.append(t)
        
    for t in threads:
        t.join()