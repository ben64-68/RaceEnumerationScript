import subprocess, os, time
from datetime import datetime
import general_utils
import threading

current_date = general_utils.current_date

def neccessary_ports(args, ProcessedIPfile):
    ping_file = run_ping_sweep(ProcessedIPfile, current_date, args.outscope_file)
    extract_alive_hosts(ping_file)
    run_needed_ports_scan(ProcessedIPfile, current_date, args.outscope_file)
    separate_nmap_hosts(f"Scans/Nmap/nmap_required_{current_date}.gnmap")
    
def run_nxc_anon_checks(ProcessedIPfile):
    t1 = threading.Thread(target=run_nxc_anon())
    t2 = threading.Thread(target=run_nxc_anonsmb_checks())
    t3 = threading.Thread(target=run_nxc_default_creds_checks())
    t1.start()
    t2.start()
    t3.start()
    t1.join()
    t2.join()
    t3.join()
    check_nxc_smb_vulns()
    
def run_nxc_creds_checks(args, ProcessedIPfile):
    required = [args.domain_user, args.domain_pass, args.domain]
    if not all(required):
        print("[-] Missing required arguments for credentialed scan. Skipping.")
        return

    t1 = threading.Thread(target=run_nxc_ssh, args=(args,))
    t2 = threading.Thread(target=run_nxc_smb_enum, args=(args,))
    t3 = threading.Thread(target=run_nxc_ldap_enum, args=(args,))
    t1.start()
    run_nxc_cred_service_checks(args)
    t2.start()
    t3.start()
    t1.join()
    t2.join()
    t3.join()
    check_nxc_smb_vulns()

def run_nmap_scans(args, ProcessedIPfile):
    run_common_ports_scan(ProcessedIPfile, current_date, args.outscope_file)
    separate_nmap_hosts(f"Scans/Nmap/nmap_common_{current_date}.gnmap")

def run_ping_sweep(inscope_file, current_date, outscope_file):
    output_file_base = f"Scans/Nmap/nmap_ping_{current_date}"
    cmd = f"nmap -sn --source-port 53 -T5 -iL {inscope_file} --excludefile {outscope_file} -oA {output_file_base}"
    threaded_run_log(cmd, inscope_file)
    return f"{output_file_base}.gnmap"

def extract_alive_hosts(ping_output_file):
    if not os.path.exists(ping_output_file):
        time.sleep(2)
        if not os.path.exists(ping_output_file):
            print(f"\033[91m[-] Error: {ping_output_file} still not found after waiting.\033[0m")
            log_command(f"grep 'Up' {ping_output_file}", start, datetime.now(), "local", "Failed")
            return

    cmd = f"grep 'Up' {ping_output_file} | cut -d ' ' -f2 > AliveHosts.txt"
    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def threaded_run_log(cmd, destination):
    general_utils.print_cmd(cmd)
    start = datetime.now()
    proc = subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    end = datetime.now()
    general_utils.log_command(cmd, start, end, destination, "Success" if proc.returncode == 0 else "Failed")

def check_nxc_smb_vulns():
    cmd = f"grep 'SMBv1:True' Scans/NXC/*SMB* | sort -u >> Finds/smbv1.txt"
    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    cmd = f"grep 'signing:False' Scans/NXC/*SMB* | sort -u >> Finds/smbSigningFalse.txt"
    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  

def run_needed_ports_scan(alive_file, current_date, outscope_file):
    output_file_base = f"Scans/Nmap/nmap_required_{current_date}"
    ports = "22,389,445,636,1433,2049"
    cmd = f"nmap --source-port 53 --open -Pn -T4 -p {ports} -iL {alive_file} --excludefile {outscope_file} -oA {output_file_base}"
    threaded_run_log(cmd, alive_file)
    
def run_common_ports_scan(alive_file, current_date, outscope_file):
    output_file_base = f"Scans/Nmap/nmap_common_{current_date}"
    ports = "20,21,22,23,25,53,80,88,111,135,137,138,139,389,443,445,636,6379,8000,8008,8080,8181,8443,8888,9000,1099,1337,1433,2049,3306,5000,6132,7000"
    cmd = f"nmap --source-port 53 --open -Pn -T4 -p {ports} -iL {alive_file} --excludefile {outscope_file} -oA {output_file_base}"
    threaded_run_log(cmd, alive_file)

def separate_nmap_hosts(nmap_output_path):
    service_ports = {
        'ftp': '21',
        'ssh': '22',
        'rdp': '3389',
        'smtp': '25',
        'smb': '445',
        'nfs': '2049',
        'dameware': '6132',
        'ldap': '389',
        'ldaps': '636',
        'telnet': '23',
        'mssql': '1433',
        'mysql': '3306'
    }

    for proto, port in service_ports.items():
        cmd = f"grep '{port}/open' {nmap_output_path} | cut -d ' ' -f2 | sort -u >> Hosts/{proto}Hosts.txt"
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Web services (multiple ports)
    web_ports = ['80', '443', '8080', '8443', '8000', '8888']
    port_pattern = '|'.join(web_ports)
    cmd = (
    f"grep -E '/({port_pattern})/open' {nmap_output_path} | "
    f"awk '{{for(i=1;i<=NF;i++) if ($i ~ /\\/({port_pattern})\\/open/) {{ split($i,p,\"/\"); print $2\":\"p[1] }} }}' | sort -u >> Hosts/webHosts.txt"
    )
    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def run_nxc_anon():
    checks = [
        ("nfs", "Scans/NXC/NFS.txt"),
        ("rdp", "Scans/NXC/AnonRDP.txt"),
        ("ldap", "Scans/NXC/AnonLDAP.txt")
    ]

    threads = []
    for service, outfile in checks:
        host_file = f"Hosts/{service}Hosts.txt"
        if os.path.exists(host_file) and os.path.getsize(host_file) > 0:
            cmd = f"nxc {service} {host_file} >> {outfile}"
            t = threading.Thread(target=threaded_run_log, args=(cmd, host_file))
            t.start()
            threads.append(t)

    for t in threads:
        t.join()

def run_nxc_anonsmb_checks():
    host_file = "Hosts/smbHosts.txt"
    if not (os.path.exists(host_file) and os.path.getsize(host_file) > 0):
        return

    cmds = [
        f"nxc smb {host_file} --users >> Scans/NXC/AnonSMBUserCheck.txt",
        f"nxc smb {host_file} -u '' -p '' --shares >> Scans/NXC/nullSMBshareCheck.txt",
        f"nxc smb {host_file} -u 'nul' -p '' --shares >> Scans/NXC/anonSMBshareCheck.txt"
    ]

    threads = []
    for cmd in cmds:
        t = threading.Thread(target=threaded_run_log, args=(cmd, host_file))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

def run_nxc_default_creds_checks():
    auth_checks = [
        ("ftp", "anonymous", "anonymous", "Scans/NXC/AnonFTP.txt"),
        ("mssql", "sa", "sa", "Scans/NXC/sa_MSSQL.txt")
    ]

    threads = []
    for service, user, pw, outfile in auth_checks:
        host_file = f"Hosts/{service}Hosts.txt"
        if os.path.exists(host_file) and os.path.getsize(host_file) > 0:
            cmd = f"nxc {service} {host_file} -u {user} -p {pw} >> {outfile}"
            t = threading.Thread(target=threaded_run_log, args=(cmd, host_file))
            t.start()
            threads.append(t)

    for t in threads:
        t.join()

def run_nxc_cred_service_checks(args):
    auth_checks = [
        ("smb", args.domain_user, args.domain_pass, args.domain, f"Scans/NXC/{args.domain}_{args.domain_user}_SMB_AccessCheck.txt"),
        ("rdp", args.domain_user, args.domain_pass, args.domain, f"Scans/NXC/{args.domain}_{args.domain_user}_RDP_AccessCheck.txt"),
        ("ldap", args.domain_user, args.domain_pass, args.domain, f"Scans/NXC/{args.domain}_{args.domain_user}_LDAP_AccessCheck.txt"),
    ]

    threads = []
    for service, user, pw, domain, outfile in auth_checks:
        host_file = f"Hosts/{service}Hosts.txt"
        if os.path.exists(host_file) and os.path.getsize(host_file) > 0:
            cmd = f"nxc {service} {host_file} -d {domain} -u {user} -p {pw} >> {outfile}"
            t = threading.Thread(target=threaded_run_log, args=(cmd, host_file))
            t.start()
            threads.append(t)

    for t in threads:
        t.join()

def run_nxc_ssh(args):
    host_file = "Hosts/sshHosts.txt"
    outfile = f"Scans/NXC/{args.domain}_{args.domain_user}_SSH_Access.txt"
    if os.path.exists(host_file) and os.path.getsize(host_file) > 0:
        cmd = f"nxc ssh {host_file} -u {args.domain_user} -p {args.domain_pass} >> {outfile}"
        t = threading.Thread(target=threaded_run_log, args=(cmd, host_file))
        t.start()
        t.join()

def run_nxc_smb_enum(args):
    smb_file = f"Scans/NXC/{args.domain}_{args.domain_user}_SMB_AccessCheck.txt"
    host_file = f"Hosts/{args.domain}_{args.domain_user}_PositiveSMBHosts.txt"
    extract_cmd = f"grep '+' {smb_file} | awk '{{print $2}}' > {host_file}"
    subprocess.run(extract_cmd, shell=True)
    result = subprocess.run(f"head -n 1 {host_file}", shell=True, capture_output=True, text=True)
    smb_ip = result.stdout.strip()
    if os.path.exists(host_file) and os.path.getsize(host_file) > 0:
        cmd1 = f"nxc smb {host_file} -d {args.domain} -u {args.domain_user} -p {args.domain_pass} --shares --generate-hosts-file nxcGeneratedHosts >> Scans/NXC/{args.domain}_{args.domain_user}_SMB_Shares.txt"
        cmd2 = f"nxc smb {host_file} -d {args.domain} -u {args.domain_user} -p {args.domain_pass} -M coerce_plus >> Scans/NXC/CoercePlus_Check.txt"
        cmd3 = f"[ \"$(grep 'COERCE_PLUS' Scans/NXC/CoercePlus_Check.txt | awk 'BEGIN {{OFS=\":\"}} {{print $2, $6}}')\" ] && grep 'COERCE_PLUS' Scans/NXC/CoercePlus_Check.txt | awk 'BEGIN {{OFS=\":\"}} {{print $2, $6}}' > Finds/Coercion.txt"
        cmd4 = f"nxc smb {smb_ip} -d {args.domain} -u {args.domain_user} -p {args.domain_pass} -M timeroast >> Scans/NXC/Timeroast_Check.txt"
        cmd5 = f"[ \"$(grep 'sntp-ms' Scans/NXC/Timeroast_Check.txt | awk 'BEGIN {{OFS=\":\"}} {{print $2, $5}}')\" ] && grep 'sntp-ms' Scans/NXC/Timeroast_Check.txt | awk 'BEGIN {{OFS=\":\"}} {{print $2, $5}}' > Finds/Timeroast.txt"
        
        threads = []
        for cmd in [cmd1, cmd2, cmd4]:
            t = threading.Thread(target=threaded_run_log, args=(cmd, host_file))
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()
        
        subprocess.run(cmd3, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(cmd5, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def run_nxc_ldap_enum(args):
    ldap_file = f"Scans/NXC/{args.domain}_{args.domain_user}_LDAP_AccessCheck.txt"
    host_file = f"Hosts/{args.domain}_{args.domain_user}_PositiveLDAPHosts.txt"
    extract_cmd = f"grep '+' {ldap_file} | awk '{{print $2}}' > {host_file}"
    subprocess.run(extract_cmd, shell=True)
    result = subprocess.run(f"grep '(domain:{args.domain})' {ldap_file} | head -n 1 | awk '{{print $2}}'", shell=True, capture_output=True, text=True)
    ldap_ip = result.stdout.strip()

    if os.path.exists(host_file) and os.path.getsize(host_file) > 0:
        cmds = [
            f"nxc ldap {ldap_ip} -d {args.domain} -u {args.domain_user} -p {args.domain_pass} --users-export ActiveDirectory/{args.domain}_Users >> Scans/NXC/{args.domain}_{args.domain_user}_Ldap_enum.txt",
            f"nxc ldap {ldap_ip} -d {args.domain} -u {args.domain_user} -p {args.domain_pass} --active-users >> ActiveDirectory/{args.domain}_Active_Users_raw",
            f"nxc ldap {ldap_ip} -d {args.domain} -u {args.domain_user} -p {args.domain_pass} --asreproast ActiveDirectory/{args.domain}_Asreproast_scan",
            f"nxc ldap {ldap_ip} -d {args.domain} -u {args.domain_user} -p {args.domain_pass} --kerberoasting ActiveDirectory/{args.domain}_Kerberoast_scan",
            f"nxc ldap {ldap_ip} -d {args.domain} -u {args.domain_user} -p {args.domain_pass} -M maq >> Scans/NXC/{args.domain}_MAQ.txt",
            f"nxc ldap {ldap_ip} -d {args.domain} -u {args.domain_user} -p {args.domain_pass} -M entra_id >> Scans/NXC/{args.domain}_Entra.txt",
            f"nxc ldap {host_file} -d {args.domain} -u {args.domain_user} -p {args.domain_pass} -M ldap-checker >> Scans/NXC/{args.domain}_BindingCheck.txt"
        ]

        threads = []
        for cmd in cmds:
            t = threading.Thread(target=threaded_run_log, args=(cmd, ldap_ip))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()
        
        cmd1 = f"[ \"$(grep 'krb5asrep' ActiveDirectory/{args.domain}_Asreproast_scan | awk '{{print $5}}')\" ] && grep 'krb5asrep' ActiveDirectory/{args.domain}_Asreproast_scan | awk '{{print $5}}' > Finds/Asreproast.txt"
        cmd2 = f"[ \"$(grep 'krb5tgs' ActiveDirectory/{args.domain}_Kerberoast_scan | awk '{{print $5}}')\" ] && grep 'krb5tgs' ActiveDirectory/{args.domain}_Kerberoast_scan | awk '{{print $5}}' > Finds/kerberoast.txt"
        cmd3 = f"[ \"$(egrep 'LDAP signing NOT enforced|LDAPS channel binding is set to: Never' Scans/NXC/{args.domain}_BindingCheck.txt)\" ] && egrep 'LDAP signing NOT enforced|LDAPS channel binding is set to: Never' Scans/NXC/{args.domain}_BindingCheck.txt > Finds/LDAPSigningFalse.txt"
        cmd4 = f"[ \"$(awk '$NF+0 > 0' Scans/NXC/{args.domain}_MAQ.txt)\" ] && awk '$NF+0 > 0' Scans/NXC/{args.domain}_MAQ.txt > Finds/MAQnot0.txt"
        cmd4 = f"[ \"$(grep 'Password:' Scans/NXC/{args.domain}_Entra.txt)\" ] && grep 'Password:' Scans/NXC/{args.domain}_Entra.txt > Finds/Entra.txt"
        subprocess.run(cmd1, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(cmd2, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(cmd3, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(cmd4, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(cmd5, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)