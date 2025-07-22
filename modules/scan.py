import subprocess, os, time
from datetime import datetime
from general_utils import log_command, current_date

def run(args):
    print("[*] Running Scan")
    ping_output = run_ping_sweep(args.inscope_file, current_date, args.outscope_file)
    extract_alive_hosts(ping_output)
    run_common_ports_scan("AliveHosts.txt", current_date, args.outscope_file)
    separate_nmap_hosts(f"Scans/Nmap/nmap_common_{current_date}.gnmap")
    run_nxc_anonsmb_checks()
    run_nxc_checks()
    run_nxc_deafult_creds_checks()
    if all([args.domain_user, args.domain_pass, args.domain]):
        run_nxc_creds_checks(args)
        run_nxc_ssh(args)
        run_nxc_smb_enum(args)
        run_nxc_ldap_enum(args)
    
    cmd = f"grep 'signing:False' Scans/NXC/*SMB* | sort -u > Finds/smbSigningFalse.txt"
    subprocess.run(cmd, shell=True)
    
    cmd = f"grep 'SMBv1:True' Scans/NXC/*SMB* | sort -u > Finds/smbv1.txt"
    subprocess.run(cmd, shell=True)

def run_ping_sweep(inscope_file, current_date, outscope_file):
    output_file_base = f"Scans/Nmap/nmap_ping_{current_date}"
    cmd = f"nmap -sn --source-port 53 -T5 -iL {inscope_file} --excludefile {outscope_file} -oA {output_file_base}"
    print(f"[*] Running: {cmd}")
    start = datetime.now()
    result = subprocess.run(cmd, shell=True)
    end = datetime.now()
    log_command(cmd, start, end, inscope_file, "Success" if result.returncode == 0 else "Failed")
    return f"{output_file_base}.gnmap"

def extract_alive_hosts(ping_output_file):
    if not os.path.exists(ping_output_file):
        print(f"[*] Waiting for {ping_output_file} to be created...")
        for _ in range(5):
            time.sleep(1)
            if os.path.exists(ping_output_file):
                break
        else:
            print(f"\033[91m[-] Error: {ping_output_file} still not found after waiting.\033[0m")
            return

    alive_file = "AliveHosts.txt"
    cmd = f"grep 'Up' {ping_output_file} | cut -d ' ' -f2 > {alive_file}"
    subprocess.run(cmd, shell=True)

def run_common_ports_scan(alive_file, current_date, outscope_file):
    output_file_base = f"Scans/Nmap/nmap_common_{current_date}"
    ports = "20,21,22,23,25,53,80,88,111,135,137,138,139,389,443,445,636,6379,8000,8008,8080,8181,8443,8888,9000,1099,1337,1433,2049,3306,5000,6132,7000"
    cmd = f"nmap --source-port 53 --open -Pn -T5 -p {ports} -iL {alive_file} --excludefile {outscope_file} -oA {output_file_base}"
    print(f"[*] Running: {cmd}")
    start = datetime.now()
    result = subprocess.run(cmd, shell=True)
    end = datetime.now()
    log_command(cmd, start, end, alive_file, "Success" if result.returncode == 0 else "Failed")

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
        cmd = f"grep '{port}/open' {nmap_output_path} | cut -d ' ' -f2 | sort -u > Hosts/{proto}Hosts.txt"
        subprocess.run(cmd, shell=True)

    # Web services (multiple ports)
    web_ports = ['80', '443', '8080', '8443', '8000', '8888']
    port_pattern = '|'.join(web_ports)
    cmd = (
    f"grep -E '/({port_pattern})/open' {nmap_output_path} | "
    f"awk '{{for(i=1;i<=NF;i++) if ($i ~ /\\/({port_pattern})\\/open/) {{ split($i,p,\"/\"); print $2\":\"p[1] }} }}' | sort -u > Hosts/webHosts.txt"
    )
    subprocess.run(cmd, shell=True)

def run_nxc_checks():
    checks = [
        ("nfs", "Scans/NXC/NFS.txt"),
        ("rdp", "Scans/NXC/AnonRDP.txt"),
        ("ldap", "Scans/NXC/AnonLDAP.txt")
    ]

    for service, outfile in checks:
        host_file = f"Hosts/{service}Hosts.txt"
        if os.path.exists(host_file) and os.path.getsize(host_file) > 0:
            cmd = f"nxc {service} {host_file} | tee {outfile}"
            print(f"[*] Running: {cmd}")
            start = datetime.now()
            result = subprocess.run(cmd, shell=True)
            end = datetime.now()
            log_command(cmd, start, end, host_file, "Success" if result.returncode == 0 else "Failed")

def run_nxc_anonsmb_checks():
    host_file = f"Hosts/smbHosts.txt"
    if os.path.exists(host_file) and os.path.getsize(host_file) > 0:
        cmd = f"nxc smb {host_file} --users | tee Scans/NXC/AnonSMBUserCheck.txt"
        print(f"[*] Running: {cmd}")
        start = datetime.now()
        result = subprocess.run(cmd, shell=True)
        end = datetime.now()
        log_command(cmd, start, end, host_file, "Success" if result.returncode == 0 else "Failed")
        
        cmd = f"nxc smb {host_file} -u '' -p '' --shares | tee Scans/NXC/nullSMBshareCheck.txt"
        print(f"[*] Running: {cmd}")
        start = datetime.now()
        result = subprocess.run(cmd, shell=True)
        end = datetime.now()
        log_command(cmd, start, end, host_file, "Success" if result.returncode == 0 else "Failed")
        
        cmd = f"nxc smb {host_file} -u 'nul' -p '' --shares | tee Scans/NXC/nullSMBshareCheck.txt"
        print(f"[*] Running: {cmd}")
        start = datetime.now()
        result = subprocess.run(cmd, shell=True)
        end = datetime.now()
        log_command(cmd, start, end, host_file, "Success" if result.returncode == 0 else "Failed")
        
def run_nxc_deafult_creds_checks():
    auth_checks = [
        ("ftp", "anonymous", "anonymous", "Scans/NXC/AnonFTP.txt"),
        ("mssql", "sa", "sa", "Scans/NXC/sa_MSSQL.txt")
    ]

    for service, user, pw, outfile in auth_checks:
        host_file = f"Hosts/{service}Hosts.txt"
        if os.path.exists(host_file) and os.path.getsize(host_file) > 0:
            cmd = f"nxc {service} {host_file} -u {user} -p {pw} | tee {outfile}"
            print(f"[*] Running: {cmd}")
            start = datetime.now()
            result = subprocess.run(cmd, shell=True)
            end = datetime.now()
            log_command(cmd, start, end, host_file, "Success" if result.returncode == 0 else "Failed")

def run_nxc_creds_checks(args):
    # Use user-supplied credentials for FTP and MSSQL
    auth_checks = [
        ("smb", args.domain_user, args.domain_pass, args.domain, f"Scans/NXC/{args.domain}_{args.domain_user}_SMB_AccessCheck.txt"),
        ("rdp", args.domain_user, args.domain_pass, args.domain, f"Scans/NXC/{args.domain}_{args.domain_user}_RDP_AccessCheck.txt"),
        ("ldap", args.domain_user, args.domain_pass, args.domain, f"Scans/NXC/{args.domain}_{args.domain_user}_LDAP_AccessCheck.txt"),
    ]

    for service, user, pw, domain, outfile in auth_checks:
        host_file = f"Hosts/{service}Hosts.txt"
        if os.path.exists(host_file) and os.path.getsize(host_file) > 0:
            cmd = f"nxc {service} {host_file} -d {domain} -u {user} -p {pw} | tee {outfile}"
            print(f"[*] Running: {cmd}")
            start = datetime.now()
            result = subprocess.run(cmd, shell=True)
            end = datetime.now()
            log_command(cmd, start, end, host_file, "Success" if result.returncode == 0 else "Failed")

def run_nxc_ssh(args):
    host_file = f"Hosts/sshHosts.txt"
    outfile = f"Scans/NXC/{args.domain}_{args.domain_user}_SSH_Access.txt"
    if os.path.exists(host_file) and os.path.getsize(host_file) > 0:
        cmd = f"nxc ssh {host_file} -u {args.domain_user} -p {args.domain_pass} | tee {outfile}"
        print(f"[*] Running: {cmd}")
        start = datetime.now()
        result = subprocess.run(cmd, shell=True)
        end = datetime.now()
        log_command(cmd, start, end, host_file, "Success" if result.returncode == 0 else "Failed")

def run_nxc_smb_enum(args):
    smb_file = f"Scans/NXC/{args.domain}_{args.domain_user}_SMB_AccessCheck.txt"
    host_file = f"Hosts/{args.domain}_{args.domain_user}_PositiveSMBHosts.txt"
    cmd = f"grep '+' {smb_file} | awk '{{print $2}}' > {host_file}"
    subprocess.run(cmd, shell=True)
    cmd = f"head -n 1 {host_file}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    smb_ip = result.stdout.strip()
    if os.path.exists(host_file) and os.path.getsize(host_file) > 0:
        cmd = f"nxc smb {host_file} -d {args.domain} -u {args.domain_user} -p {args.domain_pass} --shares --generate-hosts-file nxcGeneratedHosts | tee Scans/NXC/{args.domain}_{args.domain_user}_SMB_Shares.txt"
        print(f"[*] Running: {cmd}")
        start = datetime.now()
        result = subprocess.run(cmd, shell=True)
        end = datetime.now()
        log_command(cmd, start, end, host_file, "Success" if result.returncode == 0 else "Failed")
        
        cmd = f"nxc smb {host_file} -d {args.domain} -u {args.domain_user} -p {args.domain_pass} -M coerce_plus | tee Scans/NXC/CoercePlus_Check.txt"
        print(f"[*] Running: {cmd}")
        start = datetime.now()
        result = subprocess.run(cmd, shell=True)
        end = datetime.now()
        log_command(cmd, start, end, host_file, "Success" if result.returncode == 0 else "Failed")
        
        cmd = f"[ \"$(grep 'COERCE_PLUS' Scans/NXC/CoercePlus_Check.txt | awk 'BEGIN {{OFS=\":\"}} {{print $2, $6}}')\" ] && grep 'COERCE_PLUS' Scans/NXC/CoercePlus_Check.txt | awk 'BEGIN {{OFS=\":\"}} {{print $2, $6}}' > Finds/Coercion.txt"
        subprocess.run(cmd, shell=True)
        
        cmd = f"nxc smb {smb_ip} -d {args.domain} -u {args.domain_user} -p {args.domain_pass} -M timeroast | tee Scans/NXC/Timeroast_Check.txt"
        print(f"[*] Running: {cmd}")
        start = datetime.now()
        result = subprocess.run(cmd, shell=True)
        end = datetime.now()
        log_command(cmd, start, end, smb_ip, "Success" if result.returncode == 0 else "Failed")
        
        cmd = f"[ \"$(grep 'sntp-ms' Scans/NXC/Timeroast_Check.txt | awk 'BEGIN {{OFS=\":\"}} {{print $2, $5}}')\" ] && grep 'sntp-ms' Scans/NXC/Timeroast_Check.txt | awk 'BEGIN {{OFS=\":\"}} {{print $2, $5}}' > Finds/Timeroast.txt"
        subprocess.run(cmd, shell=True)

def run_nxc_ldap_enum(args):
    ldap_file = f"Scans/NXC/{args.domain}_{args.domain_user}_LDAP_AccessCheck.txt"
    host_file = f"Hosts/{args.domain}_{args.domain_user}_PositiveLDAPHosts.txt"
    cmd = f"grep '+' {ldap_file} | awk '{{print $2}}' > {host_file}"
    subprocess.run(cmd, shell=True)
    cmd = f"grep '(domain:{args.domain})' {ldap_file} | head -n 1 | awk '{{print $2}}'"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    ldap_ip = result.stdout.strip()
    if os.path.exists(host_file) and os.path.getsize(host_file) > 0:
        cmd = f"nxc ldap {ldap_ip} -d {args.domain} -u {args.domain_user} -p {args.domain_pass} --users-export ActiveDirectory/{args.domain}_Users | tee Scans/NXC/{args.domain}_{args.domain_user}_Ldap_enum.txt"
        print(f"[*] Running: {cmd}")
        start = datetime.now()
        result = subprocess.run(cmd, shell=True)
        end = datetime.now()
        log_command(cmd, start, end, ldap_ip, "Success" if result.returncode == 0 else "Failed")

        cmd = f"nxc ldap {ldap_ip} -d {args.domain} -u {args.domain_user} -p {args.domain_pass} --active-users | tee ActiveDirectory/{args.domain}_Active_Users_raw"
        print(f"[*] Running: {cmd}")
        start = datetime.now()
        result = subprocess.run(cmd, shell=True)
        end = datetime.now()
        log_command(cmd, start, end, ldap_ip, "Success" if result.returncode == 0 else "Failed")
        
        cmd = f"nxc ldap {ldap_ip} -d {args.domain} -u {args.domain_user} -p {args.domain_pass} --asreproast ActiveDirectory/{args.domain}_Asreproast_scan"
        print(f"[*] Running: {cmd}")
        start = datetime.now()
        result = subprocess.run(cmd, shell=True)
        end = datetime.now()
        log_command(cmd, start, end, ldap_ip, "Success" if result.returncode == 0 else "Failed")
        
        cmd = f"[ \"$(grep 'krb5asrep' ActiveDirectory/{args.domain}_Asreproast_scan | awk '{{print $5}}')\" ] && grep 'krb5asrep' ActiveDirectory/{args.domain}_Asreproast_scan | awk '{{print $5}}' > Finds/Asreproast.txt"
        subprocess.run(cmd, shell=True)
        
        cmd = f"nxc ldap {ldap_ip} -d {args.domain} -u {args.domain_user} -p {args.domain_pass} --kerberoasting ActiveDirectory/{args.domain}_Kerberoast_scan"
        print(f"[*] Running: {cmd}")
        start = datetime.now()
        result = subprocess.run(cmd, shell=True)
        end = datetime.now()
        log_command(cmd, start, end, ldap_ip, "Success" if result.returncode == 0 else "Failed")
        
        cmd = f"[ \"$(grep 'krb5tgs' ActiveDirectory/{args.domain}_Kerberoast_scan | awk '{{print $5}}')\" ] && grep 'krb5tgs' ActiveDirectory/{args.domain}_Kerberoast_scan | awk '{{print $5}}' > Finds/kerberoast.txt"
        subprocess.run(cmd, shell=True)
        
        cmd = f"nxc ldap {ldap_ip} -d {args.domain} -u {args.domain_user} -p {args.domain_pass} -M maq | tee Scans/NXC/{args.domain}_MAQ.txt"
        print(f"[*] Running: {cmd}")
        start = datetime.now()
        result = subprocess.run(cmd, shell=True)
        end = datetime.now()
        log_command(cmd, start, end, ldap_ip, "Success" if result.returncode == 0 else "Failed")
        
        cmd = f"[ \"$(awk '$NF+0 > 0' Scans/NXC/{args.domain}_MAQ.txt)\" ] && awk '$NF+0 > 0' Scans/NXC/{args.domain}_MAQ.txt > Finds/MAQnot0.txt"
        subprocess.run(cmd, shell=True)
        
        cmd = f"nxc ldap {host_file} -d {args.domain} -u {args.domain_user} -p {args.domain_pass} -M ldap-checker | tee Scans/NXC/{args.domain}_BindingCheck.txt"
        print(f"[*] Running: {cmd}")
        start = datetime.now()
        result = subprocess.run(cmd, shell=True)
        end = datetime.now()
        log_command(cmd, start, end, host_file, "Success" if result.returncode == 0 else "Failed")
        
        cmd = f"[ \"$(egrep 'LDAP signing NOT enforced|LDAPS channel binding is set to: Never' Scans/NXC/{args.domain}_BindingCheck.txt)\" ] && egrep 'LDAP signing NOT enforced|LDAPS channel binding is set to: Never' Scans/NXC/{args.domain}_BindingCheck.txt > Finds/LDAPSigningFalse.txt"
        subprocess.run(cmd, shell=True)