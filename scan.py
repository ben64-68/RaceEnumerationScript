import subprocess, os, time
from datetime import datetime
from utils import general, commands
from modules import scan
import threading

current_date = general.current_date

def neccessary_ports(args):
    ping_file = run_ping_sweep(args.proccessedIPs, current_date, args.outscope_file)
    extract_alive_hosts(ping_file)
    run_needed_ports_scan(args.proccessedIPs, current_date, args.outscope_file)
    separate_nmap_hosts(f"Scans/Nmap/nmap_required_{current_date}.gnmap")
    
def run_nxc_anon_checks(args):
    cmds = [
        scan.run_nxc_anon,
        scan.run_nxc_anonsmb_checks,
        scan.run_nxc_default_creds_checks
    ]
    commands.threaded_functions(args, cmds)
    check_nxc_smb_vulns()
    
def run_nxc_creds_checks(args):
    required = [args.domain_user, args.domain_pass, args.domain]
    if not all(required):
        print("[-] Missing required arguments for credentialed scan. Skipping.")
        return
    run_nxc_cred_service_checks(args)
    cmds = [
        scan.run_nxc_ssh,
        scan.run_nxc_smb_enum,
        scan.run_nxc_ldap_enum
    ]
    commands.threaded_functions(args, cmds)
    check_nxc_smb_vulns()

def run_nmap_scans(args):
    run_common_ports_scan(args.proccessedIPs, current_date, args.outscope_file)
    separate_nmap_hosts(f"Scans/Nmap/nmap_common_{current_date}.gnmap")

def run_ping_sweep(inscope_file, current_date, outscope_file):
    output_file_base = f"Scans/Nmap/nmap_ping_{current_date}"
    cmd = f"nmap -sn --source-port 53 -T5 -iL {inscope_file} --excludefile {outscope_file} -oA {output_file_base}"
    commands.single_command(cmd, inscope_file, "bright_black")
    return f"{output_file_base}.gnmap"

def extract_alive_hosts(ping_output_file):
    cmd = f"grep 'Up' {ping_output_file} | cut -d ' ' -f2 > AliveHosts.txt"
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def check_nxc_smb_vulns():
    cmd = f"grep 'SMBv1:True' Scans/NXC/*SMB* | sort -u >> Finds/smbv1.txt"
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    cmd = f"grep 'signing:False' Scans/NXC/*SMB* | sort -u >> Finds/smbSigningFalse.txt"
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  

def run_needed_ports_scan(alive_file, current_date, outscope_file):
    cmd = f"nmap --source-port 53 --open -Pn -T4 -p 22,389,445,636,1433,2049 -iL {alive_file} --excludefile {outscope_file} -oA Scans/Nmap/nmap_required_{current_date}"
    commands.single_command(cmd, alive_file, "bright_black")
    
def run_common_ports_scan(alive_file, current_date, outscope_file):
    cmd = f"nmap --source-port 53 --open -Pn -T4 -p 20,21,22,23,25,53,80,88,111,135,137,138,139,389,443,445,636,6379,8000,8008,8080,8181,8443,8888,9000,1099,1337,1433,2049,3306,5000,6132,7000 -iL {alive_file} --excludefile {outscope_file} -oA Scans/Nmap/nmap_common_{current_date}"
    commands.single_command(cmd, alive_file, "bright_black")

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
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Web services (multiple ports)
    web_ports = ['80', '443', '8080', '8443', '8000', '8888']
    port_pattern = '|'.join(web_ports)
    cmd = f"grep -E '/({port_pattern})/open' {nmap_output_path} | awk '{{for(i=1;i<=NF;i++) if ($i ~ /\\/({port_pattern})\\/open/) {{ split($i,p,\"/\"); print $2\":\"p[1] }} }}' | sort -u >> Hosts/webHosts.txt"
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def run_nxc_anon(args):
    cmds = [
        f"nxc nfs Hosts/nfsHosts.txt >> Scans/NXC/NFS.txt",
        f"nxc rdp Hosts/rdpHosts.txt >> Scans/NXC/AnonRDP.txt",
        f"nxc ldap Hosts/ldapHosts.txt >> Scans/NXC/AnonLDAP.txt"
    ]
    commands.threaded_commands(cmds, "Hosts/(service)Hosts.txt", "magenta")

def run_nxc_anonsmb_checks(args):
    cmds = [
        f"nxc smb Hosts/smbHosts.txt --users >> Scans/NXC/AnonSMBUserCheck.txt",
        f"nxc smb Hosts/smbHosts.txt -u '' -p '' --shares >> Scans/NXC/nullSMBshareCheck.txt",
        f"nxc smb Hosts/smbHosts.txt -u 'nul' -p '' --shares >> Scans/NXC/anonSMBshareCheck.txt"
    ]
    commands.threaded_commands(cmds, "Hosts/smbHosts.txt", "magenta")

def run_nxc_default_creds_checks(args):
    cmds = [
        f"nxc ftp Hosts/ftpHosts.txt -u anonymous -p anonymous >> Scans/NXC/AnonFTP.txt",
        f"nxc mssql Hosts/mssqlHosts.txt -u sa -p sa >> Scans/NXC/sa_MSSQL.txt"
    ]
    commands.threaded_commands(cmds, "Hosts/(service)Hosts.txt", "magenta")

def run_nxc_cred_service_checks(args):
    cmds = [
        f"nxc smb Hosts/smbHosts.txt -u {args.domain_user} -p {args.domain_pass} -d {args.domain} >> Scans/NXC/{args.domain}_{args.domain_user}_SMB_AccessCheck.txt",
        f"nxc rdp Hosts/rdpHosts.txt -u {args.domain_user} -p {args.domain_pass} -d {args.domain} >> Scans/NXC/{args.domain}_{args.domain_user}_RDP_AccessCheck.txt",
        f"nxc ldap Hosts/ldapHosts.txt -u {args.domain_user} -p {args.domain_pass} -d {args.domain} >> Scans/NXC/{args.domain}_{args.domain_user}_LDAP_AccessCheck.txt",
    ]
    commands.threaded_commands(cmds, "Hosts/(service)Hosts.txt", "magenta")

def run_nxc_ssh(args):
    cmd = f"nxc ssh Hosts/sshHosts.txt -u {args.domain_user} -p {args.domain_pass} >> Scans/NXC/{args.domain}_{args.domain_user}_SSH_Access.txt"
    commands.single_command(cmd, "Hosts/sshHosts.txt", "magenta")

def run_nxc_smb_enum(args):
    smb_file = f"Scans/NXC/{args.domain}_{args.domain_user}_SMB_AccessCheck.txt"
    host_file = f"Hosts/{args.domain}_{args.domain_user}_PositiveSMBHosts.txt"
    extract_cmd = f"grep '+' {smb_file} | awk '{{print $2}}' > {host_file}"
    proc = subprocess.Popen(extract_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    smb_ip = args.dc_ip
    
    cmds = [
        f"nxc smb {host_file} -d {args.domain} -u {args.domain_user} -p {args.domain_pass} --shares --generate-hosts-file nxcGeneratedHosts >> Scans/NXC/{args.domain}_{args.domain_user}_SMB_Shares.txt",
        f"nxc smb {host_file} -d {args.domain} -u {args.domain_user} -p {args.domain_pass} -M coerce_plus >> Scans/NXC/CoercePlus_Check.txt",
        f"nxc smb {smb_ip} -d {args.domain} -u {args.domain_user} -p {args.domain_pass} -M timeroast >> Scans/NXC/Timeroast_Check.txt"
    ]  
    commands.threaded_commands(cmds, host_file, "magenta")
    
    cmd5 = f"[ \"$(grep 'sntp-ms' Scans/NXC/Timeroast_Check.txt | awk 'BEGIN {{OFS=\":\"}} {{print $2, $5}}')\" ] && grep 'sntp-ms' Scans/NXC/Timeroast_Check.txt | awk 'BEGIN {{OFS=\":\"}} {{print $2, $5}}' > Finds/Timeroast.txt"
    cmd3 = f"[ \"$(grep 'COERCE_PLUS' Scans/NXC/CoercePlus_Check.txt | awk 'BEGIN {{OFS=\":\"}} {{print $2, $6}}')\" ] && grep 'COERCE_PLUS' Scans/NXC/CoercePlus_Check.txt | awk 'BEGIN {{OFS=\":\"}} {{print $2, $6}}' > Finds/Coercion.txt"
    proc = subprocess.Popen(cmd3, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    proc = subprocess.Popen(cmd5, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def run_nxc_ldap_enum(args):
    ldap_file = f"Scans/NXC/{args.domain}_{args.domain_user}_LDAP_AccessCheck.txt"
    host_file = f"Hosts/{args.domain}_{args.domain_user}_PositiveLDAPHosts.txt"
    extract_cmd = f"grep '+' {ldap_file} | awk '{{print $2}}' > {host_file}"
    proc = subprocess.Popen(extract_cmd, shell=True)
    ldap_ip = args.dc_ip

    cmds = [
        f"nxc ldap {ldap_ip} -d {args.domain} -u {args.domain_user} -p {args.domain_pass} --users-export ActiveDirectory/{args.domain}_Users >> Scans/NXC/{args.domain}_{args.domain_user}_Ldap_enum.txt",
        f"nxc ldap {ldap_ip} -d {args.domain} -u {args.domain_user} -p {args.domain_pass} --active-users >> ActiveDirectory/{args.domain}_Active_Users_raw",
        f"nxc ldap {ldap_ip} -d {args.domain} -u {args.domain_user} -p {args.domain_pass} --asreproast ActiveDirectory/{args.domain}_Asreproast_scan",
        f"nxc ldap {ldap_ip} -d {args.domain} -u {args.domain_user} -p {args.domain_pass} --kerberoasting ActiveDirectory/{args.domain}_Kerberoast_scan",
        f"nxc ldap {ldap_ip} -d {args.domain} -u {args.domain_user} -p {args.domain_pass} -M maq >> Scans/NXC/{args.domain}_MAQ.txt",
        f"nxc ldap {ldap_ip} -d {args.domain} -u {args.domain_user} -p {args.domain_pass} -M entra_id >> Scans/NXC/{args.domain}_Entra.txt"
    ]
    commands.threaded_commands(cmds, host_file, "magenta")
    
    cmds = [
        f"[ \"$(grep 'krb5asrep' ActiveDirectory/{args.domain}_Asreproast_scan | awk '{{print $5}}')\" ] && grep 'krb5asrep' ActiveDirectory/{args.domain}_Asreproast_scan | awk '{{print $5}}' > Finds/Asreproast.txt",
        f"[ \"$(grep 'krb5tgs' ActiveDirectory/{args.domain}_Kerberoast_scan | awk '{{print $5}}')\" ] && grep 'krb5tgs' ActiveDirectory/{args.domain}_Kerberoast_scan | awk '{{print $5}}' > Finds/kerberoast.txt",
        f"grep 'channel binding:Never' Scans/NXC/{args.domain}_{args.domain_user}_LDAP_AccessCheck.txt | sort -u >> Finds/LDAPChannelBindingFalse.txt",
        f"grep 'signing:None' Scans/NXC/{args.domain}_{args.domain_user}_LDAP_AccessCheck.txt | sort -u >> Finds/LDAPsigningFalse.txt",
        f"[ \"$(awk '$NF+0 > 0' Scans/NXC/{args.domain}_MAQ.txt)\" ] && awk '$NF+0 > 0' Scans/NXC/{args.domain}_MAQ.txt > Finds/MAQnot0.txt",
        f"[ \"$(grep 'Password:' Scans/NXC/{args.domain}_Entra.txt)\" ] && grep 'Password:' Scans/NXC/{args.domain}_Entra.txt > Finds/Entra.txt"
    ]
    
    for cmd in cmds:
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
