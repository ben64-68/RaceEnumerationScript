import subprocess, re
from utils import commands

# Global cache for DA info
GLOBAL_DA_CACHE = []

def get_netbios_name(args):
    cmd = f"rpcclient -U '{args.domain_user}%{args.domain_pass}' {args.dc_ip} -c 'lsaquery'"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"\033[91m[-] Failed to run lsaquery: {result.stderr.strip()}\033[0m")
        return None

    for line in result.stdout.splitlines():
        if line.strip().lower().startswith("domain name:"):
            shortname = line.split(":")[1].strip()
            return shortname

    print("\033[91m[-] NetBIOS domain not found in lsaquery output\033[0m")
    return None

import subprocess, os, glob

def get_da_info(args):
    bh_dir = os.path.expanduser("ActiveDirectory/Bloodhound")
    groups_files = glob.glob(os.path.join(bh_dir, "*groups.json"))
    users_files = glob.glob(os.path.join(bh_dir, "*users.json"))

    domain_admins = []

    # --- BLOODHOUND MODE ---
    if groups_files and users_files:
        print("\033[92m[+] Using BloodHound data...\033[0m")
        sid_cmd = (
            f"jq -r '.data[] | select(.Properties.name | test(\"(?i)^domain admins@\")) "
            f"| .Members[] | select(.ObjectType == \"User\") | .ObjectIdentifier' {bh_dir}/*groups.json"
        )
        sid_result = subprocess.run(sid_cmd, shell=True, capture_output=True, text=True)
        sids = sid_result.stdout.strip().splitlines()

        for sid in sids:
            user_cmd = (
                f"jq -r --arg sid '{sid}' '.data[] | select(.ObjectIdentifier == $sid) "
                f"| \"\\(.Properties.name): \\(.ObjectIdentifier)\"' {bh_dir}/*users.json"
            )
            user_result = subprocess.run(user_cmd, shell=True, capture_output=True, text=True)
            if user_result.returncode == 0 and user_result.stdout.strip():
                entry = user_result.stdout.strip()
                domain_admins.append(entry)
            else:
                print(f"\033[91m[!] SID not found in users.json: {sid}\033[0m")

    # --- CACHED MODE ---
    elif GLOBAL_DA_CACHE:
        print("\033[94m[+] Using cached Domain Admin data...\033[0m")
        domain_admins = GLOBAL_DA_CACHE.copy()

    # --- LIVE LDAP MODE ---
    else:
        print("\033[93m[!] No BloodHound data or cache found. Running live LDAP query...\033[0m")
        dc_string = ",".join([f"DC={d}" for d in args.domain.split(".")])
        cmd = f"ldapsearch -x -LLL -H ldap://{args.dc_ip} -D '{args.domain_user}@{args.domain}' -w '{args.domain_pass}' -b 'CN=Domain Admins,CN=Users,{dc_string}' member"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        if result.returncode != 0 or "member:" not in result.stdout:
            print("\033[91m[-] Failed to retrieve Domain Admin members.\033[0m")
            return None

        member_dns = [line.split("CN=")[1].split(",")[0] for line in result.stdout.splitlines() if line.startswith("member:")]

        for dn in member_dns:
            username, sid = get_user_sid(args,dn)

            if username and sid:
                entry = f"{username}: {args.domain}: {sid}"
                domain_admins.append(entry)

    if not domain_admins:
        print("\033[91m[-] No domain admins found.\033[0m")
        return None

    # Append only unique DAs to cache
    for da in domain_admins:
        if da not in GLOBAL_DA_CACHE:
            GLOBAL_DA_CACHE.append(da)

    # Prompt user
    print("\n\033[92m[+] Domain Admins:\033[0m")
    for i, entry in enumerate(domain_admins, start=1):
        print(f"{i}. {entry}")

    try:
        choice = int(input("\nSelect a domain admin to use (by number): "))
        selected = domain_admins[choice - 1]
        print(f"\n\033[94m[Selected Domain Admin]\033[0m\n  {selected}\n")
        return selected
    except (ValueError, IndexError):
        print("\033[91m[-] Invalid selection.\033[0m")
        return None

def get_user_sid(args, user):
    user_cmd = f"certipy.pyz account read -user {user} -u {args.domain_user}@{args.domain} -p {args.domain_pass} -dc-ip {args.dc_ip}"
    user_result = subprocess.run(user_cmd, shell=True, capture_output=True, text=True)
    username, sid = None, None
    for line in user_result.stdout.splitlines():
        if ':' not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if key == "sAMAccountName":
            username = value
        elif key == "objectSid":
            sid = value
    return username, sid

def write_da_cache_to_file(filepath="DAs.txt"):
    try:
        with open(filepath, "w") as f:
            for entry in GLOBAL_DA_CACHE:
                f.write(f"{entry}\n")
        print(f"[+] Cached DAs written to {filepath}")
    except Exception as e:
        print(f"[-] Failed to write cache: {e}")

def load_da_cache_from_file(filepath="DAs.txt"):
    if not os.path.exists(filepath):
        return
    try:
        with open(filepath, "r") as f:
            for line in f:
                entry = line.strip()
                if entry and entry not in GLOBAL_DA_CACHE:
                    GLOBAL_DA_CACHE.append(entry)
        print(f"[+] Loaded cached DAs from {filepath}")
    except Exception as e:
        print(f"[-] Failed to read cache: {e}")