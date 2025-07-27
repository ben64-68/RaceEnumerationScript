import subprocess, re
from utils import commands

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

def get_domain_admins(args):
    dc_string = ",".join([f"DC={d}" for d in args.domain.split(".")])
    cmd = f"ldapsearch -x -LLL -H ldap://{args.dc_ip} -D '{args.domain_user}@{args.domain}' -w '{args.domain_pass}' -b 'CN=Domain Admins,CN=Users,{dc_string}' member"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0 or "member:" not in result.stdout:
        print("\033[91m[-] Failed to retrieve Domain Admin members.\033[0m")
        return None

    member_dns = [line.split("member:")[1].strip() for line in result.stdout.splitlines() if line.startswith("member:")]
    if not member_dns:
        print("\033[93m[!] No members found in Domain Admins.\033[0m")
        return None

    domain_admins = []
    for dn in member_dns:
        user_cmd = (
            f"ldapsearch -x -LLL -H ldap://{args.dc_ip} -D '{args.domain_user}@{args.domain}' "
            f"-w '{args.domain_pass}' -b '{dn}' sAMAccountName objectSid"
        )
        user_result = subprocess.run(user_cmd, shell=True, capture_output=True, text=True)
        if user_result.returncode != 0:
            continue

        username, sid = None, None
        for line in user_result.stdout.splitlines():
            if line.startswith("sAMAccountName:"):
                username = line.split(":", 1)[1].strip()
            elif line.startswith("objectSid:"):
                sid_raw = line.split(":", 1)[1].strip()
                # Convert space-separated SID bytes to proper SID string
                sid = convert_ldap_sid_to_string(sid_raw)

        if username and sid:
            entry = f"{username.upper()}@{args.domain.upper()}: {sid}"
            domain_admins.append(entry)
            print(f"{len(domain_admins)}. {entry}")

    if not domain_admins:
        print("\033[91m[-] No domain admins parsed.\033[0m")
        return None

    choice = input("\nSelect a domain admin to use (by number): ")
    try:
        selected = domain_admins[int(choice) - 1]
        print(f"\n\033[94m[Selected Domain Admin]\033[0m\n  {selected}\n")
        return selected
    except (ValueError, IndexError):
        print("\033[91m[-] Invalid selection.\033[0m")
        return None

def convert_ldap_sid_to_string(raw_sid):
    # raw_sid is like: 1 5 21 1886521464 168325408 1675894538 500
    parts = raw_sid.split()
    if len(parts) < 4:
        return "Invalid SID"
    revision = parts[0]
    identifier_authority = parts[1]
    subauthorities = parts[2:]
    return f"S-{revision}-{identifier_authority}-" + "-".join(subauthorities)
