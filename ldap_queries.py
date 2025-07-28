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

    member_dns = [line.split("CN=")[1].split(",")[0] for line in result.stdout.splitlines() if line.startswith("member:")]

    domain_admins = []
    for dn in member_dns:
        user_cmd = f"certipy.pyz account read -user {dn} -u {args.domain_user}@{args.domain} -p {args.domain_pass} -dc-ip {args.dc_ip}"
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

        if username and sid:
            entry = f"{username.upper()}@{args.domain.upper()}: {sid}"
            domain_admins.append(entry)
            print(f"{len(domain_admins)}. {entry}")

    if not domain_admins:
        print("\033[91m[-] No domain admins parsed.\033[0m")
        return None

    choice = input("\nSelect a domain admin to use (by number): ")
    selected = domain_admins[int(choice) - 1]
    print(f"\n\033[94m[Selected Domain Admin]\033[0m\n  {selected}\n")
    return selected

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
    return sid