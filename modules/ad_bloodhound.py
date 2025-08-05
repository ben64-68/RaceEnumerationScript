import os, glob, shutil, subprocess, time, zipfile, http.client, json, mimetypes
from datetime import datetime
from utils import general, commands, ldap_queries

def run_bloodhound_collection(args):
    required_args = [args.domain_user, args.domain_pass, args.domain, args.dc_hostname]
    if not all(required_args):
        print("[-] Bloodhound requirements not met: missing username, password, domain, or dc-hostname.")
        return

    bhHostname = f"{args.dc_hostname}.{args.domain}"
    cmd = f"bloodhound-ce-python -c DCOnly -v -d {args.domain} -u {args.domain_user} -p {args.domain_pass} -dc {bhHostname}"
    commands.single_command(cmd, bhHostname, "bright_blue")

    output_dir = "ActiveDirectory/Bloodhound"

    for json_file in glob.glob("*.json"):
        try:
            shutil.move(json_file, os.path.join(output_dir, os.path.basename(json_file)))
        except Exception as e:
            print(f"[-] Failed to move {json_file}: {e}")

def get_domain_admins_from_bloodhound_or_live(args):
    bh_dir = os.path.expanduser("ActiveDirectory/Bloodhound")
    groups_files = glob.glob(os.path.join(bh_dir, "*groups.json"))
    users_files = glob.glob(os.path.join(bh_dir, "*users.json"))

    if not groups_files or not users_files:
        print("\033[93m[!] BloodHound data not found, running live LDAP query...\033[0m")
        admins = ldap_queries.get_domain_admins(args)
        return admins

    # BloodHound data present
    sid_cmd = (
        f"jq -r '.data[] | select(.Properties.name | test(\"(?i)^domain admins@\")) "
        f"| .Members[] | select(.ObjectType == \"User\") | .ObjectIdentifier' {bh_dir}/*groups.json"
    )
    sid_result = subprocess.run(sid_cmd, shell=True, capture_output=True, text=True)

    if sid_result.returncode != 0:
        print("\033[91m[-] Failed to extract Domain Admin SIDs:\033[0m")
        print(sid_result.stderr)
        return None

    sids = sid_result.stdout.strip().splitlines()
    domain_admins = []

    print("\033[92m[+] Domain Admins (from BloodHound):\n\033[0m")
    for sid in sids:
        user_cmd = (
            f"jq -r --arg sid '{sid}' '.data[] | select(.ObjectIdentifier == $sid) "
            f"| \"\\(.Properties.name): \\(.ObjectIdentifier)\"' {bh_dir}/*users.json"
        )
        user_result = subprocess.run(user_cmd, shell=True, capture_output=True, text=True)
        if user_result.returncode == 0 and user_result.stdout.strip():
            entry = user_result.stdout.strip()
            domain_admins.append(entry)
            print(f"{len(domain_admins)}. {entry}")
        else:
            print(f"\033[91m[!] SID not found in users.json: {sid}\033[0m")

    if not domain_admins:
        return None

    try:
        choice = int(input("\nSelect a domain admin to use (by number): "))
        selected = domain_admins[choice - 1]
        print(f"\n\033[94m[Selected Domain Admin]\033[0m\n  {selected}\n")
        return selected
    except (ValueError, IndexError):
        print("\033[91m[-] Invalid selection.\033[0m")
        return None

def get_user_sid(bh_dir, username):
    bh_dir = os.path.expanduser(bh_dir.rstrip("/"))

    # Run jq to search for the user by name (case-insensitive)
    sid_cmd = (
    f"jq -r --arg user \"{username.lower()}\" "
    f"'.data[] | select((.Properties.samaccountname // \"\") | ascii_downcase == $user) "
    f"| .ObjectIdentifier' {bh_dir}/*users.json"
    )

    result = subprocess.run(sid_cmd, shell=True, capture_output=True, text=True)

    if result.returncode != 0 or not result.stdout.strip():
        print(f"\033[91m[-] Could not find SID for user '{username}'\033[0m")
        if result.stderr.strip():
            print(result.stderr.strip())
        return None

    sid = result.stdout.strip()
    print(f"\033[92m[+] Found SID for '{username}': {sid}\033[0m")
    return sid

def start_bhce_server():
    cmd = "bloodhound-cli containers up"
    print(f"[+] Starting BloodHound CE server: {cmd}")
    proc = subprocess.Popen(cmd, shell=True)
    return proc  # retain for later termination if needed

def upload_to_bhce(token_id, token_key, zip_path, host="localhost", port=8080):
    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    headers = {
        "Authorization": f"Bearer {token_id}:{token_key}",
        "Content-Type": f"multipart/form-data; boundary={boundary}"
    }

    filename = os.path.basename(zip_path)
    with open(zip_path, "rb") as f:
        file_data = f.read()

    body = (
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n"
        f"Content-Type: application/zip\r\n\r\n"
    ).encode() + file_data + f"\r\n--{boundary}--\r\n".encode()

    conn = http.client.HTTPConnection(host, port)
    conn.request("POST", "/api/v2/ingest", body, headers)
    res = conn.getresponse()
    resp_data = res.read().decode()

    print(f"[+] Upload response: {res.status} {res.reason}")
    print(resp_data)
    conn.close()

def zip_bloodhound_dir(src_dir="ActiveDirectory/Bloodhound", output_file="ActiveDirectory/Bloodhound.zip"):
    with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(src_dir):
            for file in files:
                if file.endswith(".json"):
                    full_path = os.path.join(root, file)
                    arcname = os.path.relpath(full_path, src_dir)
                    zipf.write(full_path, arcname)
    print(f"[+] Zipped {src_dir} -> {output_file}")
    return output_file