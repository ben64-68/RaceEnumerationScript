import os
from . import ad_certipy, ad_bloodhound
from utils import general, commands

current_date = general.current_date

def run_ad_certipy(args):
    output_dir = "ActiveDirectory/ADCS"
    has_files = any(os.path.isfile(os.path.join(output_dir, f)) for f in os.listdir(output_dir))
    if has_files and not args.rerun:
        print(f"[+] Files already exist in {output_dir}. Skipping collection. Use --rerun to force it.")
    else:
        ad_certipy.run_certipy_find(args)

    while True:
        selected_template = ad_certipy.find_esc_vulns(output_dir)
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
            esc_handlers[esc_key](args, selected_template, target)
        else:
            print(f"[-] No handler defined for {esc_key}")
        cont = input("\n\033[93m[?] Run another certificate template? (y/N): \033[0m").strip().lower()
        if cont not in ("y", "yes"):
            print("\033[91m[-] Exiting certificate exploitation loop.\033[0m")
            break

def run_ad_bloodhound(args):
    ad_bloodhound.start_bhce_server()
    ad_bloodhound.run_bloodhound_collection(args)

    path = f"ActiveDirectory/Bloodhound"

    token_key, token_id = None, None
    with open(path, "r") as f:
        for line in f:
            if line.startswith("KEY:"):
                token_key = line.split(":", 1)[1].strip()
            elif line.startswith("ID:"):
                token_id = line.split(":", 1)[1].strip()
    zip_path = ad_bloodhound.zip_bloodhound_dir()

    ad_bloodhound.upload_to_bloodhound(zip_path, token_key, token_id)
    
