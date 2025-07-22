import argparse
from modules import scan, ad, anon
from general_utils import check_required_files, create_directories, clean_all, check_tool

def main():
    parser = argparse.ArgumentParser(description="Race Enumeration Script")

    parser.add_argument("-scan", action="store_true", help="Perform scanning")
    parser.add_argument("-ad", action="store_true", help="Perform Active Directory checks")
    parser.add_argument("-all", action="store_true", help="Run all checks")
    parser.add_argument("-clean", action="store_true", help="Delete generated scan and AD data")

    parser.add_argument("-iL", dest="inscope_file", default="Scope/inscope.txt", help="Input file with in-scope IPs")
    parser.add_argument("-oL", dest="outscope_file", default="Scope/outscope.txt", help="Input file with out-of-scope IPs")
    
    parser.add_argument("-u", dest="domain_user", help="Domain username")
    parser.add_argument("-p", dest="domain_pass", help="Domain password")
    parser.add_argument("-d", dest="domain", help="Domain name")
    parser.add_argument("--dc-ip", dest="dc_ip", help="IP address of the Domain Controller")
    parser.add_argument("--dc-hostname", dest="dc_hostname", help="Hostname of the Domain Controller (just hostname not FQDN)")

    args = parser.parse_args()

    if args.clean:
        clean_all()
    
    # Check certipy only if -ad or -all
    if args.ad or args.all:
        if not check_tool("certipy.pyz"):
            print("[-] Certipy is required for -ad/-all. Not found.")
            sys.exit(1)
        if not check_tool("bloodhound-ce-python"):
            print("[-] Certipy is required for -ad/-all. Not found.")
            sys.exit(1)

    # Check nxc only if -anon or -all
    if args.all:
        if not check_tool("nxc"):
            print("[-] nxc not found. It's required for anonymous checks.")
            sys.exit(1)

    check_required_files(args.inscope_file, args.outscope_file)
    create_directories()

    if args.all or args.scan:
        scan.run(args)
    if args.all or args.ad:
        if not all([args.domain_user, args.domain_pass, args.domain, args.dc_ip, args.dc_hostname]):
            print("[!] AD enumeration requires -u, -p, -d, --dc-ip, and --dc-hostname")
        else:
            ad.run(args)
