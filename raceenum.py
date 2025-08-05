import argparse, getpass
from modules import scan, ad
from utils import general, commands,ldap_queries
import threading

password = None
#todos: mssql,sccm,check if got domain admin and secrets dump, stealth, add certipy account read for sid to make independent of bloodhound

def main():
    # ---------- GLOBAL ARGS ----------
    global_parser = argparse.ArgumentParser(add_help=False)
    global_parser.add_argument("-iL", dest="inscope_file", default="Scope/inscope.txt", help="Input file with in-scope IPs. Defaults to Scope/inscope.txt")
    global_parser.add_argument("-oL", dest="outscope_file", default="Scope/outscope.txt", help="Input file with out-of-scope IPs. Defaults to Scope/outscope.txt")
    global_parser.add_argument("-pL", dest="proccessedIPs", default="Scope/ProcessedIpRanges.txt", help="Output file for Proccessed IP scope. Defaults to Scope/ProcessedIpRanges.txt")
    global_parser.add_argument("-u", dest="domain_user", help="Domain username")
    global_parser.add_argument("-p", dest="domain_pass", help="Domain password")
    global_parser.add_argument("-d", dest="domain", help="Domain name")
    global_parser.add_argument("--dc-ip", dest="dc_ip", help="IP address of the Domain Controller (will be found automatically if not given)")
    global_parser.add_argument("--dc-hostname", dest="dc_hostname", help="Hostname of the Domain Controller (will be found automatically if not given)")
    global_parser.add_argument("--rerun", action="store_true", help="Force data collection even if files exist.")

    # ---------- MAIN PARSER ----------
    parser = argparse.ArgumentParser(description="Race Enumeration Tool", parents=[global_parser])
    subparsers = parser.add_subparsers(dest="main_cmd", required=True)

    # ---------- scan COMMAND ----------
    scan_parser = subparsers.add_parser("scan", parents=[global_parser])
    scan_subparsers = scan_parser.add_subparsers(dest="scan_cmd", required=True)

    scan_subparsers.add_parser("nmap", help="Run Nmap scans only", parents=[global_parser])
    scan_subparsers.add_parser("cred", help="Run credentialed NXC checks", parents=[global_parser])
    scan_subparsers.add_parser("anon", help="Run anonymous NXC checks", parents=[global_parser])
    scan_subparsers.add_parser("all", help="Run all scan checks", parents=[global_parser])

    # ---------- ad COMMAND ----------
    ad_parser = subparsers.add_parser("ad", parents=[global_parser])
    ad_subparsers = ad_parser.add_subparsers(dest="ad_cmd", required=True)

    ad_subparsers.add_parser("certipy", help="Run certipy", parents=[global_parser])
    ad_subparsers.add_parser("bloodhound", help="Run bloodhound", parents=[global_parser])
    ad_subparsers.add_parser("all", help="Run all AD checks", parents=[global_parser])

    # ---------- other ----------
    subparsers.add_parser("all", parents=[global_parser])
    subparsers.add_parser("clean")

    # Parse everything
    args = parser.parse_args()
    
    if args.main_cmd == "clean":
        general.clean_all()
    
    #general setup
    general.check_required_files(args.inscope_file, args.outscope_file)
    general.create_directories()
    inscope = general.parse_ip_lines(args.inscope_file)
    outscope = general.parse_ip_lines(args.outscope_file)
    processed = general.subtract_outscope(inscope, outscope)
    general.write_processed_ranges(processed, f"{args.proccessedIPs}")
    ldap_queries.load_da_cache_from_file()
    
    #collect DC info
    if not args.dc_ip or not args.dc_hostname:
        auto_ip, auto_host = general.populate_and_write_dcs(args.domain, args.proccessedIPs)
        if not args.dc_ip:
            args.dc_ip = auto_ip
        if not args.dc_hostname:
            args.dc_hostname = auto_host
    else:
        general.write_valid_dcs(args.domain,args.proccessedIPs)

    #Start of actually doing stuff
    if args.main_cmd == "scan":
        if args.scan_cmd == "nmap":
            scan.run_nmap_scans(args)
        elif args.scan_cmd == "cred":
            scan.neccessary_ports(args)
            scan.run_nxc_creds_checks(args)
        elif args.scan_cmd == "anon":
            scan.neccessary_ports(args)
            scan.run_nxc_anon_checks()
        elif args.scan_cmd == "all":
            scan.neccessary_ports(args)
            cmds = [
                scan.run_nxc_anon_checks,
                scan.run_nxc_creds_checks,
                scan.run_nmap_scans
            ]
            commands.threaded_functions(args, cmds)

    elif args.main_cmd == "ad":
        if args.ad_cmd == "bloodhound":
            ad.run_ad_bloodhound(args)
        elif args.ad_cmd == "certipy":
            ad.run_ad_certipy(args)
        elif args.ad_cmd == "all":
            cmds = [ 
                ad.run_ad_certipy,
                ad.run_ad_bloodhound
            ]
            commands.threaded_functions(args, cmds)


    elif args.main_cmd == "all":
        scan.neccessary_ports(args, args.proccessedIPs)
        cmds = [ 
            ad.run_ad_certipy,
            ad.run_ad_bloodhound,
            scan.run_nxc_anon_checks,
            scan.run_nxc_creds_checks,
            scan.run_nmap_scans
        ]
        commands.threaded_functions(args, cmds)

    ldap_queries.write_da_cache_to_file()

if __name__ == "__main__":
    main()