import argparse
from modules import scan, ad
import general_utils
import threading

def main():
    # ---------- GLOBAL ARGS ----------
    global_parser = argparse.ArgumentParser(add_help=False)
    global_parser.add_argument("-iL", dest="inscope_file", default="Scope/inscope.txt", help="Input file with in-scope IPs. Defaults to Scope/inscope.txt")
    global_parser.add_argument("-oL", dest="outscope_file", default="Scope/outscope.txt", help="Input file with out-of-scope IPs. Defaults to Scope/outscope.txt")
    global_parser.add_argument("-u", dest="domain_user", help="Domain username")
    global_parser.add_argument("-p", dest="domain_pass", help="Domain password")
    global_parser.add_argument("-d", dest="domain", help="Domain name")
    global_parser.add_argument("--dc-ip", dest="dc_ip", help="IP address of the Domain Controller")
    global_parser.add_argument("--dc-hostname", dest="dc_hostname", help="Hostname of the Domain Controller")

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

    ad_subparsers.add_parser("enum", help="Run Active Directory enumeration", parents=[global_parser])
    ad_subparsers.add_parser("exploit", help="Run Active Directory exploit checks", parents=[global_parser])
    ad_subparsers.add_parser("all", help="Run all AD checks", parents=[global_parser])

    # ---------- other ----------
    subparsers.add_parser("all", parents=[global_parser])
    subparsers.add_parser("clean")

    # Parse everything
    args = parser.parse_args()
    
    if args.main_cmd == "clean":
        general_utils.clean_all()

    general_utils.check_required_files(args.inscope_file, args.outscope_file)
    general_utils.create_directories()
    
    ProcessedIPfile = f"Scope/ProcessedIpRanges.txt"
    inscope = general_utils.parse_ip_lines(args.inscope_file)
    outscope = general_utils.parse_ip_lines(args.outscope_file)

    processed = general_utils.subtract_outscope(inscope, outscope)
    general_utils.write_processed_ranges(processed, f"{ProcessedIPfile}")

    if args.main_cmd == "scan":
        if args.scan_cmd == "nmap":
            scan.run_nmap_scans(args, ProcessedIPfile)
        elif args.scan_cmd == "cred":
            scan.neccessary_ports(args, ProcessedIPfile)
            scan.run_nxc_creds_checks(args, ProcessedIPfile)
        elif args.scan_cmd == "anon":
            scan.neccessary_ports(args, ProcessedIPfile)
            scan.run_nxc_anon_checks()
        elif args.scan_cmd == "all":
            scan.neccessary_ports(args, ProcessedIPfile)
            t1 = threading.Thread(target=scan.run_nxc_anon_checks, args=(ProcessedIPfile,))
            t2 = threading.Thread(target=scan.run_nxc_creds_checks, args=(args,ProcessedIPfile))
            t3 = threading.Thread(target=scan.run_nmap_scans, args=(args, ProcessedIPfile))
            t1.start()
            t2.start()
            t3.start()
            t1.join()
            t2.join()
            t3.join()
            
    elif args.main_cmd == "ad":
        if args.ad_cmd == "enum":
            ad.run_ad_enum(args)
        elif args.ad_cmd == "exploit":
            ad.run_ad_exploit(args)
        elif args.ad_cmd == "all":
            t1 = threading.Thread(target=ad.run_ad_enum, args=(args,))
            t2 = threading.Thread(target=ad.run_ad_exploit, args=(args,))
            t1.start()
            t1.join()
            t2.start()
            t2.join()

    elif args.main_cmd == "all":
        scan.neccessary_ports(args, ProcessedIPfile)
        t1 = threading.Thread(target=scan.run_nxc_anon_checks, args=(ProcessedIPfile,))
        t2 = threading.Thread(target=scan.run_nxc_creds_checks, args=(args, ProcessedIPfile))
        t3 = threading.Thread(target=scan.run_nmap_scans, args=(args,))
        t4 = threading.Thread(target=ad.run_ad_enum, args=(args,))
        t5 = threading.Thread(target=ad.run_ad_exploit, args=(args,))
        t1.start()
        t2.start()
        t3.start()
        t4.start()
        t4.join()
        t5.start()
        t1.join()
        t2.join()
        t3.join()
        t5.join()  
