import os
from datetime import datetime
from modules import scan

def test_ping_output_name():
    out = scan.run_ping_sweep("Scope/inscope.txt", datetime.now().strftime("%Y-%m-%d"))
    assert out.endswith(".gnmap")

def test_extract_alive_hosts(tmp_path):
    dummy_file = tmp_path / "dummy.gnmap"
    dummy_file.write_text("Host: 192.168.1.1 ()    Status: Up\n")
    scan.extract_alive_hosts(str(dummy_file))
    assert os.path.exists("AliveHosts.txt")

def test_common_ports_scan_runs(tmp_path):
    test_file = tmp_path / "AliveHosts.txt"
    test_file.write_text("127.0.0.1\n")
    scan.run_common_ports_scan(str(test_file), datetime.now().strftime("%Y-%m-%d"))
