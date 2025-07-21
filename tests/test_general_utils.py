import os
import pytest
from general_utils import check_required_files, create_directories, get_local_ip, LOG_FILE

def test_create_directories():
    create_directories()
    assert os.path.isdir("Scans/Nmap")
    assert os.path.isdir("ActiveDirectory/ADCS")
    assert os.path.isdir("ActiveDirectory/Bloodhound")

def test_check_required_files(tmp_path):
    inscope = tmp_path / "inscope.txt"
    outscope = tmp_path / "outscope.txt"
    inscope.write_text("192.168.0.1\n")
    outscope.write_text("")

    check_required_files(str(inscope), str(outscope))  # Should not raise

def test_get_local_ip():
    ip = get_local_ip()
    assert isinstance(ip, str)
    assert len(ip.split(".")) == 4

def test_log_file_created():
    assert LOG_FILE.exists() or LOG_FILE.parent.exists()
