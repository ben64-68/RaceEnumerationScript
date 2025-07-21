# tests/test_tool_check.py
import os
import pytest
from unittest.mock import patch
from modules import ad_certipy

def test_is_tool_available_found():
    assert ad_certipy.is_tool_available("python") is True

def test_is_tool_available_not_found():
    assert ad_certipy.is_tool_available("nonexistentbinary123") is False

def test_check_required_tools_all_present(monkeypatch):
    monkeypatch.setattr(ad_certipy, "is_tool_available", lambda x: True)
    monkeypatch.setattr(os.path, "exists", lambda x: True)
    assert ad_certipy.check_required_tools() is True

def test_check_required_tools_missing_certipy(monkeypatch):
    monkeypatch.setattr(ad_certipy, "is_tool_available", lambda x: False if x == "certipy" else True)
    monkeypatch.setattr(os.path, "exists", lambda x: False if "certipy.pyz" in x else True)
    assert ad_certipy.check_required_tools() is False

def test_check_required_tools_missing_all(monkeypatch):
    monkeypatch.setattr(ad_certipy, "is_tool_available", lambda x: False)
    monkeypatch.setattr(os.path, "exists", lambda x: False)
    assert ad_certipy.check_required_tools() is False
