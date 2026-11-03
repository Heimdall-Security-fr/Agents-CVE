"""Garde-fous : le superviseur relance un fil qui plante, et la tâche de service
(schtasks/XML) est bien formée. Les fonctions sont extraites des agents, qui ne
s'importent pas tels quels hors Windows (interface graphique, registre)."""
import ast
import os
import unittest
import xml.etree.ElementTree as ET
from unittest.mock import patch


def _extract(source_path, names, extra_globals=None):
    tree = ast.parse(open(source_path, encoding="utf-8").read())
    wanted = set(names)
    nodes = [n for n in tree.body
             if (isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in wanted)
             or (isinstance(n, ast.Assign) and any(getattr(t, "id", None) in wanted for t in n.targets))]
    ns = {"os": os, "time": __import__("time"), "threading": __import__("threading"),
          "subprocess": __import__("subprocess"), "logger": _SilentLogger()}
    ns.update(extra_globals or {})
    exec(compile(ast.Module(body=nodes, type_ignores=[]), source_path, "exec"), ns)
    return ns


class _SilentLogger:
    def exception(self, *a, **k): pass
    def info(self, *a, **k): pass
    def warning(self, *a, **k): pass
    def error(self, *a, **k): pass


HERE = os.path.dirname(__file__)
LINUX = os.path.join(HERE, "..", "mini_agent.py")
WINDOWS = os.path.join(HERE, "..", "windows_agent_tray.py")


class SupervisorTests(unittest.TestCase):
    def test_crashed_thread_is_restarted_until_it_succeeds(self):
        ns = _extract(LINUX, {"_supervise"})
        calls = {"n": 0}

        def flaky():
            calls["n"] += 1
            if calls["n"] < 3:
                raise RuntimeError("boom")
            # 3e appel : succès → le superviseur s'arrête

        with patch.object(ns["time"], "sleep", lambda *_: None):
            ns["_supervise"]("test", flaky)
        self.assertEqual(calls["n"], 3)

    def test_backoff_is_capped(self):
        ns = _extract(LINUX, {"_supervise"})
        delays = []

        def always_fail():
            if len(delays) >= 12:
                return          # on arrête après 12 relances pour le test
            raise RuntimeError("boom")

        with patch.object(ns["time"], "sleep", lambda d: delays.append(d)):
            ns["_supervise"]("test", always_fail)
        self.assertEqual(delays[0], 5)
        self.assertLessEqual(max(delays), 300)       # jamais plus de 5 min
        self.assertEqual(delays[-1], 300)


class ServiceTaskXmlTests(unittest.TestCase):
    def setUp(self):
        self.ns = _extract(WINDOWS, {"_service_task_xml"})

    def test_xml_is_well_formed_and_correct(self):
        xml = self.ns["_service_task_xml"](r"C:\Program Files\Heimdall\HeimdallAgent.exe")
        self.assertTrue(xml.startswith('<?xml version="1.0" encoding="UTF-16"?>'))
        root = ET.fromstring(xml.split("?>", 1)[1])
        ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
        self.assertEqual(root.findtext(".//t:Principals/t:Principal/t:UserId", namespaces=ns), "S-1-5-18")
        self.assertEqual(root.findtext(".//t:Principals/t:Principal/t:RunLevel", namespaces=ns), "HighestAvailable")
        self.assertIsNotNone(root.find(".//t:Triggers/t:BootTrigger", ns))
        self.assertEqual(root.findtext(".//t:Settings/t:ExecutionTimeLimit", namespaces=ns), "PT0S")
        self.assertEqual(root.findtext(".//t:Settings/t:RestartOnFailure/t:Count", namespaces=ns), "999")
        self.assertEqual(root.findtext(".//t:Actions/t:Exec/t:Command", namespaces=ns),
                         r"C:\Program Files\Heimdall\HeimdallAgent.exe")
        self.assertEqual(root.findtext(".//t:Actions/t:Exec/t:Arguments", namespaces=ns), "--service")

    def test_special_characters_in_path_are_escaped(self):
        xml = self.ns["_service_task_xml"](r"C:\x & y\a.exe")
        root = ET.fromstring(xml.split("?>", 1)[1])     # ne lève pas : « & » bien échappé
        ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
        self.assertEqual(root.findtext(".//t:Actions/t:Exec/t:Command", namespaces=ns), r"C:\x & y\a.exe")


if __name__ == "__main__":
    unittest.main()
