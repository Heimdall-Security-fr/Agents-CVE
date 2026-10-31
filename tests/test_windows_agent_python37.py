"""L'exe Windows est construit avec le Python 3.7 de l'image cdrx/pyinstaller-windows.
Une construction plus récente passe la compilation mais fait planter l'agent au
démarrage (les annotations sont évaluées au chargement du module) — et un agent qui
ne démarre plus ne peut plus se mettre à jour. Ce test refuse ces constructions."""
import ast
import os
import unittest

SOURCE = os.path.join(os.path.dirname(__file__), "..", "windows_agent_tray.py")
BUILTIN_GENERICS = {"list", "dict", "tuple", "set", "frozenset", "type"}   # list[str] : Python 3.9
NEW_STR_METHODS = {"removeprefix", "removesuffix"}                          # Python 3.9


class Python37CompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(SOURCE, encoding="utf-8") as f:
            cls.tree = ast.parse(f.read())

    def annotations(self):
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                args = node.args
                for a in args.args + args.kwonlyargs + getattr(args, "posonlyargs", []) + \
                        [x for x in (args.vararg, args.kwarg) if x]:
                    if a.annotation is not None:
                        yield a.annotation
                if node.returns is not None:
                    yield node.returns
            elif isinstance(node, ast.AnnAssign):
                yield node.annotation

    def test_no_union_or_builtin_generics_in_annotations(self):
        problems = []
        for ann in self.annotations():
            for sub in ast.walk(ann):
                if isinstance(sub, ast.BinOp) and isinstance(sub.op, ast.BitOr):
                    problems.append(f"ligne {sub.lineno} : union « X | Y » (Python 3.10)")
                if isinstance(sub, ast.Subscript) and isinstance(sub.value, ast.Name) \
                        and sub.value.id in BUILTIN_GENERICS:
                    problems.append(f"ligne {sub.lineno} : {sub.value.id}[…] (Python 3.9)")
        self.assertEqual(problems, [])

    def test_no_python38_plus_syntax_or_methods(self):
        problems = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.NamedExpr):
                problems.append(f"ligne {node.lineno} : opérateur « := » (Python 3.8)")
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.args.posonlyargs:
                problems.append(f"ligne {node.lineno} : paramètres positionnels seuls « / » (Python 3.8)")
            if isinstance(node, ast.Attribute) and node.attr in NEW_STR_METHODS:
                problems.append(f"ligne {node.lineno} : .{node.attr}() (Python 3.9)")
        self.assertEqual(problems, [])


if __name__ == "__main__":
    unittest.main()
