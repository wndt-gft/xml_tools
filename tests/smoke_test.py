#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

import yaml

BASE = Path(__file__).parent.resolve()
OUT_BASE = BASE / "out"
MOCKS_DIR = BASE / "mocks"
TOOL = BASE.parent / "xml_tools.py"


def fail(msg: str) -> None:
    print(f"[FAIL] {msg}", file=sys.stderr)
    sys.exit(1)


def warn(msg: str) -> None:
    print(f"[WARN] {msg}", file=sys.stderr)


def ok(msg: str) -> None:
    print(f"[OK] {msg}")


def run_cmd(args: List[str], cwd: Optional[Path] = None) -> subprocess.CompletedProcess:
    cp = subprocess.run(args, cwd=cwd, capture_output=True, text=True)
    if cp.returncode != 0:
        if cp.stdout:
            print(cp.stdout)
        if cp.stderr:
            print(cp.stderr, file=sys.stderr)
        fail(f"Command failed: {' '.join(args)} (rc={cp.returncode})")
    return cp


def load_yaml(path: Path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def is_subset(expected, actual) -> bool:
    """Recursively check if expected is contained in actual (order-sensitive for lists)."""
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return False
        for key, exp_value in expected.items():
            if key not in actual:
                return False
            if not is_subset(exp_value, actual[key]):
                return False
        return True
    if isinstance(expected, list):
        if not isinstance(actual, list):
            return False
        if len(expected) != len(actual):
            return False
        return all(is_subset(e, a) for e, a in zip(expected, actual))
    return expected == actual


@dataclass
class Scenario:
    root: Path
    out_dir: Path = field(init=False)
    expected_dir: Optional[Path] = field(init=False)
    schemas_dir: Optional[Path] = field(init=False)
    xml_main: Optional[Path] = field(init=False)
    datamodel: Optional[Path] = field(init=False)

    def __post_init__(self) -> None:
        self.out_dir = OUT_BASE / self.root.name
        exp_dir = self.root / "expected"
        self.expected_dir = exp_dir if exp_dir.is_dir() else None
        schema_dir = self.root / "schemas"
        self.schemas_dir = schema_dir if schema_dir.is_dir() else None
        self.xml_main = self._select_primary_xml()
        self.datamodel = self._select_datamodel()

    @property
    def name(self) -> str:
        return self.root.name

    def ensure_out_dir(self) -> None:
        self.out_dir.mkdir(parents=True, exist_ok=True)

    def expected(self, name: str) -> Optional[Path]:
        if not self.expected_dir:
            return None
        candidate = self.expected_dir / name
        return candidate if candidate.exists() else None

    def _select_primary_xml(self) -> Optional[Path]:
        preferred = self.root / "sample_layout.xml"
        if preferred.exists():
            return preferred
        candidates = sorted(self.root.glob("*.xml"))
        return candidates[0] if candidates else None

    def _select_datamodel(self) -> Optional[Path]:
        preferred = self.root / "datamodel_min.yaml"
        if preferred.exists():
            return preferred
        candidates = sorted(self.root.glob("*datamodel*.yaml"))
        return candidates[0] if candidates else None

    def is_valid(self) -> bool:
        return self.xml_main is not None


@dataclass
class Stage:
    label: str
    runner: Callable[[Scenario], None]


def stage_list(scn: Scenario) -> None:
    expected = scn.expected("list_min.yaml")
    if expected is None:
        warn(f"{scn.name}: expected/list_min.yaml ausente; pulando etapa list.")
        return
    out_path = scn.out_dir / "list.yaml"
    run_cmd(
        [
            sys.executable,
            str(TOOL),
            "list",
            "--path",
            ".",
            "--pattern",
            "*layout*.xml",
            "--out",
            str(out_path),
        ],
        cwd=scn.root,
    )
    out_list = load_yaml(out_path)
    exp_list = load_yaml(expected)
    if not is_subset(exp_list, out_list):
        print("Esperado:")
        print(yaml.safe_dump(exp_list, sort_keys=False, allow_unicode=True))
        print("Obtido:")
        print(yaml.safe_dump(out_list, sort_keys=False, allow_unicode=True))
        fail(f"{scn.name}: list.yaml nao corresponde ao esperado (subset).")
    ok(f"{scn.name}: list.yaml ok")


def stage_min_datamodel(scn: Scenario) -> None:
    if scn.xml_main is None:
        warn(f"{scn.name}: nenhum XML encontrado; pulando etapa min-datamodel.")
        return
    expected = scn.expected("min_datamodel_default.yaml")
    if expected is None:
        warn(f"{scn.name}: expected/min_datamodel_default.yaml ausente; pulando etapa min-datamodel.")
        return
    out_path = scn.out_dir / "min.yaml"
    run_cmd(
        [
            sys.executable,
            str(TOOL),
            "min-datamodel",
            "--xml",
            str(scn.xml_main),
            "--out",
            str(out_path),
        ],
        cwd=scn.root,
    )
    out_min = load_yaml(out_path)
    exp_min = load_yaml(expected)
    if not is_subset(exp_min, out_min):
        print("Esperado:")
        print(yaml.safe_dump(exp_min, sort_keys=False, allow_unicode=True))
        print("Obtido:")
        print(yaml.safe_dump(out_min, sort_keys=False, allow_unicode=True))
        fail(f"{scn.name}: min.yaml nao corresponde ao esperado (subset).")
    ok(f"{scn.name}: min.yaml ok")


def stage_full_datamodel(scn: Scenario) -> None:
    if scn.xml_main is None:
        warn(f"{scn.name}: nenhum XML encontrado; pulando etapa full-datamodel.")
        return
    expected = scn.expected("full_regex_items.yaml")
    if expected is None:
        warn(f"{scn.name}: expected/full_regex_items.yaml ausente; pulando etapa full-datamodel.")
        return
    out_path = scn.out_dir / "full_items.yaml"
    run_cmd(
        [
            sys.executable,
            str(TOOL),
            "full-datamodel",
            "--xml",
            str(scn.xml_main),
            "--path",
            "children[*].text",
            "--value",
            "Item.*",
            "--regex",
            "--out",
            str(out_path),
        ],
        cwd=scn.root,
    )
    out_full = load_yaml(out_path)
    exp_full = load_yaml(expected)
    if not is_subset(exp_full, out_full):
        print("Esperado:")
        print(yaml.safe_dump(exp_full, sort_keys=False, allow_unicode=True))
        print("Obtido:")
        print(yaml.safe_dump(out_full, sort_keys=False, allow_unicode=True))
        fail(f"{scn.name}: full_items.yaml nao corresponde ao esperado (subset).")
    ok(f"{scn.name}: full_items.yaml ok")


def stage_check_xsd(scn: Scenario) -> None:
    if scn.xml_main is None:
        warn(f"{scn.name}: nenhum XML encontrado; pulando etapa check-xsd.")
        return
    if scn.schemas_dir is None:
        warn(f"{scn.name}: nenhum diretorio schemas encontrado; pulando etapa check-xsd.")
        return
    out_path = scn.out_dir / "check.yaml"
    run_cmd(
        [
            sys.executable,
            str(TOOL),
            "check-xsd",
            "--xml",
            str(scn.xml_main),
            "--schemas-dir",
            str(scn.schemas_dir),
            "--out",
            str(out_path),
        ],
        cwd=scn.root,
    )
    out_check = load_yaml(out_path)
    if not isinstance(out_check, dict) or out_check.get("valid") is not True:
        fail(f"{scn.name}: check-xsd nao retornou valid=True.")
    ok(f"{scn.name}: check-xsd ok")


def stage_fix_datamodel(scn: Scenario) -> None:
    if scn.xml_main is None or scn.datamodel is None:
        warn(f"{scn.name}: XML ou datamodel ausente; pulando etapa fix-datamodel.")
        return
    if scn.schemas_dir is None:
        warn(f"{scn.name}: nenhum diretorio schemas encontrado; pulando etapa fix-datamodel.")
        return
    out_path = scn.out_dir / "fix.yaml"
    run_cmd(
        [
            sys.executable,
            str(TOOL),
            "fix-datamodel",
            "--xml",
            str(scn.xml_main),
            "--datamodel",
            str(scn.datamodel),
            "--schemas-dir",
            str(scn.schemas_dir),
            "--out",
            str(out_path),
        ],
        cwd=scn.root,
    )
    out_fix = load_yaml(out_path)
    if out_fix.get("ok") is not True:
        fail(f"{scn.name}: fix-datamodel nao retornou ok=True.")
    xml_payload = out_fix.get("xml")
    if not isinstance(xml_payload, str) or not xml_payload.strip():
        fail(f"{scn.name}: fix-datamodel nao retornou XML gerado.")
    ok(f"{scn.name}: fix-datamodel ok")


def stage_generate_xml(scn: Scenario) -> None:
    if scn.xml_main is None or scn.datamodel is None:
        warn(f"{scn.name}: XML ou datamodel ausente; pulando etapa generate-xml.")
        return
    if scn.schemas_dir is None:
        warn(f"{scn.name}: nenhum diretorio schemas encontrado; pulando etapa generate-xml.")
        return
    out_yaml = scn.out_dir / "generate.yaml"
    generated_xml = scn.out_dir / "generated.xml"
    run_cmd(
        [
            sys.executable,
            str(TOOL),
            "generate-xml",
            "--xml",
            str(scn.xml_main),
            "--datamodel",
            str(scn.datamodel),
            "--out-file",
            str(generated_xml),
            "--schemas-dir",
            str(scn.schemas_dir),
            "--out",
            str(out_yaml),
        ],
        cwd=scn.root,
    )
    out_gen = load_yaml(out_yaml)
    if out_gen.get("ok") is not True or not generated_xml.exists():
        fail(f"{scn.name}: generate-xml nao produziu saida esperada.")
    check_yaml = scn.out_dir / "check_generated.yaml"
    run_cmd(
        [
            sys.executable,
            str(TOOL),
            "check-xsd",
            "--xml",
            str(generated_xml),
            "--schemas-dir",
            str(scn.schemas_dir),
            "--out",
            str(check_yaml),
        ],
        cwd=scn.root,
    )
    out_check = load_yaml(check_yaml)
    if out_check.get("valid") is not True:
        fail(f"{scn.name}: generated.xml nao eh valido contra XSD.")
    ok(f"{scn.name}: generate-xml ok")


STAGES: List[Stage] = [
    Stage("list", stage_list),
    Stage("min-datamodel", stage_min_datamodel),
    Stage("full-datamodel", stage_full_datamodel),
    Stage("check-xsd", stage_check_xsd),
    Stage("fix-datamodel", stage_fix_datamodel),
    Stage("generate-xml", stage_generate_xml),
]


def discover_scenarios(base: Path) -> List[Scenario]:
    if not base.is_dir():
        warn(f"Nenhum diretorio de mocks encontrado em {base}.")
        return []
    scenarios: List[Scenario] = []
    for path in sorted(base.iterdir()):
        if not path.is_dir():
            continue
        scenario = Scenario(path)
        if scenario.is_valid():
            scenarios.append(scenario)
        else:
            warn(f"{path.name}: ignorado (nenhum XML principal encontrado).")
    return scenarios


def main() -> int:
    if not TOOL.exists():
        fail(f"xml_tools.py nao encontrado em: {TOOL}")
    OUT_BASE.mkdir(parents=True, exist_ok=True)

    scenarios = discover_scenarios(MOCKS_DIR)
    if not scenarios:
        fail("Nenhum cenario valido encontrado para smoke tests.")

    total_stages = len(STAGES)
    for scenario in scenarios:
        scenario.ensure_out_dir()
        print(f"\n=== Scenario: {scenario.name} ===")
        for idx, stage in enumerate(STAGES, start=1):
            print(f"\n[{scenario.name} {idx}/{total_stages}] {stage.label} ...")
            stage.runner(scenario)

    print("\nAll smoke tests PASSED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
