"""
Command-line interface for xml_tools.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from . import core


def _dump_yaml(data: Dict[str, Any], out_path: Optional[str]) -> None:
    payload = yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=120)
    if not out_path or out_path in ("-", "stdout"):
        print(payload)
        return
    target = Path(out_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(payload, encoding="utf-8")
    print(f"[OK] YAML saved to {target}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Utilities to inspect and manipulate XML templates.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_list = sub.add_parser("list", help="List templates on disk and basic metadata.")
    p_list.add_argument("--path", default=".", help="Root folder to inspect.")
    p_list.add_argument("--pattern", default="*layout*.xml", help="Glob pattern (default: *layout*.xml).")
    p_list.add_argument("--include-level1", action="store_true", help="Include first level node summaries.")
    p_list.add_argument("--titles-tag", help="Collect text nodes for the given tag.")
    p_list.add_argument("--include-path", help="Generic path expression to extract.")
    p_list.add_argument("--with-children", action="store_true", help="Keep children when using include-path.")
    p_list.add_argument("--out", default="-", help="Output file (default: stdout).")

    p_min = sub.add_parser("min-datamodel", help="Return a condensed datamodel for the XML template.")
    p_min.add_argument("--xml", required=True)
    p_min.add_argument("--element-type")
    p_min.add_argument("--path")
    p_min.add_argument("--name")
    p_min.add_argument("--elem-id")
    p_min.add_argument("--show-children", action="store_true")
    p_min.add_argument("--depth-limit", type=int)
    p_min.add_argument("--out", default="-")

    p_full = sub.add_parser("full-datamodel", help="Return a full datamodel with optional filters.")
    p_full.add_argument("--xml", required=True)
    p_full.add_argument("--element-type")
    p_full.add_argument("--path")
    p_full.add_argument("--value")
    p_full.add_argument("--regex", action="store_true")
    p_full.add_argument("--with-children", action="store_true", default=True)
    p_full.add_argument("--depth-limit", type=int)
    p_full.add_argument("--out", default="-")

    p_check = sub.add_parser("check-xsd", help="Validate an XML file or payload against the XSD catalog.")
    p_check.add_argument("--xml", required=True, help="Path or raw XML content.")
    p_check.add_argument("--schemas-dir", required=True)
    p_check.add_argument("--out", default="-")

    p_fix = sub.add_parser("fix-datamodel", help="Apply datamodel and validate against XSD.")
    p_fix.add_argument("--xml", required=True)
    p_fix.add_argument("--datamodel", required=True)
    p_fix.add_argument("--schemas-dir", required=True)
    p_fix.add_argument("--out", default="-")

    p_gen = sub.add_parser("generate-xml", help="Apply datamodel, save XML, and optionally validate.")
    p_gen.add_argument("--xml", required=True)
    p_gen.add_argument("--datamodel", required=True)
    p_gen.add_argument("--out-file", required=True)
    p_gen.add_argument("--schemas-dir")
    p_gen.add_argument("--out", default="-")

    p_extract = sub.add_parser("extract", help="Dump generic representation for the XML file.")
    p_extract.add_argument("--xml", required=True)
    p_extract.add_argument("--out", default="-")

    p_filter = sub.add_parser("filter", help="Generic filter over the full datamodel.")
    p_filter.add_argument("--xml", required=True)
    p_filter.add_argument("--element-type")
    p_filter.add_argument("--path")
    p_filter.add_argument("--value")
    p_filter.add_argument("--regex", action="store_true")
    p_filter.add_argument("--with-children", action="store_true", default=True)
    p_filter.add_argument("--depth-limit", type=int)
    p_filter.add_argument("--out", default="-")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.cmd == "list":
            data = core.get_avail_templates_from_path(
                path=args.path,
                pattern=args.pattern,
                include_level1=bool(args.include_level1),
                titles_tag=args.titles_tag,
                include_path=args.include_path,
                with_children=bool(args.with_children),
            )
        elif args.cmd == "min-datamodel":
            data = core.get_min_datamodel_elements(
                xml_path=args.xml,
                element_type=args.element_type,
                path=args.path,
                name=args.name,
                elem_id=args.elem_id,
                show_children=bool(args.show_children),
                depth_limit=args.depth_limit,
            )
        elif args.cmd == "full-datamodel":
            data = core.get_full_datamodel_elements(
                xml_path=args.xml,
                element_type=args.element_type,
                path=args.path,
                value=args.value,
                regex=bool(args.regex),
                with_children=bool(args.with_children),
                depth_limit=args.depth_limit,
            )
        elif args.cmd == "check-xsd":
            data = core.check_xml_xds(args.xml, args.schemas_dir)
        elif args.cmd == "fix-datamodel":
            data = core.fix_elements_from_template_xsd(args.xml, args.datamodel, args.schemas_dir)
        elif args.cmd == "generate-xml":
            data = core.generate_xml_from_template(
                args.xml,
                args.datamodel,
                args.out_file,
                schemas_dir=args.schemas_dir,
            )
        elif args.cmd == "extract":
            data = {"model": core.parse_xml(args.xml)}
        elif args.cmd == "filter":
            data = core.get_full_datamodel_elements(
                xml_path=args.xml,
                element_type=args.element_type,
                path=args.path,
                value=args.value,
                regex=bool(args.regex),
                with_children=bool(args.with_children),
                depth_limit=args.depth_limit,
            )
        else:  # pragma: no cover - argparse should prevent this path
            parser.print_help()
            return 1
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    _dump_yaml(data, getattr(args, "out", "-"))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
