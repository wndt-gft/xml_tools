"""
Core utilities for converting XML layouts into generic Python/YAML
representations, navigating them, and validating or generating XML
documents against XML Schema definitions (XSD).
"""

from __future__ import annotations

import io
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple, Union
import xml.etree.ElementTree as ET

import yaml

try:
    from lxml import etree as LET
except Exception:  # pragma: no cover - optional dependency
    LET = None  # type: ignore

try:
    import xmlschema  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    xmlschema = None  # type: ignore


GenericNode = Dict[str, Any]
Token = Union[str, int]

_NAME_ATTRS = ("name", "title", "label")
_DESC_ATTRS = ("description", "summary", "desc", "documentation")
_NAME_TAGS = ("name", "title", "label")
_DESC_TAGS = ("description", "documentation", "summary")


# ---------------------------------------------------------------------------
# XML helpers
# ---------------------------------------------------------------------------

def _localname(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def _node_ns_uri(tag: str) -> Optional[str]:
    if "}" in tag:
        return tag.split("}", 1)[0][1:]
    return None


def xml_to_generic(node: ET.Element) -> GenericNode:
    """Convert an ET element into a serialisable dictionary."""
    ns_uri = _node_ns_uri(node.tag)
    data: GenericNode = {"tag": _localname(node.tag)}
    if ns_uri:
        data["ns"] = ns_uri
    if node.attrib:
        data["attrs"] = dict(node.attrib)
    text = (node.text or "").strip()
    if text:
        data["text"] = text
    children = [xml_to_generic(child) for child in list(node)]
    if children:
        data["children"] = children
    return data


def parse_xml(xml_path: Union[str, Path]) -> GenericNode:
    """Parse an XML file into the generic representation."""
    tree = ET.parse(str(xml_path))
    return xml_to_generic(tree.getroot())


# ---------------------------------------------------------------------------
# Generic model navigation
# ---------------------------------------------------------------------------

def tokenize_path(path: str) -> List[Token]:
    """
    Split a dotted path with optional indexes into tokens,
    e.g. ``children[0].attrs.id`` -> ["children", 0, "attrs", "id"].
    """
    tokens: List[Token] = []
    buf = ""
    i = 0
    while i < len(path):
        ch = path[i]
        if ch == ".":
            if buf:
                tokens.append(buf)
                buf = ""
            i += 1
            continue
        if ch == "[":
            if buf:
                tokens.append(buf)
                buf = ""
            end = path.find("]", i)
            if end == -1:
                raise ValueError(f"Malformed path, missing ']': {path}")
            inside = path[i + 1 : end].strip()
            if inside == "*":
                tokens.append("*")
            else:
                if not inside.isdigit():
                    raise ValueError(f"Invalid index in path: [{inside}]")
                tokens.append(int(inside))
            i = end + 1
            continue
        buf += ch
        i += 1
    if buf:
        tokens.append(buf)
    return tokens


def _step(values: Sequence[Any], token: Token) -> List[Any]:
    out: List[Any] = []
    for value in values:
        if token == "*":
            if isinstance(value, dict):
                out.extend(value.values())
            elif isinstance(value, list):
                out.extend(value)
        elif isinstance(token, str):
            if isinstance(value, dict):
                if token in value:
                    out.append(value[token])
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict) and token in item:
                        out.append(item[token])
        else:
            if isinstance(value, list):
                if 0 <= token < len(value):
                    out.append(value[token])
    return out


def get_values_by_path(model: GenericNode, path: str) -> List[Any]:
    """Return values resolved by a dotted path expression."""
    tokens = tokenize_path(path)
    values: List[Any] = [model]
    for tok in tokens:
        values = _step(values, tok)
        if not values:
            break
    return values


# ---------------------------------------------------------------------------
# Discovery and metadata helpers
# ---------------------------------------------------------------------------

def _truncate(text: Optional[str], max_chars: int = 200) -> Optional[str]:
    if not text:
        return None
    text = text.strip()
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 1] + "…"


def _first_non_empty_text(element: ET.Element, tags: Tuple[str, ...]) -> Optional[str]:
    for child in list(element):
        if _localname(child.tag) in tags:
            value = (child.text or "").strip()
            if value:
                return value
    for child in list(element):
        value = _first_non_empty_text(child, tags)
        if value:
            return value
    return None


def _attr_first(element: ET.Element, attrs: Tuple[str, ...]) -> Optional[str]:
    if not element.attrib:
        return None
    lower_map = {name.lower(): name for name in element.attrib}
    for attr in attrs:
        actual = lower_map.get(attr.lower())
        if actual:
            value = (element.attrib[actual] or "").strip()
            if value:
                return value
    return None


def _derive_name(element: ET.Element) -> Optional[str]:
    return _first_non_empty_text(element, _NAME_TAGS) or _attr_first(element, _NAME_ATTRS)


def _derive_description(element: ET.Element) -> Optional[str]:
    return _first_non_empty_text(element, _DESC_TAGS) or _attr_first(element, _DESC_ATTRS)


def _elem_brief(element: ET.Element, max_chars: int = 160) -> Dict[str, Any]:
    brief: Dict[str, Any] = {"tag": _localname(element.tag)}
    ns_uri = _node_ns_uri(element.tag)
    if ns_uri:
        brief["ns"] = ns_uri
    if element.attrib:
        brief["attrs"] = dict(element.attrib)
    text = (element.text or "").strip()
    if text:
        brief["text"] = _truncate(text, max_chars)
    children = list(element)
    if children:
        brief["childrenCount"] = len(children)
    return brief


def extract_template_metadata(root: ET.Element) -> Tuple[Optional[str], Optional[str]]:
    template_name = _attr_first(root, _NAME_ATTRS) or _derive_name(root)
    layout_name = None
    for child in list(root):
        layout_name = _derive_name(child)
        if layout_name:
            break
    return template_name, layout_name


def get_avail_templates_from_path(
    path: Union[str, Path],
    pattern: str = "*layout*.xml",
    include_level1: bool = False,
    titles_tag: Optional[str] = None,
    include_path: Optional[str] = None,
    with_children: bool = False,
) -> Dict[str, Any]:
    """
    Discover templates under ``path`` matching ``pattern`` and return their
    metadata. Optional flags add more expensive payloads.
    """
    base = Path(path)
    files = sorted(p for p in base.rglob(pattern) if p.is_file())
    results: List[Dict[str, Any]] = []

    for fp in files:
        entry: Dict[str, Any] = {"filename": str(fp.relative_to(base))}
        try:
            tree = ET.parse(fp)
            root = tree.getroot()
        except Exception as exc:  # pragma: no cover - parse errors are rare
            entry["error"] = f"parse failed: {exc}"
            results.append(entry)
            continue

        template_name, layout_name = extract_template_metadata(root)
        entry["template_name"] = template_name
        if layout_name:
            entry["layout_name"] = layout_name

        document: Dict[str, Any] = {"tag": _localname(root.tag)}
        ns_uri = _node_ns_uri(root.tag)
        if ns_uri:
            document["ns"] = ns_uri
        if root.attrib:
            document["attrs"] = dict(root.attrib)
        text = (root.text or "").strip()
        if text:
            document["text"] = text
        entry["document"] = document

        elements_meta: List[Dict[str, Any]] = []
        for child in list(root):
            item = {"tag": _localname(child.tag)}
            name = _derive_name(child)
            desc = _derive_description(child)
            if name:
                item["name"] = _truncate(name)
            if desc:
                item["description"] = _truncate(desc)
            if child.attrib:
                item["attrs"] = dict(child.attrib)
            elements_meta.append(item)
        if elements_meta:
            entry["elements"] = elements_meta

        includes: Dict[str, Any] = {}
        if include_level1:
            includes["level1"] = [_elem_brief(child) for child in list(root)]
        if titles_tag:
            titles: List[str] = []

            def _collect_titles(el: ET.Element) -> None:
                if _localname(el.tag) == titles_tag:
                    text_value = (el.text or "").strip()
                    if text_value:
                        titles.append(_truncate(text_value))
                for child_el in list(el):
                    _collect_titles(child_el)

            _collect_titles(root)
            includes["titles"] = titles
        if include_path:
            model = xml_to_generic(root)
            values = get_values_by_path(model, include_path)
            processed: List[Any] = []
            for value in values:
                if isinstance(value, dict) and not with_children and "children" in value:
                    shallow = dict(value)
                    shallow.pop("children", None)
                    processed.append(shallow)
                else:
                    processed.append(value)
            includes["by_path"] = {"path": include_path, "values": processed}
        if includes:
            entry["includes"] = includes

        results.append(entry)
    return {"templates": results}


# ---------------------------------------------------------------------------
# Datamodel builders
# ---------------------------------------------------------------------------

def _min_node_from_xml(node: ET.Element, depth_limit: Optional[int]) -> GenericNode:
    out: GenericNode = {"tag": _localname(node.tag)}
    name = _derive_name(node)
    description = _derive_description(node)
    if name:
        out["name"] = name
    if description:
        out["documentation"] = description

    if node.attrib:
        kept = {}
        for attr in ("id", "ref", "name"):
            value = node.attrib.get(attr)
            if value and value.strip():
                kept[attr] = value
        if kept:
            out["attrs"] = kept

    if depth_limit is not None and depth_limit <= 0:
        return out

    children: List[GenericNode] = []
    for child in list(node):
        children.append(_min_node_from_xml(child, None if depth_limit is None else depth_limit - 1))
    if children:
        out["children"] = children
    return out


def get_min_datamodel_elements(
    xml_path: Union[str, Path],
    element_type: Optional[str] = None,
    path: Optional[str] = None,
    name: Optional[str] = None,
    elem_id: Optional[str] = None,
    show_children: bool = False,
    depth_limit: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Build a condensed datamodel for the first level elements in ``xml_path``.
    Optional filters make the traversal recursive.
    """
    tree = ET.parse(str(xml_path))
    root = tree.getroot()
    candidates: Iterable[ET.Element] = list(root)

    if any((element_type, path, name, elem_id)):
        candidates = list(root.iter())

    model = xml_to_generic(root)
    results: List[GenericNode] = []

    name_lower = name.lower() if name else None
    id_lower = elem_id.lower() if elem_id else None

    for element in candidates:
        if element_type and _localname(element.tag) != element_type:
            continue
        if name_lower:
            candidate_name = (_derive_name(element) or "").lower()
            if candidate_name != name_lower:
                continue
        if id_lower and (element.attrib.get("id", "")).lower() != id_lower:
            continue
        if path:
            values = get_values_by_path(model, path)
            if not any(v == _derive_name(element) for v in values):
                continue
        value = _min_node_from_xml(element, None if show_children else 0 if depth_limit is None else depth_limit)
        results.append(value)

    return {"min_datamodel": results}


def _collect_full_nodes(
    element: ET.Element,
    regex: Optional[re.Pattern[str]],
    element_type: Optional[str],
    path: Optional[str],
    value: Optional[str],
    with_children: bool,
    depth_limit: Optional[int],
) -> List[GenericNode]:
    matches: List[GenericNode] = []
    if element_type:
        nodes = [el for el in element.iter() if _localname(el.tag) == element_type]
    else:
        nodes = list(element.iter())[1:]  # skip the root element by default

    for node in nodes:
        generic = xml_to_generic(node)
        if not with_children and "children" in generic:
            generic = dict(generic)
            generic.pop("children", None)
        if depth_limit is not None:
            generic = _limit_depth(generic, depth_limit)

        if path or value or regex:
            values = get_values_by_path(generic, path) if path else [generic]
            haystack = [str(v) for v in values]
            if regex:
                if not any(regex.search(h) for h in haystack):
                    continue
            elif value is not None:
                if not any(value == h for h in haystack):
                    continue

        matches.append(generic)
    return matches


def _limit_depth(node: GenericNode, depth_limit: int) -> GenericNode:
    if depth_limit <= 0:
        shallow = dict(node)
        shallow.pop("children", None)
        return shallow
    children = node.get("children")
    if not isinstance(children, list):
        return dict(node)
    limited = dict(node)
    limited["children"] = [_limit_depth(child, depth_limit - 1) for child in children]
    return limited


def get_full_datamodel_elements(
    xml_path: Union[str, Path],
    element_type: Optional[str] = None,
    path: Optional[str] = None,
    value: Optional[str] = None,
    regex: bool = False,
    with_children: bool = True,
    depth_limit: Optional[int] = None,
) -> Dict[str, Any]:
    """Return a full datamodel filtered by several criteria."""
    tree = ET.parse(str(xml_path))
    root = tree.getroot()
    pattern = re.compile(value) if regex and value else None
    matches = _collect_full_nodes(
        root,
        pattern,
        element_type,
        path,
        value if not regex else None,
        with_children,
        depth_limit,
    )
    return {"full_datamodel": matches}


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _load_yaml(data: Union[str, Path]) -> Any:
    if isinstance(data, Path) or (isinstance(data, str) and os.path.exists(data)):
        return yaml.safe_load(Path(data).read_text(encoding="utf-8"))
    return yaml.safe_load(str(data))


def _apply_datamodel_to_element(element: ET.Element, node_model: Dict[str, Any], allow_create: bool = True) -> None:
    """
    Merge a node description into ``element`` by either applying attributes/text
    to the element itself or creating/finding the child described in the model.
    """
    target = element
    model_tag = node_model.get("tag")

    if model_tag and _localname(element.tag) != model_tag:
        attrs = node_model.get("attrs", {})
        key_id = attrs.get("id")
        key_ref = attrs.get("ref")
        key_name = attrs.get("name")

        for child in list(element):
            if _localname(child.tag) != model_tag:
                continue
            if key_id is not None and child.attrib.get("id") != str(key_id):
                continue
            if key_ref is not None and child.attrib.get("ref") != str(key_ref):
                continue
            if key_name is not None and child.attrib.get("name") != str(key_name):
                continue
            target = child
            break
        else:
            if not allow_create:
                return
            ns_uri = _node_ns_uri(element.tag)
            qname = model_tag if ns_uri is None else f"{{{ns_uri}}}{model_tag}"
            target = ET.SubElement(element, qname)

    for key, value in node_model.get("attrs", {}).items():
        target.set(key, str(value))

    if "text" in node_model and node_model["text"] is not None:
        target.text = str(node_model["text"])

    for child_model in node_model.get("children", []) or []:
        _apply_datamodel_to_element(target, child_model, allow_create=allow_create)


def check_xml_xds(xml_or_path: Union[str, Path], schemas_dir: Union[str, Path]) -> Dict[str, Any]:
    """
    Validate ``xml_or_path`` against every XSD found under ``schemas_dir``.
    Returns ``{"valid": bool, "errors": [...]}``.
    """
    xml_input = xml_or_path
    xml_data: str

    if isinstance(xml_input, (str, Path)) and Path(xml_input).exists():
        xml_data = Path(xml_input).read_text(encoding="utf-8")
    else:
        xml_data = str(xml_input)

    schemas_path = Path(schemas_dir)
    xsds = sorted(p for p in schemas_path.rglob("*.xsd") if p.is_file())
    if not xsds:
        raise FileNotFoundError(f"No XSD files found under {schemas_dir}")

    if xmlschema is not None:
        return _validate_with_xmlschema(xml_data, xsds)
    if LET is not None:
        return _validate_with_lxml(xml_data, xsds)
    raise RuntimeError("Neither xmlschema nor lxml is available for XSD validation.")


def _validate_with_xmlschema(xml_data: str, xsds: Sequence[Path]) -> Dict[str, Any]:
    report: Dict[str, Any] = {"valid": False, "errors": []}
    xml_doc = xmlschema.XMLResource(io.StringIO(xml_data))
    for schema_file in xsds:
        schema = xmlschema.XMLSchema(str(schema_file))
        if schema.is_valid(xml_doc):
            report["valid"] = True
            return report
        report["errors"].extend(str(err) for err in schema.iter_errors(xml_doc))
    return report


def _validate_with_lxml(xml_data: str, xsds: Sequence[Path]) -> Dict[str, Any]:
    report: Dict[str, Any] = {"valid": False, "errors": []}
    try:
        xml_doc = LET.fromstring(xml_data.encode("utf-8"))
    except Exception as exc:  # pragma: no cover - invalid xml not produced in tests
        report["errors"].append(f"XML parse failed: {exc}")
        return report

    for schema_file in xsds:
        schema_doc = LET.parse(str(schema_file))
        schema = LET.XMLSchema(schema_doc)
        if schema.validate(xml_doc):
            report["valid"] = True
            return report
        report["errors"].extend(str(err) for err in schema.error_log)
    return report


def fix_elements_from_template_xsd(
    xml_path: Union[str, Path], datamodel_yaml: Union[str, Path], schemas_dir: Union[str, Path]
) -> Dict[str, Any]:
    """
    Apply a datamodel onto the XML template and validate against XSDs.
    Returns ``{"ok": bool, "errors": [...], "xml": "<payload>"}``.
    """
    tree = ET.parse(str(xml_path))
    root = tree.getroot()

    datamodel = _load_yaml(datamodel_yaml)
    if isinstance(datamodel, dict) and datamodel.get("tag") == _localname(root.tag) and "children" in datamodel:
        _apply_datamodel_to_element(root, datamodel, allow_create=True)
    elif isinstance(datamodel, dict) and datamodel.get("min_datamodel"):
        for node in datamodel["min_datamodel"]:
            _apply_datamodel_to_element(root, node, allow_create=True)
    elif isinstance(datamodel, dict) and datamodel.get("full_datamodel"):
        _apply_datamodel_to_element(root, datamodel["full_datamodel"], allow_create=True)
    else:
        raise ValueError("Unsupported datamodel structure.")

    xml_output = ET.tostring(root, encoding="utf-8").decode("utf-8")
    report = check_xml_xds(xml_output, schemas_dir)
    return {"ok": bool(report.get("valid")), "errors": report.get("errors", []), "xml": xml_output}


def generate_xml_from_template(
    xml_path: Union[str, Path],
    datamodel_yaml: Union[str, Path],
    out_file: Union[str, Path],
    schemas_dir: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """
    Apply ``datamodel_yaml`` to a template and save the new XML in ``out_file``.
    Optionally validate the generated document.
    """
    if schemas_dir:
        fix_report = fix_elements_from_template_xsd(xml_path, datamodel_yaml, schemas_dir)
        payload = fix_report.get("xml", "")
        ok = bool(fix_report.get("ok"))
        errors = fix_report.get("errors", [])
    else:
        tree = ET.parse(str(xml_path))
        root = tree.getroot()
        datamodel = _load_yaml(datamodel_yaml)
        if isinstance(datamodel, dict) and datamodel.get("tag") == _localname(root.tag) and "children" in datamodel:
            _apply_datamodel_to_element(root, datamodel, allow_create=True)
        elif isinstance(datamodel, dict) and datamodel.get("min_datamodel"):
            for node in datamodel["min_datamodel"]:
                _apply_datamodel_to_element(root, node, allow_create=True)
        elif isinstance(datamodel, dict) and datamodel.get("full_datamodel"):
            _apply_datamodel_to_element(root, datamodel["full_datamodel"], allow_create=True)
        else:
            raise ValueError("Unsupported datamodel structure.")
        payload = ET.tostring(root, encoding="utf-8").decode("utf-8")
        ok = True
        errors = []

    Path(out_file).parent.mkdir(parents=True, exist_ok=True)
    Path(out_file).write_text(payload, encoding="utf-8")
    return {"ok": ok, "errors": errors, "out_file": str(out_file)}


__all__ = [
    "GenericNode",
    "check_xml_xds",
    "extract_template_metadata",
    "fix_elements_from_template_xsd",
    "generate_xml_from_template",
    "get_avail_templates_from_path",
    "get_full_datamodel_elements",
    "get_min_datamodel_elements",
    "get_values_by_path",
    "parse_xml",
    "tokenize_path",
    "xml_to_generic",
]
