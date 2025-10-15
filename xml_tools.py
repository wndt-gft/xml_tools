#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
xml_tools.py — Utilidades genéricas para XML em YAML + filtros e XSD

APIs principais (também expostas via CLI):

- get_avail_templates_from_path(path, pattern="*layout*.xml", include_level1=False,
                                titles_tag=None, include_path=None, with_children=False)
- get_min_datamodel_elements(xml_path, element_type=None, path=None, name=None, elem_id=None,
                             show_children=False, depth_limit=None)
- get_full_datamodel_elements(xml_path, element_type=None, path=None, value=None, regex=False,
                              with_children=True, depth_limit=None)
- fix_elements_from_template_xsd(xml_path, datamodel_yaml, schemas_dir)
- check_xml_xds(xml_or_str, schemas_dir)
- generate_xml_from_template(xml_path, datamodel_yaml, out_file, schemas_dir=None)

CLI:
  extract           -> modelo completo (genérico)
  filter            -> filtro genérico por element-type / path / value (regex opcional)
  list              -> lista arquivos/padrões, metadados + inclusões opcionais
  min-datamodel     -> datamodel mínimo (hierarquia enxuta)
  full-datamodel    -> coleção completa filtrável
  check-xsd         -> valida um XML (arquivo ou string) contra XSDs
  fix-datamodel     -> valida/ajusta datamodel contra XSDs
  generate-xml      -> aplica datamodel no template e salva XML (valida se XSDs)

Requisitos:
  - Python 3.8+
  - pip install pyyaml lxml xmlschema
"""

from __future__ import annotations
import argparse
import io
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union
import xml.etree.ElementTree as ET
import yaml

# XSD libs (opcionais)
try:
    from lxml import etree as LET
except Exception:
    LET = None  # type: ignore

try:
    import xmlschema
except Exception:
    xmlschema = None  # type: ignore


# ============================================================
# Conversão XML → Modelo genérico (tag, ns, attrs, text, children)
# ============================================================

def _localname(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag

def _node_ns_uri(tag: str) -> Optional[str]:
    if "}" in tag:
        return tag.split("}", 1)[0][1:]
    return None

def xml_to_generic(node: ET.Element) -> Dict[str, Any]:
    ns_uri = _node_ns_uri(node.tag)
    attrs = dict(node.attrib) if node.attrib else {}
    text = (node.text or "").strip() or None
    children = [xml_to_generic(c) for c in list(node)]
    out: Dict[str, Any] = {"tag": _localname(node.tag)}
    if ns_uri: out["ns"] = ns_uri
    if attrs: out["attrs"] = attrs
    if text: out["text"] = text
    if children: out["children"] = children
    return out

def parse_xml(xml_path: str) -> Dict[str, Any]:
    tree = ET.parse(xml_path)
    root = tree.getroot()
    return xml_to_generic(root)

# ============================================================
# Path navigation no modelo genérico
# ============================================================

Token = Union[str, int]

def tokenize_path(path: str) -> List[Token]:
    tokens: List[Token] = []
    buf = ""; i = 0
    while i < len(path):
        ch = path[i]
        if ch == ".":
            if buf: tokens.append(buf); buf = ""
            i += 1; continue
        if ch == "[":
            if buf: tokens.append(buf); buf = ""
            j = path.find("]", i)
            if j == -1:
                raise ValueError(f"Path malformado, falta ']': {path}")
            inside = path[i+1:j].strip()
            if inside == "*":
                tokens.append("*")
            else:
                if not inside.isdigit():
                    raise ValueError(f"Índice inválido em path: [{inside}]")
                tokens.append(int(inside))
            i = j + 1; continue
        buf += ch; i += 1
    if buf: tokens.append(buf)
    return tokens

def _step(values: List[Any], tok: Token) -> List[Any]:
    out: List[Any] = []
    for v in values:
        if tok == "*":
            if isinstance(v, dict): out.extend(v.values())
            elif isinstance(v, list): out.extend(v)
        elif isinstance(tok, str):
            if isinstance(v, dict):
                if tok in v: out.append(v[tok])
            elif isinstance(v, list):
                for it in v:
                    if isinstance(it, dict) and tok in it:
                        out.append(it[tok])
        elif isinstance(tok, int):
            if isinstance(v, list) and 0 <= tok < len(v):
                out.append(v[tok])
    return out

def get_values_by_path(obj: Any, path: str) -> List[Any]:
    toks = tokenize_path(path)
    vals: List[Any] = [obj]
    for t in toks:
        vals = _step(vals, t)
        if not vals: break
    return vals

# ============================================================
# Heurísticas genéricas para name/description/documentation
# ============================================================

_CAND_NAME_TAGS = ("name", "title")
_CAND_DESC_TAGS = ("description", "documentation", "summary", "desc")
_CAND_NAME_ATTRS = ("name", "title", "id")
_CAND_DESC_ATTRS = ("description", "summary", "desc")

def _first_non_empty_text(elem: ET.Element, tags: Tuple[str, ...]) -> Optional[str]:
    for c in list(elem):
        if _localname(c.tag) in tags:
            t = (c.text or "").strip()
            if t:
                return t
    for c in list(elem):
        t = _first_non_empty_text(c, tags)
        if t: return t
    return None

def _attr_first(elem: ET.Element, attrs: Tuple[str, ...]) -> Optional[str]:
    lower_map = {k.lower(): k for k in elem.attrib.keys()}
    for a in attrs:
        if a.lower() in lower_map:
            val = (elem.attrib[lower_map[a.lower()]] or "").strip()
            if val: return val
    return None

def extract_name_description(root: ET.Element) -> Tuple[Optional[str], Optional[str]]:
    name = _attr_first(root, _CAND_NAME_ATTRS) or _first_non_empty_text(root, _CAND_NAME_TAGS)
    desc = _attr_first(root, _CAND_DESC_ATTRS) or _first_non_empty_text(root, _CAND_DESC_TAGS)
    return name, desc

# ============================================================
# get_avail_templates_from_path
# ============================================================

def _truncate(s: Optional[str], max_chars: int = 200) -> Optional[str]:
    if not s: return None
    s = s.strip()
    return s if len(s) <= max_chars else s[:max_chars-1] + "…"

def _elem_brief(e: ET.Element, max_chars: int = 160) -> Dict[str, Any]:
    ns_uri = _node_ns_uri(e.tag)
    out: Dict[str, Any] = {"tag": _localname(e.tag)}
    if ns_uri: out["ns"] = ns_uri
    if e.attrib: out["attrs"] = dict(e.attrib)
    t = (e.text or "").strip()
    if t: out["text"] = _truncate(t, max_chars)
    if list(e): out["childrenCount"] = len(list(e))
    return out

def get_avail_templates_from_path(
    path: str,
    pattern: str = "*layout*.xml",
    include_level1: bool = False,
    titles_tag: Optional[str] = None,
    include_path: Optional[str] = None,
    with_children: bool = False,
) -> Dict[str, Any]:
    base = Path(path)
    files = sorted(p for p in base.rglob(pattern) if p.is_file())

    results: List[Dict[str, Any]] = []
    for fp in files:
        entry: Dict[str, Any] = {"filename": str(fp.relative_to(base))}
        try:
            tree = ET.parse(fp)
            root = tree.getroot()
        except Exception as e:
            entry["error"] = f"parse failed: {e}"
            results.append(entry); continue

        template_name, layout_name = extract_name_description(root)
        entry["template_name"] = template_name
        entry["layout_name"] = layout_name
        entry["document"] = {
            "tag": _localname(root.tag),
            "ns": _node_ns_uri(root.tag),
            "attrs": dict(root.attrib) if root.attrib else None,
            "text": (root.text or "").strip() or None,
        }
        # limpeza
        for k in ["ns", "attrs", "text"]:
            if not entry["document"].get(k): entry["document"].pop(k, None)

        # elements (heurístico): nomes e docs potenciais
        elems_meta: List[Dict[str, Any]] = []
        for c in list(root):
            name = _first_non_empty_text(c, _CAND_NAME_TAGS) or _attr_first(c, _CAND_NAME_ATTRS)
            desc = _first_non_empty_text(c, _CAND_DESC_TAGS) or _attr_first(c, _CAND_DESC_ATTRS)
            item = {"tag": _localname(c.tag)}
            if name: item["name"] = _truncate(name)
            if desc: item["description"] = _truncate(desc)
            if c.attrib: item["attrs"] = dict(c.attrib)
            elems_meta.append(item)
        if elems_meta: entry["elements"] = elems_meta

        includes: Dict[str, Any] = {}
        if include_level1:
            includes["level1"] = [_elem_brief(c) for c in list(root)]
        if titles_tag:
            titles: List[str] = []
            def collect_titles(el: ET.Element):
                if _localname(el.tag) == titles_tag:
                    t = (el.text or "").strip()
                    if t: titles.append(_truncate(t))
                for ch in list(el): collect_titles(ch)
            collect_titles(root)
            includes["titles"] = titles
        if include_path:
            model = xml_to_generic(root)
            vals = get_values_by_path(model, include_path)
            out_vals: List[Any] = []
            for v in vals:
                if isinstance(v, dict) and not with_children and "children" in v:
                    v2 = dict(v); v2.pop("children", None)
                    out_vals.append(v2)
                else:
                    out_vals.append(v)
            includes["by_path"] = {"path": include_path, "values": out_vals}
        if includes: entry["includes"] = includes

        results.append(entry)
    return {"templates": results}

# ============================================================
# Datamodel mínimo (tag, name, documentation, children) + filtros
# ============================================================

def _derive_name(node: ET.Element) -> Optional[str]:
    return _first_non_empty_text(node, _CAND_NAME_TAGS) or _attr_first(node, _CAND_NAME_ATTRS) or None

def _derive_doc(node: ET.Element) -> Optional[str]:
    return _first_non_empty_text(node, _CAND_DESC_TAGS) or _attr_first(node, _CAND_DESC_ATTRS) or None

def _min_node_from_xml(node: ET.Element, depth_limit: Optional[int]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"tag": _localname(node.tag)}
    nm = _derive_name(node); dc = _derive_doc(node)
    if nm: out["name"] = nm
    if dc: out["documentation"] = dc
    # preserva 'id'/'ref' se existirem (útil para merge posterior)
    if node.attrib:
        kept = {}
        for k in ("id", "ref", "name"):
            if k in node.attrib and str(node.attrib[k]).strip():
                kept[k] = node.attrib[k]
        if kept: out["attrs"] = kept
    if depth_limit is not None and depth_limit <= 0:
        return out
    children = []
    for c in list(node):
        children.append(_min_node_from_xml(c, None if depth_limit is None else depth_limit - 1))
    if children: out["children"] = children
    return out

def get_min_datamodel_elements(
    xml_path: str,
    element_type: Optional[str] = None,
    path: Optional[str] = None,
    name: Optional[str] = None,
    elem_id: Optional[str] = None,
    show_children: bool = False,
    depth_limit: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Retorna datamodel mínimo:
      - tag, name, documentation, attrs(id/ref), children(opcional)
    Filtros (opcionais):
      - element_type: filtra por tag
      - path: path no modelo genérico (ex.: 'attrs.id' == 'xxx' via name/elem_id/regex — ver exemplos)
      - name: filtra por nome (heurístico) (igualdade case-insensitive)
      - elem_id: filtra por atributo id (igualdade case-insensitive)
    Por padrão, retorna apenas PRIMEIRO NÍVEL (children imediatos do root).
    """
    tree = ET.parse(xml_path); root = tree.getroot()

    # constrói lista de candidatos
    candidates = list(root)  # primeiro nível por padrão
    if element_type or path or name or elem_id:
        # se houver filtros, buscamos na árvore toda
        candidates = list(root.iter())

    results: List[Dict[str, Any]] = []
    model = xml_to_generic(root)  # para uso do path

    for el in candidates:
        if element_type and _localname(el.tag) != element_type:
            continue
        if name:
            nm = (_derive_name(el) or "").lower()
            if nm != name.lower():
                continue
        if elem_id:
            if el.attrib.get("id", "").lower() != elem_id.lower():
                continue
        if path:
            vals = get_values_by_path(xml_to_generic(el), path)
            if not any(str(v).strip() for v in vals):
                continue
        node = _min_node_from_xml(el, (None if show_children else 0) if depth_limit is None else depth_limit)
        results.append(node)

    return {"min_datamodel": results}

# ============================================================
# Datamodel completo (modelo genérico) + filtros opcionais
# ============================================================

def _filter_tree_generic(node: Dict[str, Any], element_type: Optional[str],
                         path: Optional[str], value: Optional[str],
                         regex: bool, with_children: bool,
                         depth_limit: Optional[int]) -> Optional[Dict[str, Any]]:
    """Mantém nó se ele ou algum descendente casar; pode limitar profundidade."""
    # depth cutoff
    if depth_limit is not None and depth_limit <= 0:
        # no cutoff for the current node fields; stop recursing
        kept_children = None
    else:
        kept_children_list: List[Dict[str, Any]] = []
        for ch in node.get("children", []) or []:
            kept = _filter_tree_generic(
                ch, element_type, path, value,
                regex, with_children,
                None if depth_limit is None else depth_limit - 1
            )
            if kept is not None:
                kept_children_list.append(kept)
        kept_children = kept_children_list

    def matches_here(obj: Dict[str, Any]) -> bool:
        if element_type and obj.get("tag") != element_type:
            return False
        if path:
            vals = get_values_by_path(obj, path)
            if value is None:
                return any(str(v).strip() for v in vals)
            if regex:
                return any(re.search(value, str(v), flags=0) for v in vals)
            return any(str(v).lower() == value.lower() for v in vals)
        return True if (not element_type and not path) else True

    me = matches_here(node)
    if kept_children:
        out = {k: v for k, v in node.items() if k != "children"}
        if with_children and kept_children: out["children"] = kept_children
        return out
    if me:
        out = {k: v for k, v in node.items()}
        if not with_children: out.pop("children", None)
        return out
    return None

def get_full_datamodel_elements(
    xml_path: str,
    element_type: Optional[str] = None,
    path: Optional[str] = None,
    value: Optional[str] = None,
    regex: bool = False,
    with_children: bool = True,
    depth_limit: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Retorna coleção completa (modelo genérico) filtrável por:
      - element_type (tag exata),
      - path (+ value, regex opcional),
      - with_children (inclui subárvore),
      - depth_limit (limita profundidade).
    """
    model = parse_xml(xml_path)
    kept = _filter_tree_generic(model, element_type, path, value, regex, with_children, depth_limit)
    return {"full_datamodel": kept or {"_note": "Nada casou com os filtros."}}

# ============================================================
# XSD helpers (validação e (opcional) correção)
# ============================================================

def _collect_xsd_schemas(schemas_dir: str) -> List[Path]:
    p = Path(schemas_dir)
    return [x for x in p.rglob("*.xsd") if x.is_file()]

def check_xml_xds(xml_or_str: str, schemas_dir: str) -> Dict[str, Any]:
    """
    Valida um XML (caminho ou conteúdo) contra XSDs em 'schemas_dir'.
    Requer lxml; se xmlschema estiver disponível, usa-o para mensagens melhores.
    """
    xsds = _collect_xsd_schemas(schemas_dir)
    report: Dict[str, Any] = {"schemas": [str(x) for x in xsds], "valid": False, "errors": []}

    if not xsds:
        report["errors"].append("Nenhum XSD encontrado em schemas_dir.")
        return report

    xml_str = ""
    if os.path.isfile(xml_or_str):
        xml_str = Path(xml_or_str).read_text(encoding="utf-8")
    else:
        xml_str = xml_or_str

    if xmlschema:
        try:
            # tenta criar um "meta-esquema" agregando todos ou valida com o primeiro que casa
            # Aqui validamos contra todos (o que passar em pelo menos um, ok)
            errors_all = []
            for xsdfile in xsds:
                try:
                    xs = xmlschema.XMLSchema(str(xsdfile))
                    v = xs.is_valid(xml_str)
                    if v:
                        report["valid"] = True
                        return report
                    else:
                        errors_all.extend([str(e) for e in xs.iter_errors(xml_str)])
                except Exception as e:
                    errors_all.append(f"{xsdfile}: {e}")
            report["errors"] = errors_all or ["Falha de validação em todos os XSDs."]
            return report
        except Exception as e:
            report["errors"].append(f"xmlschema error: {e}")

    if LET is None:
        report["errors"].append("lxml não disponível para fallback de validação.")
        return report

    # Fallback com lxml: usar o primeiro XSD (melhor do que nada)
    try:
        xml_doc = LET.fromstring(xml_str.encode("utf-8"))
        for xsdfile in xsds:
            schema_doc = LET.parse(str(xsdfile))
            schema = LET.XMLSchema(schema_doc)
            if schema.validate(xml_doc):
                report["valid"] = True
                return report
            else:
                report["errors"].extend([str(e) for e in schema.error_log])
        return report
    except Exception as e:
        report["errors"].append(f"lxml parse/validate error: {e}")
        return report

def _load_yaml(yaml_str_or_path: str) -> Any:
    if os.path.isfile(yaml_str_or_path):
        return yaml.safe_load(Path(yaml_str_or_path).read_text(encoding="utf-8"))
    return yaml.safe_load(yaml_str_or_path)

def _apply_datamodel_to_element(el: ET.Element, dm: Dict[str, Any], allow_create: bool = True):
    """
    Aplica um nó de datamodel (formato genérico) sobre um elemento XML:
      - casa por tag e opcionalmente por attrs(id/ref/name)
      - atualiza text/attrs no elemento correspondente
      - para children: busca/cria filho e aplica recursivamente
    """
    target = el
    dm_tag = dm.get("tag")
    if dm_tag and _localname(el.tag) != dm_tag:
        key_attrs = dm.get("attrs", {})
        key_id = key_attrs.get("id")
        key_ref = key_attrs.get("ref")
        key_name = key_attrs.get("name")

        target = None
        for existing in list(el):
            if _localname(existing.tag) != dm_tag:
                continue
            ok = True
            if key_id is not None and existing.attrib.get("id") != str(key_id):
                ok = False
            if key_ref is not None and existing.attrib.get("ref") != str(key_ref):
                ok = False
            if key_name is not None and existing.attrib.get("name") != str(key_name):
                ok = False
            if ok:
                target = existing
                break

        if target is None:
            if not allow_create:
                return
            ns_uri = _node_ns_uri(el.tag)
            qname = dm_tag if ns_uri is None else f"{{{ns_uri}}}{dm_tag}"
            target = ET.SubElement(el, qname)

    if target is None:
        return

    for k, v in dm.get("attrs", {}).items():
        target.set(k, str(v))

    if "text" in dm and dm["text"] is not None:
        target.text = str(dm["text"])

    for ch in dm.get("children", []) or []:
        _apply_datamodel_to_element(target, ch, allow_create=allow_create)

def fix_elements_from_template_xsd(xml_path: str, datamodel_yaml: str, schemas_dir: str) -> Dict[str, Any]:
    """
    Valida e tenta corrigir/completar o datamodel conforme XSDs:
      - Carrega template (XML) e datamodel (YAML genérico).
      - Aplica datamodel no template (criando faltantes).
      - Valida contra XSDs:
          * Se xmlschema disponível: melhor diagnóstico e auto-preenchimento de defaults em encode.
          * Senão: valida com lxml e lista erros.
      - Retorna {'ok': bool, 'errors': [...], 'xml': '<conteúdo>'}
    """
    # Carrega template
    tree = ET.parse(xml_path)
    root = tree.getroot()

    dm = _load_yaml(datamodel_yaml)
    if isinstance(dm, dict) and "children" in dm and dm.get("tag") == _localname(root.tag):
        # datamodel root
        _apply_datamodel_to_element(root, dm, allow_create=True)
    elif isinstance(dm, dict) and dm.get("min_datamodel"):
        for node in dm["min_datamodel"]:
            _apply_datamodel_to_element(root, node, allow_create=True)
    elif isinstance(dm, dict) and dm.get("full_datamodel"):
        node = dm["full_datamodel"]
        _apply_datamodel_to_element(root, node, allow_create=True)
    else:
        raise ValueError("Formato de datamodel inesperado. Informe YAML compatível (genérico).")

    # Serializa
    xml_bytes = ET.tostring(root, encoding="utf-8")
    xml_str = xml_bytes.decode("utf-8")

    # Valida
    report = check_xml_xds(xml_str, schemas_dir)
    return {"ok": bool(report.get("valid")), "errors": report.get("errors", []), "xml": xml_str}

def generate_xml_from_template(xml_path: str, datamodel_yaml: str, out_file: str, schemas_dir: Optional[str] = None) -> Dict[str, Any]:
    """
    Aplica o datamodel no template, gera XML e salva (valida se schemas_dir for informado).
    Retorna {'ok': bool, 'errors': [...], 'out_file': '<path>'}
    """
    fix = {"ok": True, "errors": [], "xml": ""}
    if schemas_dir:
        fix = fix_elements_from_template_xsd(xml_path, datamodel_yaml, schemas_dir)
        ok = bool(fix.get("ok"))
        xml_out = fix.get("xml", "")
    else:
        # sem validação XSD, apenas aplica e salva
        tree = ET.parse(xml_path); root = tree.getroot()
        dm = _load_yaml(datamodel_yaml)
        if isinstance(dm, dict) and "children" in dm and dm.get("tag") == _localname(root.tag):
            _apply_datamodel_to_element(root, dm, allow_create=True)
        elif isinstance(dm, dict) and dm.get("min_datamodel"):
            for node in dm["min_datamodel"]:
                _apply_datamodel_to_element(root, node, allow_create=True)
        elif isinstance(dm, dict) and dm.get("full_datamodel"):
            _apply_datamodel_to_element(root, dm["full_datamodel"], allow_create=True)
        else:
            raise ValueError("Formato de datamodel inesperado. Informe YAML compatível.")
        xml_out = ET.tostring(root, encoding="utf-8").decode("utf-8")
        ok = True

    Path(out_file).parent.mkdir(parents=True, exist_ok=True)
    Path(out_file).write_text(xml_out, encoding="utf-8")
    return {"ok": ok, "errors": fix.get("errors", []), "out_file": out_file}

# ============================================================
# Wrappers YAML
# ============================================================

def to_yaml(data: Dict[str, Any]) -> str:
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=120)

# ============================================================
# CLI
# ============================================================

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Ferramentas genéricas para XML → YAML, filtros e XSD.")
    sub = p.add_subparsers(dest="cmd", required=True)

    # list
    p_list = sub.add_parser("list", help="Lista templates disponíveis e metadados.")
    p_list.add_argument("--path", default=".", help="Diretório raiz (default: .)")
    p_list.add_argument("--pattern", default="*layout*.xml", help="Glob (default: *layout*.xml)")
    p_list.add_argument("--include-level1", action="store_true")
    p_list.add_argument("--titles-tag")
    p_list.add_argument("--include-path")
    p_list.add_argument("--with-children", action="store_true")
    p_list.add_argument("--out", default="-")

    # extract
    p_ext = sub.add_parser("extract", help="Extrai modelo completo genérico.")
    p_ext.add_argument("--xml", required=True)
    p_ext.add_argument("--out", default="-")

    # filter
    p_filter = sub.add_parser("filter", help="Extrai e filtra (genérico).")
    p_filter.add_argument("--xml", required=True)
    p_filter.add_argument("--element-type")
    p_filter.add_argument("--path")
    p_filter.add_argument("--value")
    p_filter.add_argument("--regex", action="store_true")
    p_filter.add_argument("--with-children", action="store_true", default=True)
    p_filter.add_argument("--depth-limit", type=int)
    p_filter.add_argument("--out", default="-")

    # min-datamodel
    p_min = sub.add_parser("min-datamodel", help="Datamodel mínimo (hierarquia enxuta).")
    p_min.add_argument("--xml", required=True)
    p_min.add_argument("--element-type")
    p_min.add_argument("--path")
    p_min.add_argument("--name")
    p_min.add_argument("--elem-id")
    p_min.add_argument("--show-children", action="store_true")
    p_min.add_argument("--depth-limit", type=int)
    p_min.add_argument("--out", default="-")

    # full-datamodel
    p_full = sub.add_parser("full-datamodel", help="Coleção completa com filtros.")
    p_full.add_argument("--xml", required=True)
    p_full.add_argument("--element-type")
    p_full.add_argument("--path")
    p_full.add_argument("--value")
    p_full.add_argument("--regex", action="store_true")
    p_full.add_argument("--with-children", action="store_true", default=True)
    p_full.add_argument("--depth-limit", type=int)
    p_full.add_argument("--out", default="-")

    # check-xsd
    p_chk = sub.add_parser("check-xsd", help="Valida XML (arquivo ou conteúdo) contra XSDs.")
    p_chk.add_argument("--xml", required=True, help="Caminho OU conteúdo XML")
    p_chk.add_argument("--schemas-dir", required=True)
    p_chk.add_argument("--out", default="-")

    # fix-datamodel
    p_fix = sub.add_parser("fix-datamodel", help="Valida e tenta corrigir datamodel conforme XSDs.")
    p_fix.add_argument("--xml", required=True)
    p_fix.add_argument("--datamodel", required=True, help="Arquivo YAML ou conteúdo YAML")
    p_fix.add_argument("--schemas-dir", required=True)
    p_fix.add_argument("--out", default="-")

    # generate-xml
    p_gen = sub.add_parser("generate-xml", help="Aplica datamodel no template e salva XML (valida se XSDs informados).")
    p_gen.add_argument("--xml", required=True)
    p_gen.add_argument("--datamodel", required=True)
    p_gen.add_argument("--out-file", required=True)
    p_gen.add_argument("--schemas-dir")
    p_gen.add_argument("--out", default="-")

    return p

def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        if args.cmd == "list":
            data = get_avail_templates_from_path(
                path=args.path, pattern=args.pattern, include_level1=bool(args.include_level1),
                titles_tag=args.titles_tag, include_path=args.include_path, with_children=bool(args.with_children)
            )
        elif args.cmd == "extract":
            data = {"model": parse_xml(args.xml)}
        elif args.cmd == "filter":
            data = get_full_datamodel_elements(
                args.xml, element_type=args.element_type, path=args.path, value=args.value,
                regex=bool(args.regex), with_children=bool(args.with_children), depth_limit=args.depth_limit
            )
        elif args.cmd == "min-datamodel":
            data = get_min_datamodel_elements(
                args.xml, element_type=args.element_type, path=args.path, name=args.name, elem_id=args.elem_id,
                show_children=bool(args.show_children), depth_limit=args.depth_limit
            )
        elif args.cmd == "full-datamodel":
            data = get_full_datamodel_elements(
                args.xml, element_type=args.element_type, path=args.path, value=args.value,
                regex=bool(args.regex), with_children=bool(args.with_children), depth_limit=args.depth_limit
            )
        elif args.cmd == "check-xsd":
            data = check_xml_xds(args.xml, args.schemas_dir)
        elif args.cmd == "fix-datamodel":
            data = fix_elements_from_template_xsd(args.xml, args.datamodel, args.schemas_dir)
        elif args.cmd == "generate-xml":
            data = generate_xml_from_template(args.xml, args.datamodel, args.out_file, schemas_dir=args.schemas_dir)
        else:
            print("[ERRO] Comando inválido.", file=sys.stderr)
            return 1
    except Exception as e:
        print(f"[ERRO] {e}", file=sys.stderr)
        return 2

    dump = to_yaml(data)
    if getattr(args, "out", "-") in ("-", "stdout", None):
        print(dump)
    else:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(dump, encoding="utf-8")
        print(f"[OK] YAML salvo em: {args.out}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
