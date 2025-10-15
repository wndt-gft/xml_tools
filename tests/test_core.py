from __future__ import annotations

from pathlib import Path
import xml.etree.ElementTree as ET

import pytest
import yaml

from xml_tools import core


DATA_DIR = Path(__file__).parent / "data" / "xml_simple_sample_1"


def load_yaml(relative: str):
    return yaml.safe_load((DATA_DIR / relative).read_text(encoding="utf-8"))


def test_private_helpers_handle_namespaces_and_truncate():
    element = ET.fromstring(
        '<ns:root xmlns:ns="http://example.com/ns"><ns:child attr="1">Value</ns:child></ns:root>'
    )
    generic = core.xml_to_generic(element)
    assert generic["ns"] == "http://example.com/ns"
    assert generic["children"][0]["text"] == "Value"
    assert core._localname(element.tag) == "root"
    assert core._node_ns_uri(element.tag) == "http://example.com/ns"
    assert core._localname("plain") == "plain"
    assert core._node_ns_uri("plain") is None

    long_text = "x" * 210
    truncated = core._truncate(long_text, max_chars=10)
    assert truncated.endswith("…")

    empty = ET.fromstring("<root><wrapper/></root>")
    assert core._first_non_empty_text(empty, ("name",)) is None
    assert core._attr_first(empty, ("id",)) is None


def test_tokenize_path_supports_indices_and_wildcards():
    tokens = core.tokenize_path("children[0].attrs.id")
    assert tokens == ["children", 0, "attrs", "id"]
    tokens = core.tokenize_path("children[*].text")
    assert tokens == ["children", "*", "text"]


def test_get_avail_templates_from_path_lists_metadata():
    result = core.get_avail_templates_from_path(DATA_DIR, pattern="sample_layout*.xml")
    names = [t["template_name"] for t in result["templates"]]
    assert "Sample Catalog" in names
    assert "Another Catalog" in names


def test_get_avail_templates_with_includes():
    result = core.get_avail_templates_from_path(
        DATA_DIR,
        pattern="sample_layout.xml",
        include_level1=True,
        titles_tag="name",
        include_path="children[0]",
        with_children=False,
    )
    entry = result["templates"][0]
    includes = entry["includes"]
    assert includes["level1"][0]["tag"] == "layout"
    assert "titles" in includes and "Layout A" in includes["titles"]
    path_values = includes["by_path"]["values"]
    assert isinstance(path_values[0], dict)
    assert "children" not in path_values[0]


def test_parse_xml_returns_generic_root():
    model = core.parse_xml(DATA_DIR / "sample_layout.xml")
    assert model["tag"] == "catalog"
    assert len(model["children"]) == 3


def test_min_datamodel_matches_expected_snapshot():
    result = core.get_min_datamodel_elements(DATA_DIR / "sample_layout.xml")
    expected = load_yaml("expected/min_datamodel_default.yaml")
    assert result["min_datamodel"] == expected["min_datamodel"]


def test_min_datamodel_filters_by_id_and_name():
    result = core.get_min_datamodel_elements(
        DATA_DIR / "sample_layout.xml",
        element_type="item",
        elem_id="i2",
        name="Item Bar",
        show_children=True,
    )
    assert len(result["min_datamodel"]) == 1
    assert result["min_datamodel"][0]["attrs"]["id"] == "i2"


def test_min_datamodel_filters_by_path():
    result = core.get_min_datamodel_elements(
        DATA_DIR / "sample_layout.xml",
        path="children[*].children[0].text",
        name="Layout A",
        show_children=False,
    )
    assert any(entry["tag"] == "layout" for entry in result["min_datamodel"])


def test_full_datamodel_regex_filters_items():
    result = core.get_full_datamodel_elements(
        DATA_DIR / "sample_layout.xml",
        path="children[*].text",
        value="Item.*",
        regex=True,
    )
    expected = load_yaml("expected/full_regex_items.yaml")
    assert result == expected


def test_full_datamodel_literal_value_filter():
    result = core.get_full_datamodel_elements(
        DATA_DIR / "sample_layout.xml",
        element_type="layout",
        path="children[*].text",
        value="Demo layout",
        regex=False,
    )
    assert len(result["full_datamodel"]) == 1
    assert result["full_datamodel"][0]["tag"] == "layout"


def test_full_datamodel_element_type_with_depth_limit():
    result = core.get_full_datamodel_elements(
        DATA_DIR / "sample_layout.xml",
        element_type="item",
        with_children=False,
        depth_limit=0,
    )
    assert len(result["full_datamodel"]) == 2
    assert "children" not in result["full_datamodel"][0]


def test_fix_elements_from_template_xsd_injects_node(tmp_path: Path):
    datamodel = DATA_DIR / "datamodel_min.yaml"
    template = DATA_DIR / "sample_layout.xml"
    schemas = DATA_DIR / "schemas"
    report = core.fix_elements_from_template_xsd(template, datamodel, schemas)
    assert report["ok"] is True
    assert 'id="i3"' in report["xml"]


def test_generate_xml_from_template_creates_file(tmp_path: Path):
    template = DATA_DIR / "sample_layout.xml"
    datamodel = DATA_DIR / "datamodel_min.yaml"
    schemas = DATA_DIR / "schemas"
    destination = tmp_path / "generated.xml"

    report = core.generate_xml_from_template(template, datamodel, destination, schemas_dir=schemas)
    assert report["ok"] is True
    assert destination.exists()


def test_generate_xml_without_validation(tmp_path: Path):
    template = DATA_DIR / "sample_layout.xml"
    datamodel = DATA_DIR / "datamodel_min.yaml"
    destination = tmp_path / "plain.xml"

    report = core.generate_xml_from_template(template, datamodel, destination, schemas_dir=None)
    assert report["ok"] is True
    assert destination.exists()


def test_generate_xml_with_full_datamodel_branch(tmp_path: Path):
    template = DATA_DIR / "sample_layout.xml"
    destination = tmp_path / "full.xml"
    datamodel_payload = {
        "full_datamodel": {
            "tag": "catalog",
            "children": [
                {"tag": "layout", "attrs": {"id": "L1"}, "children": [{"tag": "description", "text": "Updated"}]}
            ],
        }
    }
    datamodel_text = yaml.safe_dump(datamodel_payload)
    report = core.generate_xml_from_template(
        template,
        datamodel_text,
        destination,
        schemas_dir=None,
    )
    assert report["ok"] is True
    assert "Updated" in destination.read_text(encoding="utf-8")


def test_check_xml_xds_reports_errors_for_invalid_document():
    bad_xml = """
    <catalog xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <layout id="L1">
        <name>Layout A</name>
      </layout>
    </catalog>
    """
    report = core.check_xml_xds(bad_xml, DATA_DIR / "schemas")
    assert report["valid"] is False
    assert report["errors"]


def test_check_xml_xds_supports_path_input():
    report = core.check_xml_xds(DATA_DIR / "sample_layout.xml", DATA_DIR / "schemas")
    assert report["valid"] is True


def test_check_xml_xds_without_schemas(tmp_path: Path):
    empty = tmp_path / "schemas"
    empty.mkdir()
    with pytest.raises(FileNotFoundError):
        core.check_xml_xds(DATA_DIR / "sample_layout.xml", empty)


def test_tokenize_path_raises_for_invalid_index():
    try:
        core.tokenize_path("children[foo]")
    except ValueError as exc:
        assert "invalid index" in str(exc).lower()
    else:  # pragma: no cover
        raise AssertionError("ValueError expected")


def test_apply_datamodel_matches_existing_children():
    root = ET.fromstring("<catalog><item name='Keep'/></catalog>")
    model = {
        "tag": "item",
        "attrs": {"name": "Keep"},
        "children": [{"tag": "documentation", "text": "Doc"}],
    }
    core._apply_datamodel_to_element(root, model)
    child = root.find("item")
    assert child is not None
    assert child.find("documentation").text == "Doc"

    missing = {"tag": "missing"}
    core._apply_datamodel_to_element(root, missing, allow_create=False)
    assert root.find("missing") is None


def test_fix_elements_accepts_root_datamodel(tmp_path: Path):
    datamodel = {
        "tag": "catalog",
        "children": [
            {
                "tag": "layout",
                "attrs": {"id": "L1"},
                "children": [{"tag": "description", "text": "Demo layout"}],
            }
        ],
    }
    datamodel_path = tmp_path / "root_datamodel.yaml"
    datamodel_path.write_text(yaml.safe_dump(datamodel), encoding="utf-8")
    report = core.fix_elements_from_template_xsd(
        DATA_DIR / "sample_layout.xml",
        datamodel_path,
        DATA_DIR / "schemas",
    )
    assert report["ok"] is True


def test_load_yaml_supports_raw_strings():
    data = core._load_yaml("value: 1")
    assert data["value"] == 1


def test_limit_depth_handles_non_list_children():
    pruned = core._limit_depth({"tag": "node", "children": "not-list"}, depth_limit=1)
    assert pruned["tag"] == "node"
