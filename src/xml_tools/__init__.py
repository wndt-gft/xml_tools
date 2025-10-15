"""
xml_tools public API.
"""

from .core import (
    GenericNode,
    check_xml_xds,
    extract_template_metadata,
    fix_elements_from_template_xsd,
    generate_xml_from_template,
    get_avail_templates_from_path,
    get_full_datamodel_elements,
    get_min_datamodel_elements,
    get_values_by_path,
    parse_xml,
    tokenize_path,
    xml_to_generic,
)

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
