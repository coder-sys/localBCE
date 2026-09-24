#!/usr/bin/env python3
"""Parse bounded MSBuild project evidence without DTD or external-entity support."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
import xml.etree.ElementTree as ElementTree


MAX_PROJECT_BYTES = 4 * 1024 * 1024
MSBUILD_NAMESPACE = "http://schemas.microsoft.com/developer/msbuild/2003"
RELEASE_CONDITION = "'$(Configuration)|$(Platform)'=='Release|x64'"
SUPPORTED_CONFIGURATION_CONDITIONS = (
    "'$(Configuration)|$(Platform)'=='Debug|x64'",
    RELEASE_CONDITION,
    "'$(Configuration)|$(Platform)'=='MinSizeRel|x64'",
    "'$(Configuration)|$(Platform)'=='RelWithDebInfo|x64'",
)


def local_name(tag: object) -> str:
    if not isinstance(tag, str):
        return ""
    return tag.rsplit("}", 1)[-1]


def qualified_tag(name: str) -> str:
    return f"{{{MSBUILD_NAMESPACE}}}{name}"


def exact_release_condition(element: ElementTree.Element) -> bool:
    return element.get("Condition") == RELEASE_CONDITION


def named_children(element: ElementTree.Element, name: str) -> list[ElementTree.Element]:
    tag = qualified_tag(name)
    return [child for child in list(element) if child.tag == tag]


def element_text(
    element: ElementTree.Element,
    label: str,
    allowed_attributes: set[str] | frozenset[str] = frozenset(),
) -> str:
    unexpected_attributes = set(element.attrib) - set(allowed_attributes)
    if unexpected_attributes:
        raise ValueError(
            f"{label} has unsupported attributes: {sorted(unexpected_attributes)}"
        )
    if list(element):
        raise ValueError(f"{label} must be a scalar XML node without nested payload")
    value = element.text or ""
    value = value.strip()
    if not value:
        raise ValueError(f"{label} is empty")
    return value


def scalar_children(
    element: ElementTree.Element, name: str, label: str
) -> list[ElementTree.Element]:
    direct = named_children(element, name)
    direct_ids = {id(child) for child in direct}
    nested = [
        child
        for child in element.iter()
        if child.tag == qualified_tag(name) and id(child) not in direct_ids
    ]
    if nested:
        raise ValueError(f"{label} must be a direct child of its supported parent")
    return direct


def require_attributes(
    element: ElementTree.Element,
    expected: set[str] | frozenset[str],
    label: str,
) -> None:
    actual = set(element.attrib)
    if actual != set(expected):
        raise ValueError(
            f"{label} has unsupported or incomplete attributes: "
            f"expected {sorted(expected)}, found {sorted(actual)}"
        )


def decode_project_bytes(raw: bytes) -> str:
    if len(raw) > MAX_PROJECT_BYTES:
        raise ValueError(
            f"project exceeds bounded XML size {MAX_PROJECT_BYTES} bytes"
        )
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = raw.decode("utf-16")
    else:
        text = raw.decode("utf-8-sig")

    # ElementTree/Expat does not fetch external resources here, and rejecting
    # every DTD/entity declaration makes that boundary explicit rather than
    # relying on parser defaults or accepting an opaque external reference.
    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", text, re.IGNORECASE):
        raise ValueError("DTD or entity declaration is forbidden")
    if re.search(r"<![^>]*\b(?:SYSTEM|PUBLIC)\b", text, re.IGNORECASE):
        raise ValueError("external XML identifier is forbidden")
    return text


def read_project_bytes(path: Path) -> bytes:
    # The read itself is bounded.  A size check after an unbounded read would
    # allocate attacker-controlled project bytes before this parser's limit.
    with path.open("rb") as stream:
        return stream.read(MAX_PROJECT_BYTES + 1)


def parse_project(path: Path) -> ElementTree.Element:
    try:
        text = decode_project_bytes(read_project_bytes(path))
        root = ElementTree.fromstring(text, parser=ElementTree.XMLParser())
    except (OSError, UnicodeError, ElementTree.ParseError, ValueError) as exc:
        raise ValueError(f"unparseable XML project {path}: {exc}") from exc
    if root.tag != qualified_tag("Project"):
        raise ValueError(f"XML root is not Project: {path}")
    for element in root.iter():
        if not isinstance(element.tag, str) or not element.tag.startswith("{"):
            raise ValueError(f"unsupported XML namespace in project {path}")
        namespace, _, _ = element.tag[1:].partition("}")
        if namespace != MSBUILD_NAMESPACE:
            raise ValueError(f"unsupported XML namespace in project {path}")
    return root


def project_references(root: ElementTree.Element) -> tuple[list[str], list[str]]:
    references: list[str] = []
    reference_names: list[str] = []
    direct_edges: list[ElementTree.Element] = []
    item_definition_defaults: list[ElementTree.Element] = []
    for item_group in named_children(root, "ItemGroup"):
        for element in list(item_group):
            if element.tag != qualified_tag("ProjectReference"):
                continue
            require_attributes(element, {"Include"}, "ProjectReference edge")
            include = (element.get("Include") or "").strip()
            if not include:
                raise ValueError("direct ProjectReference edge has an empty Include")
            direct_edges.append(element)
    for item_definition_group in named_children(root, "ItemDefinitionGroup"):
        for element in list(item_definition_group):
            if element.tag != qualified_tag("ProjectReference"):
                continue
            require_attributes(element, set(), "ItemDefinitionGroup ProjectReference default")
            item_definition_defaults.append(element)

    allowed_ids = {id(element) for element in direct_edges}
    allowed_ids.update(id(element) for element in item_definition_defaults)
    for element in root.iter():
        if element.tag != qualified_tag("ProjectReference"):
            continue
        if id(element) not in allowed_ids:
            raise ValueError(
                "ProjectReference must be a direct child of a top-level ItemGroup "
                "or ItemDefinitionGroup default"
            )

    for element in direct_edges:
        include = (element.get("Include") or "").strip()
        if include in references:
            raise ValueError(f"duplicate ProjectReference Include {include}")
        references.append(include)
        name_elements = scalar_children(element, "Name", "ProjectReference Name")
        if len(name_elements) > 1:
            raise ValueError("ProjectReference contains duplicate Name nodes")
        if name_elements:
            reference_names.append(element_text(name_elements[0], "ProjectReference Name"))
    return references, reference_names


def release_evidence(root: ElementTree.Element) -> tuple[str, str]:
    configuration_groups = [
        element
        for element in root.iter()
        if element.tag == qualified_tag("PropertyGroup")
        and element.get("Label") == "Configuration"
    ]
    for group in configuration_groups:
        require_attributes(group, {"Condition", "Label"}, "Configuration PropertyGroup")
        if group.get("Condition") not in SUPPORTED_CONFIGURATION_CONDITIONS:
            raise ValueError("Configuration PropertyGroup has an unsupported condition")
    direct_configuration_groups = [
        child
        for child in list(root)
        if child.tag == qualified_tag("PropertyGroup")
        and child.get("Label") == "Configuration"
    ]
    if len(configuration_groups) != len(direct_configuration_groups):
        raise ValueError("Configuration PropertyGroup must be a direct Project child")
    release_configuration_groups = [
        element for element in direct_configuration_groups if exact_release_condition(element)
    ]
    if len(release_configuration_groups) != 1:
        raise ValueError(
            "expected exactly one Release|x64 Configuration PropertyGroup, "
            f"found {len(release_configuration_groups)}"
        )
    configuration_group = release_configuration_groups[0]
    configuration_type = scalar_children(
        configuration_group, "ConfigurationType", "Release ConfigurationType"
    )
    if len(configuration_type) != 1 or element_text(
        configuration_type[0], "Release ConfigurationType"
    ) != "Application":
        raise ValueError("Release ConfigurationType is absent, duplicated, or not Application")
    platform_toolset = scalar_children(
        configuration_group, "PlatformToolset", "Release PlatformToolset"
    )
    if len(platform_toolset) != 1:
        raise ValueError("Release PlatformToolset is absent or duplicated")
    element_text(platform_toolset[0], "Release PlatformToolset")

    int_dirs = [
        element
        for element in root.iter()
        if element.tag == qualified_tag("IntDir")
    ]
    int_dir_groups = [
        child
        for child in list(root)
        if child.tag == qualified_tag("PropertyGroup")
        and named_children(child, "IntDir")
    ]
    if len(int_dir_groups) != 1:
        if int_dirs:
            raise ValueError("IntDir must be a direct child of one top-level PropertyGroup")
        raise ValueError(
            "expected one top-level PropertyGroup containing the configuration IntDir nodes"
        )
    int_dir_group = int_dir_groups[0]
    require_attributes(int_dir_group, set(), "IntDir PropertyGroup")
    direct_int_dirs = named_children(int_dir_group, "IntDir")
    if len(int_dirs) != len(direct_int_dirs):
        raise ValueError("IntDir must be a direct child of the top-level PropertyGroup")
    seen_int_dir_conditions: set[str] = set()
    for int_dir_element in direct_int_dirs:
        require_attributes(int_dir_element, {"Condition"}, "IntDir")
        condition = int_dir_element.get("Condition")
        if condition not in SUPPORTED_CONFIGURATION_CONDITIONS:
            raise ValueError("IntDir has an unsupported condition")
        if condition in seen_int_dir_conditions:
            raise ValueError("IntDir has duplicate configuration conditions")
        seen_int_dir_conditions.add(condition)
        element_text(int_dir_element, "IntDir", {"Condition"})
    release_int_dirs = [
        element for element in direct_int_dirs if exact_release_condition(element)
    ]
    if len(release_int_dirs) != 1:
        raise ValueError(
            f"expected exactly one Release|x64 IntDir, found {len(release_int_dirs)}"
        )
    int_dir = element_text(release_int_dirs[0], "Release IntDir", {"Condition"})

    item_definition_groups = [
        element
        for element in root.iter()
        if element.tag == qualified_tag("ItemDefinitionGroup")
    ]
    direct_item_definition_groups = [
        child for child in list(root) if child.tag == qualified_tag("ItemDefinitionGroup")
    ]
    if len(item_definition_groups) != len(direct_item_definition_groups):
        raise ValueError("ItemDefinitionGroup must be a direct Project child")
    seen_item_definition_conditions: set[str] = set()
    for item_definition_group in direct_item_definition_groups:
        require_attributes(item_definition_group, {"Condition"}, "ItemDefinitionGroup")
        condition = item_definition_group.get("Condition")
        if condition not in SUPPORTED_CONFIGURATION_CONDITIONS:
            raise ValueError("ItemDefinitionGroup has an unsupported condition")
        if condition in seen_item_definition_conditions:
            raise ValueError("ItemDefinitionGroup has duplicate configuration conditions")
        seen_item_definition_conditions.add(condition)
    release_item_definition_groups = [
        element
        for element in direct_item_definition_groups
        if exact_release_condition(element)
    ]
    if len(release_item_definition_groups) != 1:
        raise ValueError(
            "expected exactly one Release|x64 ItemDefinitionGroup, "
            f"found {len(release_item_definition_groups)}"
        )
    link_nodes = scalar_children(
        release_item_definition_groups[0], "Link", "Release Link"
    )
    if len(link_nodes) != 1:
        raise ValueError(
            f"expected exactly one Release Link node, found {len(link_nodes)}"
        )
    require_attributes(link_nodes[0], set(), "Release Link")
    dependency_nodes = scalar_children(
        link_nodes[0], "AdditionalDependencies", "Release AdditionalDependencies"
    )
    if len(dependency_nodes) != 1:
        raise ValueError(
            "expected exactly one Release AdditionalDependencies node, "
            f"found {len(dependency_nodes)}"
        )
    dependencies = element_text(
        dependency_nodes[0], "Release AdditionalDependencies"
    )
    return dependencies, int_dir


def emit(path: Path, require_release: bool) -> int:
    root = parse_project(path)
    dependencies = ""
    int_dir = ""
    if require_release:
        dependencies, int_dir = release_evidence(root)
    references, reference_names = project_references(root)
    project_names = [
        element_text(element, "ProjectName")
        for element in root.iter()
        if element.tag == qualified_tag("ProjectName")
    ]
    result: dict[str, object] = {
        "project_names": project_names,
        "references": references,
        "reference_names": reference_names,
        "release_dependencies": "",
        "release_int_dir": "",
    }
    if require_release:
        result["release_dependencies"] = dependencies
        result["release_int_dir"] = int_dir
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
    return 0


def main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[2] not in {"--references", "--release"}:
        print(
            "usage: verify_real_symbols_xml.py PROJECT (--references|--release)",
            file=sys.stderr,
        )
        return 2
    path = Path(argv[1])
    if not path.is_file():
        print(f"missing or non-file XML project {path}", file=sys.stderr)
        return 2
    try:
        return emit(path, argv[2] == "--release")
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
