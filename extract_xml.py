import json
import os
import xml.etree.ElementTree as ET
from xml.etree import ElementTree

# TODO: change the source location to default when downloaded on VHI systems
SOURCE_FILE = "./source/ssg-rhel9-ds.xml"
FILE_PATH = "./output/"

NS = {
    # --- you will query these ---
    'xccdf': 'http://checklists.nist.gov/xccdf/1.2',  # Rules, Profiles, Groups, Values
    'oval': 'http://oval.mitre.org/XMLSchema/oval-definitions-5',  # OVAL definitions
    'ind': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#independent',
    'linux': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#linux',
    'unix': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#unix',
    'ocil': 'http://scap.nist.gov/schema/ocil/2.0',  # Manual checks
    'ds': 'http://scap.nist.gov/schema/scap/source/1.2',  # Wrapper structure
    'cpe': 'http://cpe.mitre.org/dictionary/2.0',  # Platform dict
}

skeleton_structure = {}


def find_rule_path(element, target_rule_id, ns, current_path=None):
    if current_path is None:
        current_path = []

    tag = element.tag.split('}')[-1]

    if tag == "Group":
        current_path = current_path + [element.get('id')]

    if tag == "Rule" and element.get("id") == target_rule_id:
        return current_path

    for child in element:
        result = find_rule_path(child, target_rule_id, ns, current_path)
        if result is not None:
            return result
    return None


def match(policy_id: str) -> list[dict[str, str]]:
    matches = []
    with open("./output/profiles.json", "r") as f:
        profiles = json.load(f)
        for profile in profiles:
            for selected_rules in profile["selected_rules"]:
                if selected_rules == policy_id:
                    matches.append(profile["id"])
    return matches


def main() -> None:
    tree = ET.parse(SOURCE_FILE)
    root = tree.getroot()
    rules_collection = []
    profile_collection = []
    benchmark = (
        root.find(".//xccdf:Benchmark", NS)
        if root is not None
        else ElementTree.Element("xccdf:Benchmark", NS)
    )
    profiles = benchmark.findall(".//xccdf:Profile", NS) if benchmark is not None else []
    for profile_elem in profiles:
        select_rules = []
        refine_values = []

        for select in profile_elem.findall(".//xccdf:select", NS):
            if select.get("selected") == "true":
                select_rules.append(select.get("idref"))
        for rv in profile_elem.findall(".//xccdf:refine-value", NS):
            refine_values.append({"idref": rv.get("idref"), "selector": rv.get("selector")})

        title_elem = profile_elem.find("xccdf:title", NS)
        desc_elem = profile_elem.find("xccdf:description", NS)
        profile_collection.append({
            "id": profile_elem.get("id"),
            "title": title_elem.text if title_elem is not None else "",
            "description": desc_elem.text if desc_elem is not None else "",
            "selected_rules": select_rules,
            "refine_values": refine_values,
        })

    os.makedirs(os.path.dirname(FILE_PATH), exist_ok=True)
    with open("./output/profiles.json", "w") as f:
        json.dump(profile_collection, f, indent=4, ensure_ascii=True)

    rules = benchmark.findall(".//xccdf:Rule", NS) if benchmark is not None else []
    for rule in rules:
        rule_id = rule.get("id") if rule is not None else ""
        severity = rule.get("severity") if rule is not None else ""
        title_elem = rule.find("xccdf:title", NS) if rule is not None else ""
        title_text = title_elem.text if title_elem is not None else ""
        description_elem = rule.find("xccdf:description", NS) if rule is not None else ""
        description = (
            ''.join(description_elem.itertext()).strip()
            if description_elem is not None else ""
        )
        rationale_elem = rule.find("xccdf:rationale", NS) if rule is not None else ""
        rationale = (
            ''.join(rationale_elem.itertext()).strip()
            if rationale_elem is not None else ""
        )
        rules_collection.append({
            "id": rule_id,
            "severity": severity,
            "title": title_text,
            "description": description,
            "rationale": rationale,
            "profiles": match(rule_id),
            "groups": find_rule_path(benchmark, rule_id, NS),
        })

    os.makedirs(FILE_PATH, exist_ok=True)
    with open("./output/policies.json", "w") as f:
        json.dump(rules_collection, f, indent=2, ensure_ascii=True)


if __name__ == '__main__':
    main()
