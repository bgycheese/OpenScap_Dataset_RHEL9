# `ssg-rhel9-ds.xml` — SCAP Source Data Stream (RHEL 9)

## Overview

This file is a **SCAP Source Data Stream** published by the
[SCAP Security Guide](https://github.com/ComplianceAsCode/content) project.
It contains the authoritative, machine-readable security-compliance content for
**Red Hat Enterprise Linux 9**: 1467 hardening rules, organized into 19 named
compliance profiles (CIS, DISA STIG, ANSSI, HIPAA, PCI-DSS, etc.), along with
the automated tests that verify each rule.

It is the **source of truth** from which `profiles.json` and `policies.json` in
this dataset were extracted.

## File facts

| Attribute            | Value                                                          |
|----------------------|----------------------------------------------------------------|
| Filename             | `ssg-rhel9-ds.xml`                                             |
| Size                 | ~24.8 MB                                                       |
| Format               | SCAP 1.3 Source Data Stream (XML)                              |
| Benchmark ID         | `xccdf_org.ssgproject.content_benchmark_RHEL-9`                |
| Benchmark title      | Guide to the Secure Configuration of Red Hat Enterprise Linux 9|
| Benchmark version    | 0.1.73                                                         |
| Upstream project     | SCAP Security Guide / ComplianceAsCode                         |
| Upstream license     | BSD-3-Clause                                                   |
| Target platform      | Red Hat Enterprise Linux 9                                     |

## What is SCAP?

**SCAP** (Security Content Automation Protocol) is a suite of interoperable
open standards maintained by NIST. It defines how to express security policy,
configuration checks, and results in machine-readable form so that scanners
from different vendors can consume the same content.

A **Source Data Stream** is SCAP's "bundle" format: a single XML file that
packages several sub-documents together. This file contains four such
sub-documents, each conforming to its own standard:

| Sub-standard | Purpose                                              | Maintained by |
|--------------|------------------------------------------------------|---------------|
| **XCCDF** 1.2 | The human-oriented checklist: profiles, rules, fixes | NIST          |
| **OVAL** 5   | The machine-oriented tests that verify each rule     | MITRE / CIS   |
| **OCIL** 2.0 | Human-answered questionnaires for rules that can't be automated | NIST |
| **CPE** 2.0  | Platform identification (so the content knows it's running on RHEL 9) | NIST |

You don't need to understand all four to use the extracted JSON. But if you
ever need to regenerate the JSON, trace a rule to its test logic, or debug a
scanner result, this is the map.

## Internal structure

At the top level the file is a `<ds:data-stream-collection>` with two kinds of
children:

1. **One `<ds:data-stream>`** — the manifest. It lists which component
   documents make up this stream and how they reference each other.
2. **Several `<ds:component>`** elements — the actual payloads:
   - `ssg-rhel9-xccdf.xml` — the XCCDF Benchmark (what the JSON is extracted from)
   - `ssg-rhel9-oval.xml` — OVAL definitions (the automated tests)
   - `ssg-rhel9-ocil.xml` — OCIL questionnaires
   - `ssg-rhel9-cpe-dictionary.xml` + `ssg-rhel9-cpe-oval.xml` — platform detection

```
<ds:data-stream-collection>
├── <ds:data-stream>                    ← table of contents
│   ├── <ds:dictionaries>               ← points to CPE component
│   ├── <ds:checklists>                 ← points to XCCDF component
│   └── <ds:checks>                     ← points to OVAL + OCIL components
└── <ds:component> × N                  ← the actual payloads
    ├── cpe-list                        (CPE dictionary)
    ├── Benchmark                       (XCCDF — contains Profiles, Rules, Groups, Values)
    ├── oval_definitions                (OVAL — contains definitions, tests, objects, states)
    └── ocil                            (OCIL — questionnaires)
```

### The XCCDF Benchmark in detail

The `<xccdf:Benchmark>` element is the part that matters most for this dataset.
It contains:

| Child type         | Count | Meaning                                                           |
|--------------------|------:|-------------------------------------------------------------------|
| `<Profile>`        |    19 | Named compliance standards (CIS, STIG, ANSSI, …)                  |
| `<Rule>`           |  1467 | Individual security rules                                         |
| `<Group>`          |   179 | Topic-based categorization of rules (e.g. "accounts", "services") |
| `<Value>`          |   441 | Tunable parameters (e.g. minimum password length)                 |

Each `<Profile>` contains a flat list of `<xccdf:select idref="…" selected="true"/>`
elements — these are the references that become the `selected_rules` array in
`profiles.json`. It may also contain `<xccdf:refine-value>` elements that
override the default `<Value>`s — these become `refine_values` in the JSON.

Each `<Rule>` carries its title, description, rationale, severity, a list of
`<xccdf:reference>` entries (pointers into frameworks like NIST 800-53), and a
`<xccdf:check>` that links to the OVAL definition that actually tests it.

## The 19 profiles

| Short ID                    | Title                                                                        |
|-----------------------------|------------------------------------------------------------------------------|
| `anssi_bp28_minimal`        | ANSSI-BP-028 (minimal)                                                       |
| `anssi_bp28_intermediary`   | ANSSI-BP-028 (intermediary)                                                  |
| `anssi_bp28_enhanced`       | ANSSI-BP-028 (enhanced)                                                      |
| `anssi_bp28_high`           | ANSSI-BP-028 (high)                                                          |
| `ccn_basic`                 | CCN-STIC for RHEL 9 — Basic                                                  |
| `ccn_intermediate`          | CCN-STIC for RHEL 9 — Intermediate                                           |
| `ccn_advanced`              | CCN-STIC for RHEL 9 — Advanced                                               |
| `cis_server_l1`             | CIS RHEL 9 Benchmark, Level 1, Server                                        |
| `cis`                       | CIS RHEL 9 Benchmark, Level 2, Server                                        |
| `cis_workstation_l1`        | CIS RHEL 9 Benchmark, Level 1, Workstation                                   |
| `cis_workstation_l2`        | CIS RHEL 9 Benchmark, Level 2, Workstation                                   |
| `cui`                       | NIST 800-171 (Controlled Unclassified Information) — DRAFT                   |
| `e8`                        | ACSC Essential Eight (Australia)                                             |
| `hipaa`                     | Health Insurance Portability and Accountability Act                          |
| `ism_o`                     | ACSC ISM Official (Australia)                                                |
| `ospp`                      | Protection Profile for General Purpose Operating Systems                     |
| `pci-dss`                   | PCI-DSS v4.0 Control Baseline for RHEL 9                                     |
| `stig`                      | DISA STIG for RHEL 9                                                         |
| `stig_gui`                  | DISA STIG for RHEL 9 with GUI                                                |

(Full IDs are prefixed with `xccdf_org.ssgproject.content_profile_`.)

## Relationship to the JSON files

`profiles.json` and `policies.json` are a **projection** of this XML —
extracted, flattened, and denormalized for ease of use:

| Source element in XML                    | Destination in JSON                       |
|------------------------------------------|-------------------------------------------|
| `<xccdf:Profile>` (×19)                  | A record in `profiles.json`               |
| `<xccdf:Profile>/<xccdf:title>`          | `profile.title`                           |
| `<xccdf:Profile>/<xccdf:description>`    | `profile.description`                     |
| `<xccdf:select idref="…" selected="true"/>` | an entry in `profile.selected_rules`   |
| `<xccdf:refine-value>`                   | `profile.refine_values`                   |
| `<xccdf:Rule>` (×1467)                   | A record in `policies.json`               |
| `<xccdf:Rule>/@severity`                 | `policy.severity`                         |
| `<xccdf:Rule>/<xccdf:title>`             | `policy.title`                            |
| `<xccdf:Rule>/<xccdf:description>`       | `policy.description`                      |
| `<xccdf:Rule>/<xccdf:rationale>`         | `policy.rationale`                        |
| Parent `<xccdf:Group>`s of a Rule        | `policy.groups`                           |
| The inverse of `profile.selected_rules`  | `policy.profiles` (reverse index)         |

**Verified**: Profile count and Rule count in the XML exactly match the record
counts in the JSON files (19 and 1467). No rules or profiles were dropped
during extraction.

What is **not** extracted into the JSON (but lives in this XML if you need it):

- The **OVAL tests** — the actual runnable compliance checks.
- The **OCIL questionnaires** — manual-verification questions.
- **Remediations** (`<xccdf:fix>`): Bash/Ansible/Kubernetes snippets that
  automatically fix each violation. There are ~3,059 of these, on average
  roughly two per rule.
- **Cross-references** (`<xccdf:reference>`): mappings from each rule to
  external frameworks (NIST 800-53, CCE, CJIS, etc.). ~41,248 references in total.
- **Values** (`<xccdf:Value>`): the default values for tunable parameters.
- **Groups**: rules are only referenced by group ID in the JSON; the group
  metadata (title, description, hierarchy) is in the XML.

## Provenance

- **Upstream repository**: <https://github.com/ComplianceAsCode/content>
- **Project name**: SCAP Security Guide (SSG), also known as ComplianceAsCode
- **Build**: Generated by the SSG build system from YAML rule definitions in
  the upstream repository. Each release is tagged and published as SCAP
  content bundled with the `scap-security-guide` RPM on RHEL.
- **Standards authority**: NIST (SCAP, XCCDF, OVAL, OCIL, CPE)
- **Typical update cadence**: Roughly aligned with RHEL minor releases and
  upstream compliance-framework updates (weeks to months).

## Intended use

- **Compliance scanning**: Consumed by tools like `oscap` (the OpenSCAP
  command-line scanner) to evaluate a live RHEL 9 system against any of the 19
  profiles.
- **Automated remediation**: Fed to `oscap xccdf generate fix` or to Ansible
  via the bundled fix content to bring systems into compliance.
- **Compliance reporting**: Consumed by SCAP Workbench, Red Hat Insights,
  Foreman/Satellite, and other compliance dashboards.
- **Regeneration of this dataset's JSON**: Re-running the extraction against a
  newer version of this XML will produce an updated `profiles.json` /
  `policies.json`.

## Caveats & gotchas

1. **Size and parser choice.** At 24.8 MB with 143,056 elements, naive DOM
   parsing is fine on a developer laptop but wasteful in a service. Prefer
   streaming (`lxml.etree.iterparse` or `xml.sax`) when you only need a
   subset.

2. **Namespaces everywhere.** Every meaningful element is in a namespace. If
   your XPath returns nothing, you've almost certainly forgotten the namespace
   prefix. Common ones: `xccdf-1.2`, `oval-def`, `ocil`, `cpe-dict`.

3. **`selected="false"` exists.** An `<xccdf:Profile>` can also contain
   `<xccdf:select idref="…" selected="false"/>` to *deselect* a rule. The JSON
   only captures `selected="true"` in `selected_rules`. If you regenerate the
   JSON, preserve this filter.

4. **Profile inheritance (`extends`).** Some profiles `extends` another. The
   XCCDF spec says the child inherits the parent's selections unless
   overridden. The JSON is **already flattened**, i.e. effective selections;
   the XML still shows the inheritance relationship in the `extends` attribute.

5. **Rule severity can be `"unknown"`.** 51 of 1467 rules have severity
   `unknown` in the JSON — this comes directly from rules in the XML that
   don't declare a `severity` attribute. Don't silently drop them.

6. **Rules with zero profiles.** The XML catalog contains rules that no
   current profile selects. In the JSON these appear with `"profiles": []`.
   They're valid catalog entries, not bugs.

7. **Text fields contain XHTML.** `<description>` and `<rationale>` can
   contain inline XHTML (`<html:p>`, `<html:code>`, `<html:pre>`). The JSON
   extraction normalizes these to plain text; if you need the rich formatting,
   go back to the XML.

## Further reading

- SCAP 1.3 specification: NIST SP 800-126 Rev. 3
- XCCDF 1.2 specification: NIST IR 7275 Rev. 4
- OVAL language reference: <https://oval.mitre.org/>
- OCIL: NIST IR 7692
- CPE 2.3: NIST IR 7695 / 7696 / 7697 / 7698
- SCAP Security Guide upstream: <https://github.com/ComplianceAsCode/content>
- OpenSCAP scanner: <https://www.open-scap.org/>
