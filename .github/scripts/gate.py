#!/usr/bin/env python3
"""
Gate voor de CodeQL-bevindingen.

Het Security-tabblad van GitHub laat de pipeline NIET falen. Daarom lezen we de
SARIF zelf in en beslissen we hier.

Wat is kritiek? (onze eigen keuze, zie het verslag)
  - CodeQL-bevindingen met security-severity >= 7.0  (dat is High of Critical), OF
  - een security-regel met niveau "error".

Wat is de baseline?
  Alles wat de eerste run op de ONGEWIJZIGDE starter-app vond, is bewust aanvaard
  en staat in security/codeql-baseline.json (regel-id + bestand). Die laten we door.
  Een nieuwe kritieke bevinding die daar niet in staat, laat de pipeline falen.

Gebruik:  python3 gate.py <results.sarif> <baseline.json>
"""
import json
import sys

CRITICAL_SECURITY_SEVERITY = 7.0


def load_rules(run):
    rules = {}
    driver = run.get("tool", {}).get("driver", {})
    for comp in [driver] + run.get("tool", {}).get("extensions", []):
        for rule in comp.get("rules", []):
            rules[rule["id"]] = rule
    return rules


def is_critical(result, rules):
    rule = rules.get(result.get("ruleId"), {})
    props = rule.get("properties", {})
    sev = props.get("security-severity")
    if sev is not None:
        # Heeft de regel een security-severity, dan geeft die de doorslag:
        # >= 7.0 is CodeQL High/Critical en telt voor ons als kritiek.
        try:
            return float(sev) >= CRITICAL_SECURITY_SEVERITY
        except ValueError:
            return False
    # Geen security-severity bekend? Dan valt een security-regel met niveau
    # "error" terug op kritiek (voorzichtige kant).
    level = result.get("level") or rule.get("defaultConfiguration", {}).get("level")
    tags = props.get("tags", [])
    return level == "error" and "security" in tags


def fingerprint(result):
    loc = result["locations"][0]["physicalLocation"]
    uri = loc["artifactLocation"]["uri"]
    line = loc.get("region", {}).get("startLine", 0)
    return f'{result.get("ruleId")}@{uri}:{line}'


def main():
    sarif_path, baseline_path = sys.argv[1], sys.argv[2]

    with open(sarif_path, encoding="utf-8") as f:
        sarif = json.load(f)
    try:
        with open(baseline_path, encoding="utf-8") as f:
            baseline = set(json.load(f).get("accepted", []))
    except FileNotFoundError:
        baseline = set()

    new_critical = []
    for run in sarif.get("runs", []):
        rules = load_rules(run)
        for result in run.get("results", []):
            if not is_critical(result, rules):
                continue
            fp = fingerprint(result)
            if fp not in baseline:
                new_critical.append(fp)

    if new_critical:
        print("PIPELINE FAALT - nieuwe kritieke SAST-bevinding(en):")
        for fp in new_critical:
            print(f"  - {fp}")
        print("\nLos ze op, of voeg ze bewust toe aan de baseline met een reden "
              "in het verslag.")
        sys.exit(1)

    print("Geen nieuwe kritieke SAST-bevindingen. Baseline ongewijzigd doorgelaten.")


if __name__ == "__main__":
    main()
