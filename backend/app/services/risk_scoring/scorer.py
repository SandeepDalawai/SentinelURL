from collections import defaultdict
from app.services.detection_rules.rules import WEIGHTS

GROUP_CAPS = {"Structure": 34, "Obfuscation": 38, "Impersonation": 48, "Infrastructure": 28, "Content": 22}
RELIABILITY = {"URL-CREDENTIALS": 1.0, "BRAND-SUBDOMAIN": 1.0, "BRAND-LOOKALIKE": 0.82, "PUNYCODE-HOST": 0.75, "HOST-IP": 0.72, "PERCENT-ENCODING": 0.62, "default": 0.7}


def score(findings: list[dict]) -> tuple[int, str, list[str]]:
    # Deduplicate by stable rule id, then use diminishing returns within categories.
    unique = {item["rule_id"]: item for item in findings}
    groups: dict[str, list[float]] = defaultdict(list)
    reasons = []
    for item in unique.values():
        weight = WEIGHTS.get(item["severity"], 4) * RELIABILITY.get(item["rule_id"], RELIABILITY["default"])
        groups[item["category"]].append(weight)
        reasons.append(f"{item['name']}: {round(weight)} weighted points before category cap")
    total = 0.0
    for category, values in groups.items():
        values.sort(reverse=True)
        subtotal = values[0] + sum(value * (0.45 ** index) for index, value in enumerate(values[1:], start=1))
        contribution = min(GROUP_CAPS.get(category, 24), subtotal)
        total += contribution
        reasons.append(f"{category} signal group: {round(contribution)} points after diminishing returns")
    result = min(100, round(total))
    level = "Low" if result < 25 else "Medium" if result < 50 else "High" if result < 75 else "Critical"
    if not unique:
        reasons.append("No known heuristic indicators detected; this does not guarantee the URL is safe.")
    return result, level, reasons
