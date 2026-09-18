import re
import subprocess
import sys
from pathlib import Path

import yaml

BASE_DIR = Path(__file__).resolve().parent
CONFIG = (BASE_DIR / (sys.argv[1] if len(sys.argv) > 1 else "clash_fixed.yaml")).resolve()
MIHOMO = (BASE_DIR / (sys.argv[2] if len(sys.argv) > 2 else "mihomo")).resolve()
MAX_REPAIRS = 500
PROXY_ERROR = re.compile(r"proxy\s+(\d+)\s*:\s*(.+)", re.IGNORECASE)

BUILTINS = {
    "DIRECT", "REJECT", "REJECT-DROP", "PASS",
    "COMPATIBLE", "BLOCK", "GLOBAL", "SYSTEM",
}

RULE_TARGET_AT_2 = {
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD",
    "DOMAIN-REGEX", "GEOSITE", "GEOIP", "IP-CIDR", "IP-CIDR6",
    "IP-SUFFIX", "IP-ASN", "SRC-GEOIP", "SRC-IP-ASN", "SRC-IP-CIDR",
    "SRC-IP-SUFFIX", "DST-PORT", "SRC-PORT", "IN-PORT", "IN-TYPE",
    "IN-USER", "IN-NAME", "REMATCH-NAME", "PROCESS-PATH",
    "PROCESS-PATH-WILDCARD", "PROCESS-PATH-REGEX", "PROCESS-NAME",
    "PROCESS-NAME-WILDCARD", "PROCESS-NAME-REGEX", "UID", "NETWORK",
    "DSCP", "RULE-SET", "AND", "OR", "NOT", "SUB-RULE",
}
RULE_TARGET_AT_1 = {"MATCH"}

DYNAMIC_GROUP_FIELDS = {
    "include-all",
    "include-all-proxies",
    "include-all-providers",
    "use",
}


def run_test():
    p = subprocess.run(
        [str(MIHOMO), "-t", "-f", str(CONFIG)],
        cwd=str(BASE_DIR),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=90,
    )
    return p.returncode, p.stdout


def load_config():
    with CONFIG.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict) or not isinstance(data.get("proxies"), list):
        raise ValueError("config has no proxies list")
    return data


def split_rule_fields(rule):
    """Split a Mihomo rule on top-level commas only."""
    fields = []
    current = []
    depth = 0
    quote = None
    escaped = False

    for ch in rule:
        if escaped:
            current.append(ch)
            escaped = False
            continue

        if quote is not None:
            current.append(ch)
            if ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            continue

        if ch in ("'", '"'):
            quote = ch
            current.append(ch)
        elif ch == "(":
            depth += 1
            current.append(ch)
        elif ch == ")":
            if depth > 0:
                depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            fields.append("".join(current).strip())
            current = []
        else:
            current.append(ch)

    fields.append("".join(current).strip())
    return fields


def rule_target(rule):
    """Return the routing target without mistaking no-resolve/src for it."""
    if not isinstance(rule, str):
        return None, False

    fields = split_rule_fields(rule)
    if not fields:
        return None, False

    rule_type = fields[0].strip().upper()

    if rule_type in RULE_TARGET_AT_1:
        return (fields[1], True) if len(fields) >= 2 and fields[1] else (None, False)

    if rule_type in RULE_TARGET_AT_2:
        return (fields[2], True) if len(fields) >= 3 and fields[2] else (None, False)

    # Unknown/custom syntax: do not guess; let Mihomo validate it.
    return None, False


def prune_references(data):
    """Remove references to deleted proxies without corrupting valid syntax."""
    proxies = data.get("proxies", [])
    names = {
        p.get("name")
        for p in proxies
        if isinstance(p, dict) and isinstance(p.get("name"), str) and p.get("name")
    }

    groups = data.get("proxy-groups", [])
    if not isinstance(groups, list):
        groups = []

    new_groups = []
    for group in groups:
        if not isinstance(group, dict):
            continue

        refs = group.get("proxies")
        if isinstance(refs, list):
            group["proxies"] = [
                x for x in refs
                if isinstance(x, str) and x in (names | BUILTINS)
            ]

        has_dynamic_members = any(
            bool(group.get(field)) for field in DYNAMIC_GROUP_FIELDS
        )

        if isinstance(refs, list) and not group["proxies"] and not has_dynamic_members:
            continue

        new_groups.append(group)

    changed = True
    while changed:
        changed = False
        current_names = {
            g.get("name")
            for g in new_groups
            if isinstance(g, dict) and isinstance(g.get("name"), str) and g.get("name")
        }
        allowed = names | current_names | BUILTINS

        kept = []
        for group in new_groups:
            refs = group.get("proxies")
            if isinstance(refs, list):
                filtered = [
                    x for x in refs
                    if isinstance(x, str) and x in allowed
                ]
                if filtered != refs:
                    group["proxies"] = filtered
                    changed = True

                has_dynamic_members = any(
                    bool(group.get(field)) for field in DYNAMIC_GROUP_FIELDS
                )
                if not filtered and not has_dynamic_members:
                    changed = True
                    continue

            kept.append(group)

        new_groups = kept

    data["proxy-groups"] = new_groups

    group_names = {
        g.get("name")
        for g in new_groups
        if isinstance(g, dict) and isinstance(g.get("name"), str) and g.get("name")
    }
    allowed = names | group_names | BUILTINS

    rules = data.get("rules")
    if isinstance(rules, list):
        cleaned_rules = []
        for rule in rules:
            if not isinstance(rule, str):
                continue

            target, has_target = rule_target(rule)

            if has_target and target not in allowed:
                continue

            cleaned_rules.append(rule)

        data["rules"] = cleaned_rules

    # dialer-proxy can also reference a proxy or proxy-group.
    for proxy in proxies:
        if not isinstance(proxy, dict):
            continue
        dialer = proxy.get("dialer-proxy")
        if isinstance(dialer, str) and dialer not in allowed:
            proxy.pop("dialer-proxy", None)


def save_config(data):
    prune_references(data)
    tmp = CONFIG.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8", newline="\n") as f:
        yaml.safe_dump(
            data,
            f,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
            width=4096,
        )
    tmp.replace(CONFIG)


def main():
    if not CONFIG.exists() or not MIHOMO.is_file():
        print("[FATAL] validation input missing")
        print(f"[FATAL] config : {CONFIG}")
        print(f"[FATAL] mihomo : {MIHOMO}")
        return 1

    if not MIHOMO.stat().st_mode & 0o111:
        print(f"[FATAL] Mihomo is not executable: {MIHOMO}")
        return 1

    data = load_config()
    dropped = []

    print(f"[INFO] Config : {CONFIG}")
    print(f"[INFO] Mihomo : {MIHOMO}")

    for _ in range(MAX_REPAIRS + 1):
        code, output = run_test()
        if code == 0:
            print(output.rstrip())
            print("========== MIHOMO VALIDATION ==========")
            print(f"Remaining proxies: {len(data['proxies'])}")
            print(f"Removed by core  : {len(dropped)}")
            print("Result            : PASS")
            print("========================================")
            return 0

        print(output.rstrip())
        match = PROXY_ERROR.search(output)
        if not match:
            print("[FATAL] Mihomo rejected config without a proxy index; refusing publish.")
            return 1

        index = int(match.group(1))
        reason = match.group(2).strip()
        if index < 0 or index >= len(data["proxies"]):
            print(f"[FATAL] Mihomo reported proxy {index}, but config has {len(data['proxies'])}.")
            print("[FATAL] This indicates the tested config is not the generated file.")
            return 1

        proxy = data["proxies"][index]
        name = proxy.get("name", f"proxy-{index}")
        print(f"[MIHOMO DROP] proxy {index}: {name}: {reason}")
        dropped.append((index, name, reason))
        del data["proxies"][index]

        if not data["proxies"]:
            print("[FATAL] no proxies remain")
            return 1

        save_config(data)

    print("[FATAL] Mihomo repair limit exceeded")
    return 1


if __name__ == "__main__":
    sys.exit(main())
