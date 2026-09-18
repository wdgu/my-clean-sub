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
BUILTINS = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "BLOCK", "GLOBAL", "SYSTEM"}


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


def prune_references(data):
    names = {p.get("name") for p in data.get("proxies", []) if isinstance(p, dict)}
    groups = data.get("proxy-groups", [])
    if isinstance(groups, list):
        group_names = {g.get("name") for g in groups if isinstance(g, dict)}
        allowed = names | group_names | BUILTINS
        new_groups = []
        for g in groups:
            if not isinstance(g, dict):
                continue
            refs = g.get("proxies")
            if isinstance(refs, list):
                g["proxies"] = [x for x in refs if x in allowed]
                if not g["proxies"]:
                    continue
            new_groups.append(g)
        data["proxy-groups"] = new_groups

        group_names = {g.get("name") for g in new_groups if isinstance(g, dict)}
        allowed = names | group_names | BUILTINS
        rules = data.get("rules")
        if isinstance(rules, list):
            cleaned = []
            for rule in rules:
                if not isinstance(rule, str):
                    continue
                parts = rule.split(",")
                target = parts[-1].strip() if len(parts) >= 2 else ""
                if target and target not in allowed:
                    continue
                cleaned.append(rule)
            data["rules"] = cleaned


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
