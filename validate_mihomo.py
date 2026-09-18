import re
import subprocess
import sys
from pathlib import Path
import yaml

CONFIG = Path(sys.argv[1] if len(sys.argv) > 1 else "clash_fixed.yaml")
MIHOMO = Path(sys.argv[2] if len(sys.argv) > 2 else "./mihomo")
MAX_REPAIRS = 500
PROXY_ERROR = re.compile(r"proxy\s+(\d+)\s*:\s*(.+)", re.IGNORECASE)

def run_test():
    p = subprocess.run(
        [str(MIHOMO), "-t", "-f", str(CONFIG)],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=90,
    )
    return p.returncode, p.stdout

def load_config():
    with CONFIG.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict) or not isinstance(data.get("proxies"), list):
        raise ValueError("config has no proxies list")
    return data

def save_config(data):
    tmp = CONFIG.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8", newline="\n") as f:
        yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False,
                       default_flow_style=False, width=4096)
    tmp.replace(CONFIG)

def main():
    if not CONFIG.exists() or not MIHOMO.exists():
        print("[FATAL] validation input missing")
        return 1
    data = load_config()
    dropped = []

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
