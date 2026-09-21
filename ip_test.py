#!/usr/bin/env python3
import json
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

import yaml

INPUT = Path("clash_fixed.yaml")
TEST_CONFIG = Path("ip_test_config.yaml")
RESULTS = Path("test_results.json")
MIHOMO = "./mihomo"
API = "http://127.0.0.1:9090"
MIXED_PORT = 7892
TEST_GROUP = "__IP_TEST__"
TEST_URLS = [
    ("https://www.gstatic.com/generate_204", 204),
    ("https://cp.cloudflare.com/generate_204", 204),
]
IP_URL = "https://api.ipify.org"


def api_request(path, method="GET", body=None, timeout=30):
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = Request(API + path, data=data, headers=headers, method=method)
    with urlopen(req, timeout=timeout) as r:
        raw = r.read()
        return json.loads(raw.decode()) if raw else None


def wait_api():
    for _ in range(60):
        try:
            api_request("/version", timeout=2)
            return
        except Exception:
            time.sleep(1)
    raise RuntimeError("Mihomo external controller did not become ready")


def build_test_config(data):
    cfg = dict(data)
    cfg["mixed-port"] = MIXED_PORT
    cfg["allow-lan"] = False
    cfg["external-controller"] = "127.0.0.1:9090"
    cfg["secret"] = ""
    cfg["mode"] = "rule"
    cfg["rules"] = [f"MATCH,{TEST_GROUP}"]

    groups = cfg.get("proxy-groups")
    if not isinstance(groups, list):
        groups = []

    groups = [
        g for g in groups
        if isinstance(g, dict) and g.get("name") != TEST_GROUP
    ]

    names = [
        p.get("name") for p in cfg["proxies"]
        if isinstance(p, dict) and isinstance(p.get("name"), str)
    ]
    groups.append({
        "name": TEST_GROUP,
        "type": "select",
        "proxies": names,
        "hidden": True,
    })
    cfg["proxy-groups"] = groups

    # Prevent the test instance from modifying the repository's main config.
    cfg.pop("external-ui", None)
    cfg.pop("external-ui-url", None)
    cfg.pop("tun", None)
    cfg.pop("listeners", None)

    with TEST_CONFIG.open("w", encoding="utf-8") as f:
        yaml.safe_dump(
            cfg, f, allow_unicode=True, sort_keys=False,
            default_flow_style=False, width=4096
        )


def main():
    with INPUT.open(encoding="utf-8") as f:
        data = yaml.safe_load(f)

    proxies = data.get("proxies") if isinstance(data, dict) else None
    if not isinstance(proxies, list) or not proxies:
        raise RuntimeError("clash_fixed.yaml has no proxies")

    build_test_config(data)

    log = open("ip_test.log", "w", encoding="utf-8")
    proc = subprocess.Popen(
        [MIHOMO, "-f", str(TEST_CONFIG), "-d", "."],
        stdout=log, stderr=subprocess.STDOUT,
    )

    try:
        wait_api()

        # Mihomo can health-check all members of a strategy group in one API
        # request. We use two independent 204 endpoints; one success is enough
        # to make a node an IP-testing candidate.
        delay_by_name = {}
        for url, expected in TEST_URLS:
            path = "/group/" + quote(TEST_GROUP, safe="") + "/delay?" + urlencode({
                "url": url,
                "timeout": 5000,
                "expected": expected,
            })
            try:
                result = api_request(path, timeout=180)
                if isinstance(result, dict):
                    for name, delay in result.items():
                        try:
                            delay = int(delay)
                        except (TypeError, ValueError):
                            continue
                        if delay > 0 and delay < 65535:
                            old = delay_by_name.get(name)
                            delay_by_name[name] = delay if old is None else min(old, delay)
            except Exception as exc:
                print(f"[WARN] group health check failed for {url}: {exc}")

        print(f"Total proxies: {len(proxies)}")
        print(f"IP candidates: {len(delay_by_name)}")

        results = []
        by_name = {
            p.get("name"): p for p in proxies
            if isinstance(p, dict) and isinstance(p.get("name"), str)
        }

        for index, name in enumerate(delay_by_name, 1):
            proxy = by_name.get(name)
            if not proxy:
                continue

            record = {
                "name": name,
                "server": proxy.get("server", ""),
                "port": proxy.get("port", ""),
                "type": proxy.get("type", ""),
                "delay_ms": delay_by_name[name],
                "egress_ip": "",
                "status": "ip_failed",
            }

            try:
                # Select this node in the dedicated selector group.
                api_request(
                    "/proxies/" + quote(TEST_GROUP, safe=""),
                    method="PUT",
                    body={"name": name},
                    timeout=10,
                )

                req = Request(IP_URL)
                req.add_header("User-Agent", "mihomo-ip-test/1.0")
                with urlopen(
                    Request(
                        IP_URL,
                        headers={"User-Agent": "mihomo-ip-test/1.0"},
                    ),
                    timeout=8,
                ) as direct:
                    direct_ip = direct.read().decode().strip()

                # The actual proxy request is made by curl so the selected
                # Mihomo mixed port is explicitly used.
                p = subprocess.run(
                    [
                        "curl", "-4", "-fsS",
                        "--proxy", f"http://127.0.0.1:{MIXED_PORT}",
                        "--max-time", "10",
                        IP_URL,
                    ],
                    capture_output=True, text=True, timeout=15,
                )
                if p.returncode == 0:
                    ip = p.stdout.strip()
                    if ip:
                        record["egress_ip"] = ip
                        record["status"] = "success"
                        record["direct_ip"] = direct_ip
            except Exception as exc:
                record["error"] = str(exc)

            results.append(record)
            print(
                f"[{index}/{len(delay_by_name)}] {name}: "
                f"{record['status']} ip={record['egress_ip'] or '-'} "
                f"delay={record['delay_ms']}ms"
            )

        RESULTS.write_text(
            json.dumps(
                {"results": results},
                ensure_ascii=False, indent=2
            ) + "\n",
            encoding="utf-8",
        )

        success = sum(1 for r in results if r["status"] == "success")
        print(f"Successful egress IP tests: {success}/{len(results)}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        log.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"[FATAL] {exc}")
        sys.exit(1)
