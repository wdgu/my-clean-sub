#!/usr/bin/env python3
import concurrent.futures
import json
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

import yaml

INPUT = Path("clash_fixed.yaml")
RESULTS = Path("test_results.json")
MIHOMO = "./mihomo"
WORKERS = 16
BASE_API = 9100
BASE_MIXED = 7900
IP_URL = "https://api.ipify.org"
TEST_URL = "https://www.gstatic.com/generate_204"


def api_request(api, path, method="GET", body=None, timeout=30):
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = Request(api + path, data=data, headers=headers, method=method)
    with urlopen(req, timeout=timeout) as r:
        raw = r.read()
        return json.loads(raw.decode()) if raw else None


def wait_api(api):
    for _ in range(30):
        try:
            api_request(api, "/version", timeout=2)
            return
        except Exception:
            time.sleep(1)
    raise RuntimeError("Mihomo external controller did not become ready")


def worker(worker_id, proxies):
    api_port = BASE_API + worker_id
    mixed_port = BASE_MIXED + worker_id
    api = f"http://127.0.0.1:{api_port}"
    group = f"__IP_TEST_{worker_id}__"
    config_path = Path(f"ip_test_config_{worker_id}.yaml")
    log_path = Path(f"ip_test_{worker_id}.log")

    cfg = {
        "mixed-port": mixed_port,
        "allow-lan": False,
        "external-controller": f"127.0.0.1:{api_port}",
        "mode": "rule",
        "proxies": proxies,
        "proxy-groups": [{
            "name": group,
            "type": "select",
            "proxies": [p["name"] for p in proxies],
        }],
        "rules": [f"MATCH,{group}"],
    }

    with config_path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False, width=4096)

    log = log_path.open("w", encoding="utf-8")
    proc = subprocess.Popen(
        [MIHOMO, "-f", str(config_path), "-d", "."],
        stdout=log, stderr=subprocess.STDOUT,
    )

    try:
        wait_api(api)

        # One lightweight reachability pass. The duplicate decision itself is
        # made later from the observed egress IP and node configuration.
        delay_by_name = {}
        path = "/group/" + quote(group, safe="") + "/delay?" + urlencode({
            "url": TEST_URL,
            "timeout": 4000,
            "expected": 204,
        })
        try:
            result = api_request(api, path, timeout=120)
            if isinstance(result, dict):
                for name, delay in result.items():
                    try:
                        delay = int(delay)
                    except (TypeError, ValueError):
                        continue
                    if 0 < delay < 65535:
                        delay_by_name[name] = delay
        except Exception as exc:
            print(f"[worker {worker_id}] health check failed: {exc}")

        results = []
        for index, proxy in enumerate(proxies, 1):
            name = proxy["name"]
            record = {
                "name": name,
                "server": proxy.get("server", ""),
                "port": proxy.get("port", ""),
                "type": proxy.get("type", ""),
                "delay_ms": delay_by_name.get(name, 65535),
                "egress_ip": "",
                "egress_ips": [],
                "ip_stable": False,
                "status": "unreachable",
                "worker": worker_id,
            }

            if name not in delay_by_name:
                results.append(record)
                continue

            try:
                api_request(
                    api,
                    "/proxies/" + quote(group, safe=""),
                    method="PUT",
                    body={"name": name},
                    timeout=5,
                )
                p = subprocess.run(
                    [
                        "curl", "-4", "-fsS",
                        "--proxy", f"http://127.0.0.1:{mixed_port}",
                        "--max-time", "6",
                        IP_URL,
                    ],
                    capture_output=True, text=True, timeout=8,
                )
                if p.returncode == 0 and p.stdout.strip():
                    ip = p.stdout.strip()
                    record["egress_ip"] = ip
                    record["egress_ips"] = [ip]
                    record["status"] = "success"
            except Exception as exc:
                record["error"] = str(exc)

            results.append(record)
            print(
                f"[worker {worker_id}] {index}/{len(proxies)} "
                f"{name}: {record['status']} ip={record['egress_ip'] or '-'} "
                f"delay={record['delay_ms']}ms",
                flush=True,
            )

        return results

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        log.close()


def main():
    with INPUT.open(encoding="utf-8") as f:
        data = yaml.safe_load(f)

    proxies = data.get("proxies") if isinstance(data, dict) else None
    if not isinstance(proxies, list) or not proxies:
        raise RuntimeError("clash_fixed.yaml has no proxies")

    proxies = [
        p for p in proxies
        if isinstance(p, dict) and isinstance(p.get("name"), str)
    ]

    chunks = [[] for _ in range(min(WORKERS, len(proxies)))]
    for i, proxy in enumerate(proxies):
        chunks[i % len(chunks)].append(proxy)

    print(f"Total proxies: {len(proxies)}")
    print(f"Parallel Mihomo workers: {len(chunks)}")

    all_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(chunks)) as pool:
        futures = [
            pool.submit(worker, i, chunk)
            for i, chunk in enumerate(chunks)
        ]
        for future in concurrent.futures.as_completed(futures):
            all_results.extend(future.result())

    # Restore source order for deterministic reports.
    order = {p["name"]: i for i, p in enumerate(proxies)}
    all_results.sort(key=lambda r: order.get(r["name"], 10**9))

    # First observation is deliberately not marked stable. dedup_by_ip.py will
    # perform a second observation only for IP-collision groups.
    RESULTS.write_text(
        json.dumps({"results": all_results}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    success = sum(1 for r in all_results if r["status"] == "success")
    print(f"Successful egress IP observations: {success}/{len(all_results)}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"[FATAL] {exc}")
        sys.exit(1)
