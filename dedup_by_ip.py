#!/usr/bin/env python3
"""
Conservative local duplicate-node reducer.

This script is intentionally NOT part of the GitHub Actions cleaner.
Run it after local Mihomo testing on the target device, where egress IP
observations are meaningful.

Inputs:
  clash_fixed.yaml
  test_results.json

Expected result records can use either:
  {"name": "...", "egress_ip": "...", ...}
or
  {"proxy": "...", "ip": "...", ...}

The script only removes a node when there is strong evidence that another
node is the same effective route:
  - same observed egress IP
  - same server + port
  - same protocol/type
  - same transport/security fingerprint when available

Same egress IP alone is NEVER enough to delete a node.
Same server/port alone is NEVER enough to delete a node.

Outputs:
  clash_dedup.yaml
  dedup_report.json
"""

import argparse
import json
import sys
from collections import defaultdict

import yaml


def norm(value):
    if value is None:
        return ""
    return str(value).strip().lower()


def result_name(record):
    for key in ("name", "proxy", "proxy_name", "node", "node_name"):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def result_ip(record):
    for key in ("egress_ip", "exit_ip", "public_ip", "ip", "external_ip"):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def result_success(record):
    for key in ("status", "result"):
        value = record.get(key)
        if isinstance(value, str):
            return norm(value) in {"good", "ok", "success", "alive", "pass", "passed"}
    for key in ("success", "alive", "reachable"):
        if key in record:
            return bool(record[key])
    return True


def fingerprint(proxy):
    # Fields which describe the effective route rather than cosmetic metadata.
    keys = (
        "type", "server", "port", "uuid", "cipher", "password",
        "network", "tls", "servername", "sni", "flow", "client-fingerprint",
        "fingerprint", "reality-opts", "ws-opts", "grpc-opts", "xhttp-opts",
        "obfs", "obfs-password", "up", "down", "auth", "auth-str",
        "alpn", "skip-cert-verify", "socks5", "plugin", "plugin-opts",
    )
    data = {}
    for key in keys:
        if key in proxy:
            value = proxy[key]
            if isinstance(value, dict):
                value = {k: value[k] for k in sorted(value)}
            data[key] = value
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def candidate_score(a, b):
    score = 0
    reasons = []

    if a["egress_ip"] and a["egress_ip"] == b["egress_ip"]:
        score += 4
        reasons.append("same observed egress IP")

    if a["server"] and a["server"] == b["server"]:
        score += 3
        reasons.append("same server")

    if a["port"] and a["port"] == b["port"]:
        score += 1
        reasons.append("same port")

    if a["type"] and a["type"] == b["type"]:
        score += 1
        reasons.append("same protocol")

    if a["fingerprint"] == b["fingerprint"]:
        score += 6
        reasons.append("same effective configuration")

    return score, reasons


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="clash_fixed.yaml")
    ap.add_argument("--results", default="test_results.json")
    ap.add_argument("--output", default="clash_dedup.yaml")
    ap.add_argument("--report", default="dedup_report.json")
    ap.add_argument(
        "--min-score",
        type=int,
        default=8,
        help="minimum evidence score required to remove a possible duplicate",
    )
    args = ap.parse_args()

    try:
        with open(args.config, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        with open(args.results, encoding="utf-8") as f:
            results = json.load(f)
    except Exception as exc:
        print(f"[FATAL] failed to read input: {exc}")
        return 1

    if not isinstance(data, dict) or not isinstance(data.get("proxies"), list):
        print("[FATAL] config has no proxies list")
        return 1

    if isinstance(results, dict):
        for key in ("results", "proxies", "nodes", "tests"):
            if isinstance(results.get(key), list):
                results = results[key]
                break

    if not isinstance(results, list):
        print("[FATAL] test_results.json must contain a list of result records")
        return 1

    observed = {}
    for record in results:
        if not isinstance(record, dict):
            continue
        name = result_name(record)
        if not name or not result_success(record):
            continue
        ip = result_ip(record)
        if not ip:
            continue
        observed[name] = {
            "egress_ip": ip,
            "server": norm(record.get("server")),
            "port": norm(record.get("port")),
            "type": norm(record.get("type")),
        }

    nodes = []
    for index, proxy in enumerate(data["proxies"]):
        if not isinstance(proxy, dict):
            continue
        name = proxy.get("name")
        if not isinstance(name, str):
            continue
        info = observed.get(name, {})
        nodes.append({
            "index": index,
            "name": name,
            "egress_ip": info.get("egress_ip", ""),
            "server": info.get("server") or norm(proxy.get("server")),
            "port": info.get("port") or norm(proxy.get("port")),
            "type": info.get("type") or norm(proxy.get("type")),
            "fingerprint": fingerprint(proxy),
        })

    # Only compare nodes for which a successful egress-IP observation exists.
    by_ip = defaultdict(list)
    for node in nodes:
        if node["egress_ip"] and node.get("ip_stable") is True:
            by_ip[node["egress_ip"]].append(node)

    remove = set()
    decisions = []

    for ip, group in by_ip.items():
        if len(group) < 2:
            continue

        # Deterministic order: preserve the first node in the source config.
        group.sort(key=lambda n: n["index"])

        for i in range(1, len(group)):
            current = group[i]
            best = None

            for j in range(i):
                other = group[j]
                if other["name"] in remove:
                    continue
                score, reasons = candidate_score(current, other)
                if best is None or score > best[0]:
                    best = (score, other, reasons)

            if best is None:
                continue

            score, keep, reasons = best
            if score < args.min_score:
                decisions.append({
                    "action": "keep",
                    "name": current["name"],
                    "matched": keep["name"],
                    "egress_ip": ip,
                    "score": score,
                    "reasons": reasons,
                    "why": "same IP is not sufficient evidence",
                })
                continue

            remove.add(current["index"])
            decisions.append({
                "action": "remove",
                "name": current["name"],
                "keep": keep["name"],
                "egress_ip": ip,
                "score": score,
                "reasons": reasons,
            })

    output_proxies = [
        proxy for index, proxy in enumerate(data["proxies"])
        if index not in remove
    ]
    data["proxies"] = output_proxies

    try:
        with open(args.output, "w", encoding="utf-8", newline="\n") as f:
            yaml.safe_dump(
                data,
                f,
                allow_unicode=True,
                sort_keys=False,
                default_flow_style=False,
                width=4096,
            )
        report = {
            "source_proxies": len(nodes),
            "successful_egress_ip_observations": len(observed),
            "observed_ip_groups_with_multiple_nodes": sum(
                1 for group in by_ip.values() if len(group) > 1
            ),
            "removed_proxies": len(remove),
            "min_score": args.min_score,
            "decisions": decisions,
            "output": args.output,
            "note": (
                "Same egress IP alone never causes deletion. "
                "Deletion requires combined evidence."
            ),
        }
        with open(args.report, "w", encoding="utf-8", newline="\n") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
            f.write("\n")
    except Exception as exc:
        print(f"[FATAL] failed to write output: {exc}")
        return 1

    print("========== IP DEDUP SUMMARY ==========")
    print(f"Input proxies                 : {len(data['proxies']) + len(remove)}")
    print(f"Successful IP observations    : {len(observed)}")
    print(f"IP groups with multiple nodes : {sum(1 for g in by_ip.values() if len(g) > 1)}")
    print(f"Removed possible duplicates   : {len(remove)}")
    print(f"Output proxies                : {len(output_proxies)}")
    print(f"Minimum evidence score        : {args.min_score}")
    print(f"Output                        : {args.output}")
    print(f"Report                        : {args.report}")
    print("======================================")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
