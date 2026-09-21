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
node is the same effective route. References to removed nodes are rewritten
to the node that was kept, so Mihomo proxy groups/rules cannot point at a
nonexistent proxy.
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

    # Compare nodes for which a successful egress-IP observation exists.
    # ip_test.py records status="success" but does not set ip_stable=True.
    # Requiring ip_stable here would silently disable all IP grouping.
    by_ip = defaultdict(list)
    for node in nodes:
        if node["egress_ip"]:
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

    # Build a replacement map before removing nodes. Mihomo proxy-groups can
    # contain concrete proxy names, so deleting a proxy without rewriting
    # those references produces an invalid config.
    replacements = {}
    for decision in decisions:
        if decision.get("action") == "remove":
            replacements[decision["name"]] = decision["keep"]

    def resolve_replacement(name):
        # A -> B -> C can happen when several nodes in one IP group are
        # removed in sequence. Always resolve to the final surviving node.
        seen = set()
        while name in replacements and name not in seen:
            seen.add(name)
            name = replacements[name]
        return name

    def rewrite_refs(value):
        if isinstance(value, str):
            return resolve_replacement(value)
        if isinstance(value, list):
            return [rewrite_refs(item) for item in value]
        if isinstance(value, dict):
            out = {}
            for k, v in value.items():
                # A proxy/group's own name is metadata, not a reference.
                out[k] = v if k == "name" else rewrite_refs(v)
            return out
        return value

    data = rewrite_refs(data)

    # Safety net: never publish a config containing a proxy-group/rule
    # reference to a removed proxy. If a reference survived the rewrite for
    # any reason, restore that proxy instead of producing a broken config.
    original_proxies = {
        proxy.get("name"): proxy
        for proxy in data["proxies"]
        if isinstance(proxy, dict) and isinstance(proxy.get("name"), str)
    }
    surviving_names = set(original_proxies)
    referenced_names = set()

    def collect_refs(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "proxies" and isinstance(item, list):
                    for name in item:
                        if isinstance(name, str):
                            referenced_names.add(name)
                elif key == "rules" and isinstance(item, list):
                    for rule in item:
                        if isinstance(rule, str):
                            parts = rule.split(",")
                            if parts:
                                target = parts[-1].strip()
                                if target in surviving_names:
                                    referenced_names.add(target)
                else:
                    collect_refs(item)
        elif isinstance(value, list):
            for item in value:
                collect_refs(item)

    collect_refs(data.get("proxy-groups", []))
    collect_refs(data.get("rules", []))

    # Map removed proxy names to their original proxy definitions. If any
    # reference still points at one, cancel that deletion.
    restored = set()
    for name in referenced_names:
        if name in replacements and name not in surviving_names:
            # The reference should normally already have been rewritten.
            # Keeping the original node is safer than publishing a broken
            # configuration if a non-standard structure escaped rewriting.
            for node in nodes:
                if node["name"] == name:
                    remove.discard(node["index"])
                    restored.add(name)
                    break

    if restored:
        # Re-run the rewrite after restoring protected nodes; references to
        # nodes that are actually removed must always point to a survivor.
        protected_replacements = {
            old: new for old, new in replacements.items() if old not in restored
        }
        replacements = protected_replacements
        data = rewrite_refs(data)

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
            "replacements": replacements,
            "rewritten_references": len(replacements),
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
    print(f"Rewritten proxy references    : {len(replacements)}")
    print(f"Minimum evidence score        : {args.min_score}")
    print(f"Output                        : {args.output}")
    print(f"Report                        : {args.report}")
    print("======================================")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
