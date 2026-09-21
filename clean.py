import json
import re
import sys
import hashlib
from urllib.parse import unquote, urlsplit

import yaml

SOURCE_FILE = "source.yaml"
OUTPUT_FILE = "clash_fixed.yaml"
REPORT_FILE = "clean_report.json"

CONTROL_PATTERN = re.compile(
    r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]"
)
HEX_PATTERN = re.compile(r"^[0-9a-fA-F]+$")
HOST_PATTERN = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9_\-.:\[\]]+$")

BUILTIN_POLICIES = {
    "DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE",
    "BLOCK", "GLOBAL", "SYSTEM"
}

KNOWN_NETWORKS = {
    "tcp", "udp", "ws", "grpc", "h2", "http", "xhttp",
    "httpupgrade", "splithttp", "quic"
}

DROP_LIMIT = 0.50
# Duplicate configurations are expected cleanup and do not count toward the
# corruption-safety threshold. Only genuinely invalid nodes are protected by it.

IDENTITY_IGNORED_FIELDS = {
    "name", "icon", "udp", "tfo", "mptcp", "smux",
    "interface-name", "routing-mark", "ip-version",
}


def canonicalize(value):
    if isinstance(value, dict):
        return {
            k: canonicalize(v)
            for k, v in sorted(value.items())
            if k not in IDENTITY_IGNORED_FIELDS
        }
    if isinstance(value, list):
        return [canonicalize(v) for v in value]
    if isinstance(value, str):
        return value.strip()
    return value


def node_fingerprint(proxy):
    identity = canonicalize(proxy)
    raw = json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def sanitize_text(text):
    return CONTROL_PATTERN.sub("", text)


def sanitize_value(value):
    if isinstance(value, str):
        return sanitize_text(value)
    if isinstance(value, dict):
        return {k: sanitize_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize_value(v) for v in value]
    return value


def valid_port(value):
    try:
        return 1 <= int(value) <= 65535
    except (TypeError, ValueError):
        return False


def valid_server(value):
    if not isinstance(value, str):
        return False
    value = value.strip()
    return bool(value) and not any(ch.isspace() for ch in value)


def clean_sni(value, fallback):
    if not isinstance(value, str):
        value = ""

    value = sanitize_text(value).strip()
    if value:
        value = unquote(value)

        if "://" in value:
            try:
                parsed = urlsplit(value)
                value = parsed.hostname or ""
            except ValueError:
                value = ""

        if "/" in value or "?" in value or "#" in value:
            value = value.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]

    if value and HOST_PATTERN.fullmatch(value):
        return value.rstrip(".")

    if isinstance(fallback, str):
        fallback = fallback.strip()
        if fallback and not any(ch.isspace() for ch in fallback):
            if HOST_PATTERN.fullmatch(fallback):
                return fallback.rstrip(".")

    return None


def validate_reality(proxy):
    reality = proxy.get("reality-opts")
    if not isinstance(reality, dict):
        return None, "REALITY reality-opts missing"

    reality = sanitize_value(reality)

    public_key = reality.get("public-key")
    if not isinstance(public_key, str) or not public_key.strip():
        return None, "REALITY public-key missing"

    public_key = public_key.strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]+", public_key):
        return None, "REALITY public-key malformed"

    short_id = reality.get("short-id")

    if short_id is None:
        return None, "invalid REALITY short ID: missing"

    if not isinstance(short_id, str):
        return None, "invalid REALITY short ID: non-string"

    short_id = short_id.strip()
    if short_id.lower() in {"", "null", "none", "nil", "undefined"}:
        return None, "invalid REALITY short ID: empty/null"

    if not HEX_PATTERN.fullmatch(short_id):
        return None, f"invalid REALITY short ID: {short_id!r}"

    if len(short_id) % 2 != 0 or not 2 <= len(short_id) <= 16:
        return None, f"invalid REALITY short ID length: {len(short_id)}"

    reality["public-key"] = public_key
    reality["short-id"] = short_id.lower()
    proxy["reality-opts"] = reality
    proxy["tls"] = True

    return proxy, ""


def normalize_transport(proxy):
    network = proxy.get("network")
    if not isinstance(network, str):
        return proxy, ""

    network = sanitize_text(network).strip().lower()
    if not network:
        proxy.pop("network", None)
        return proxy, ""

    if network == "raw":
        network = "tcp"

    if network not in KNOWN_NETWORKS:
        return None, f"invalid network: {network!r}"

    proxy["network"] = network

    if network == "ws":
        ws_opts = proxy.get("ws-opts")
        if not isinstance(ws_opts, dict):
            ws_opts = {}
        ws_opts = sanitize_value(ws_opts)

        path = ws_opts.get("path")
        if not isinstance(path, str) or not path.strip():
            ws_opts["path"] = "/"
        else:
            ws_opts["path"] = path.strip()

        proxy["ws-opts"] = ws_opts

    if network == "grpc":
        grpc_opts = proxy.get("grpc-opts")
        if not isinstance(grpc_opts, dict):
            grpc_opts = {}
        grpc_opts = sanitize_value(grpc_opts)

        if not grpc_opts.get("serviceName") and grpc_opts.get("grpc-service-name"):
            grpc_opts["serviceName"] = grpc_opts["grpc-service-name"]

        service_name = grpc_opts.get("serviceName")
        if not isinstance(service_name, str) or not service_name.strip():
            return None, "grpc network missing grpc-opts.serviceName"

        grpc_opts["serviceName"] = service_name.strip()
        proxy["grpc-opts"] = grpc_opts

    return proxy, ""


def normalize_sni(proxy):
    server = proxy.get("server", "")
    sni = proxy.get("sni")
    servername = proxy.get("servername")

    cleaned_servername = clean_sni(servername, server)
    cleaned_sni = clean_sni(sni, cleaned_servername or server)
    chosen = cleaned_servername or cleaned_sni

    if chosen:
        if servername is not None:
            proxy["servername"] = chosen
        if sni is not None:
            proxy["sni"] = chosen
    else:
        proxy.pop("sni", None)
        proxy.pop("servername", None)

    return proxy


def normalize_proxy(proxy, index):
    if not isinstance(proxy, dict):
        return None, "proxy is not a mapping"

    proxy = sanitize_value(proxy)

    name = proxy.get("name")
    if not isinstance(name, str) or not name.strip():
        name = f"proxy-{index}"
    proxy["name"] = name.strip()

    tp = proxy.get("type")
    if not isinstance(tp, str) or not tp.strip():
        return None, "missing type"
    proxy["type"] = tp.strip().lower()

    server = proxy.get("server")
    if not valid_server(server):
        return None, "missing/invalid server"
    proxy["server"] = server.strip()

    if not valid_port(proxy.get("port")):
        return None, "invalid port"
    proxy["port"] = int(proxy["port"])

    tp = proxy["type"]

    if tp in {"vless", "vmess"}:
        if not isinstance(proxy.get("uuid"), str) or not proxy["uuid"].strip():
            return None, f"{tp} uuid missing"
        proxy["uuid"] = proxy["uuid"].strip()

    if tp == "trojan":
        if not isinstance(proxy.get("password"), str) or not proxy["password"]:
            return None, "trojan password missing"

    if tp in {"ss", "ssr"}:
        if not isinstance(proxy.get("cipher"), str) or not proxy["cipher"]:
            return None, f"{tp} cipher missing"
        if not isinstance(proxy.get("password"), str) or not proxy["password"]:
            return None, f"{tp} password missing"

    if tp == "hysteria2":
        if not isinstance(proxy.get("password"), str) or not proxy["password"]:
            return None, "hysteria2 password missing"

    proxy, reason = normalize_transport(proxy)
    if proxy is None:
        return None, reason

    proxy = normalize_sni(proxy)

    if tp == "vless" and "reality-opts" in proxy:
        proxy, reason = validate_reality(proxy)
        if proxy is None:
            return None, reason

    if tp == "vless" and proxy.get("network") == "xhttp":
        xhttp = proxy.get("xhttp-opts")
        if xhttp is not None and not isinstance(xhttp, dict):
            return None, "xhttp-opts is not a mapping"

    return proxy, ""


def clean_proxy_groups(data, proxy_names):
    groups = data.get("proxy-groups")
    if not isinstance(groups, list):
        return 0

    group_names = {
        g.get("name")
        for g in groups
        if isinstance(g, dict) and isinstance(g.get("name"), str)
    }

    allowed = set(proxy_names) | group_names | BUILTIN_POLICIES
    new_groups = []
    dropped = 0

    for group in groups:
        if not isinstance(group, dict):
            dropped += 1
            continue

        group = sanitize_value(group)
        name = group.get("name")
        if not isinstance(name, str) or not name.strip():
            dropped += 1
            continue

        refs = group.get("proxies")
        if isinstance(refs, list):
            group["proxies"] = [
                ref for ref in refs
                if isinstance(ref, str) and ref in allowed
            ]
            if not group["proxies"]:
                dropped += 1
                continue

        new_groups.append(group)

    data["proxy-groups"] = new_groups
    return dropped


def clean_rules(data, valid_targets):
    rules = data.get("rules")
    if not isinstance(rules, list):
        return 0

    cleaned = []
    dropped = 0

    for rule in rules:
        if not isinstance(rule, str):
            dropped += 1
            continue

        rule = sanitize_text(rule).strip()
        if not rule:
            dropped += 1
            continue

        parts = rule.split(",")
        if len(parts) >= 2:
            target = parts[-1].strip()
            if target and target not in valid_targets and target not in BUILTIN_POLICIES:
                dropped += 1
                continue

        cleaned.append(rule)

    data["rules"] = cleaned
    return dropped


def main():
    try:
        with open(SOURCE_FILE, "rb") as f:
            raw_bytes = f.read()

        raw_text = raw_bytes.decode("utf-8", errors="replace")
        sanitized_text = sanitize_text(raw_text)
        data = yaml.safe_load(sanitized_text)
    except Exception as e:
        print(f"[FATAL] source YAML parse failed: {e}")
        sys.exit(1)

    if not isinstance(data, dict):
        print("[FATAL] source YAML root is not a mapping")
        sys.exit(1)

    proxies = data.get("proxies")
    if not isinstance(proxies, list):
        print("[FATAL] source YAML has no proxies list")
        sys.exit(1)

    fixed = []
    dropped = []
    duplicate_groups = {}
    fingerprints = {}
    names = set()

    for index, proxy in enumerate(proxies, 1):
        normalized, reason = normalize_proxy(proxy, index)

        if normalized is None:
            name = (
                proxy.get("name", f"proxy-{index}")
                if isinstance(proxy, dict)
                else f"proxy-{index}"
            )
            dropped.append((index, name, reason))
            print(f"[DROP] proxy {index}: {name}: {reason}")
            continue

        name = normalized["name"]
        fingerprint = node_fingerprint(normalized)
        if fingerprint in fingerprints:
            first_name = fingerprints[fingerprint]["name"]
            duplicate_groups.setdefault(fingerprint, [first_name]).append(name)
            dropped.append((index, name, f"duplicate node configuration; same as {first_name}"))
            print(f"[DROP] proxy {index}: {name}: duplicate node configuration; same as {first_name}")
            continue

        fingerprints[fingerprint] = {
            "name": name,
            "server": normalized.get("server"),
            "port": normalized.get("port"),
            "type": normalized.get("type"),
        }

        if name in names:
            dropped.append((index, name, "duplicate proxy name"))
            print(f"[DROP] proxy {index}: {name}: duplicate proxy name")
            continue

        names.add(name)
        fixed.append(normalized)

    if not fixed:
        print("[FATAL] no valid proxies remain")
        sys.exit(1)

    duplicate_drops = sum(
        1 for _, _, reason in dropped
        if reason.startswith("duplicate node configuration")
        or reason == "duplicate proxy name"
    )
    invalid_drops = len(dropped) - duplicate_drops
    invalid_drop_ratio = invalid_drops / len(proxies)

    if invalid_drop_ratio > DROP_LIMIT:
        print(
            f"[FATAL] {invalid_drops}/{len(proxies)} genuinely invalid proxies "
            f"dropped ({invalid_drop_ratio:.1%}); refusing to publish"
        )
        print(
            f"[INFO] Duplicate cleanup excluded from safety threshold: "
            f"{duplicate_drops} nodes"
        )
        sys.exit(1)

    data["proxies"] = fixed

    group_dropped = clean_proxy_groups(data, names)

    group_names = {
        g.get("name")
        for g in data.get("proxy-groups", [])
        if isinstance(g, dict) and isinstance(g.get("name"), str)
    }
    rule_targets = names | group_names
    rule_dropped = clean_rules(data, rule_targets)

    try:
        with open(OUTPUT_FILE, "w", encoding="utf-8", newline="\n") as f:
            yaml.safe_dump(
                data,
                f,
                allow_unicode=True,
                sort_keys=False,
                default_flow_style=False,
                width=4096,
            )

        with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
            final_data = yaml.safe_load(f)

        if not isinstance(final_data, dict):
            raise ValueError("output root is not a mapping")
        if not isinstance(final_data.get("proxies"), list):
            raise ValueError("output proxies is not a list")
        if not final_data["proxies"]:
            raise ValueError("output proxies is empty")

        with open(OUTPUT_FILE, "rb") as f:
            final_text = f.read().decode("utf-8", errors="replace")
        if CONTROL_PATTERN.search(final_text):
            raise ValueError("output still contains YAML control bytes")

    except Exception as e:
        print(f"[FATAL] output validation failed: {e}")
        sys.exit(1)

    print("")
    print("========== CLEAN SUMMARY ==========")
    print(f"Source proxies       : {len(proxies)}")
    print(f"Valid proxies        : {len(fixed)}")
    print(f"Dropped proxies      : {len(dropped)}")
    print(f"Duplicate drops      : {duplicate_drops}")
    print(f"Invalid drops        : {invalid_drops}")
    print(f"Invalid drop ratio   : {invalid_drop_ratio:.1%}")
    print(f"Removed proxy groups : {group_dropped}")
    print(f"Removed rules        : {rule_dropped}")
    report = {
        "source_proxies": len(proxies),
        "valid_proxies": len(fixed),
        "dropped_proxies": len(dropped),
        "duplicate_drops": duplicate_drops,
        "invalid_drops": invalid_drops,
        "invalid_drop_ratio": invalid_drop_ratio,
        "duplicate_node_groups": list(duplicate_groups.values()),
        "duplicate_node_group_count": len(duplicate_groups),
        "removed_proxy_groups": group_dropped,
        "removed_rules": rule_dropped,
        "output": OUTPUT_FILE,
    }
    with open(REPORT_FILE, "w", encoding="utf-8", newline="\n") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
        f.write("\n")

    print(f"Duplicate node groups : {len(duplicate_groups)}")
    print(f"Report                : {REPORT_FILE}")
    print(f"Output                : {OUTPUT_FILE}")
    print("====================================")


if __name__ == "__main__":
    main()
