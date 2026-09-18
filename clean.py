import yaml
import re
import sys

SOURCE_FILE = "source.yaml"
OUTPUT_FILE = "clash_fixed.yaml"

C1_CTRL_PATTERN = re.compile(r'[\x80-\x9F]')
HEX_PATTERN = re.compile(r'^[0-9a-fA-F]+$')

# Mihomo/Clash 常见 proxy 类型
VALID_TYPES = {
    "vless", "vmess", "trojan", "ss", "ssr",
    "socks5", "http", "hysteria", "hysteria2", "tuic",
    "wireguard", "snell"
}

VALID_NETWORK = {"tcp", "ws", "grpc", "http", "h2", "httpupgrade", "splithttp"}

def sanitize_string(s):
    return C1_CTRL_PATTERN.sub("", s)

def sanitize_value(value):
    if isinstance(value, str):
        return sanitize_string(value)
    if isinstance(value, dict):
        return {k: sanitize_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize_value(v) for v in value]
    return value

def is_valid_port(port):
    try:
        port = int(port)
        return 1 <= port <= 65535
    except (TypeError, ValueError):
        return False

def is_valid_reality(proxy):
    """
    REALITY 节点不尝试猜测/生成 short-id。
    参数不合法就丢弃整个节点，避免 FLClash 在加载配置时失败。
    """
    reality = proxy.get("reality-opts")
    if not isinstance(reality, dict):
        return False, "reality-opts missing"

    public_key = reality.get("public-key")
    if not isinstance(public_key, str) or not public_key.strip():
        return False, "REALITY public-key missing"

    short_id = reality.get("short-id")

    # 有些订阅会使用空 short-id；对 FLClash/Mihomo 兼容性优先，直接丢弃
    if not isinstance(short_id, str) or not short_id:
        return False, "invalid REALITY short ID: empty"

    short_id = short_id.strip()

    # short-id 必须是十六进制字符串
    if not HEX_PATTERN.fullmatch(short_id):
        return False, f"invalid REALITY short ID: {short_id!r}"

    # REALITY short-id 应为偶数个十六进制字符，且不超过 16 个字符
    if len(short_id) % 2 != 0 or len(short_id) > 16:
        return False, f"invalid REALITY short ID length: {len(short_id)}"

    # 标准 short-id 至少应包含一个字节
    if len(short_id) < 2:
        return False, "invalid REALITY short ID: too short"

    reality["short-id"] = short_id
    reality["public-key"] = public_key.strip()
    return True, ""

def validate_proxy(proxy, index):
    if not isinstance(proxy, dict):
        return None, "proxy is not an object"

    proxy = sanitize_value(proxy)

    name = proxy.get("name", f"proxy-{index}")
    tp = str(proxy.get("type", "")).lower()

    if tp not in VALID_TYPES:
        return None, f"unsupported/invalid type: {tp!r}"

    server = proxy.get("server")
    if not isinstance(server, str) or not server.strip():
        return None, "server missing"

    if not is_valid_port(proxy.get("port")):
        return None, "invalid port"

    proxy["server"] = server.strip()

    # network 有值时必须合法；不再强行把未知值改成 tcp。
    net = proxy.get("network")
    if net is not None:
        if not isinstance(net, str) or net.lower() not in VALID_NETWORK:
            return None, f"invalid network: {net!r}"
        proxy["network"] = net.lower()

    # 不再把可疑 SNI 强制清空；明显非法才丢弃节点。
    for key in ("sni", "servername"):
        value = proxy.get(key)
        if value is not None:
            if not isinstance(value, str):
                return None, f"invalid {key}"
            value = value.strip()
            if not value or value.startswith(("http://", "https://")) or "%" in value:
                return None, f"invalid {key}: {value!r}"
            proxy[key] = value

    # VLESS 必须有 UUID
    if tp == "vless":
        uuid = proxy.get("uuid")
        if not isinstance(uuid, str) or not uuid.strip():
            return None, "VLESS uuid missing"

        # VLESS + REALITY 专项检查
        reality = proxy.get("reality-opts")
        if reality is not None:
            ok, reason = is_valid_reality(proxy)
            if not ok:
                return None, reason

    # VMess / Trojan / SS 等基础必要字段
    if tp == "vmess":
        uuid = proxy.get("uuid")
        if not isinstance(uuid, str) or not uuid.strip():
            return None, "VMess uuid missing"

    if tp == "trojan":
        password = proxy.get("password")
        if not isinstance(password, str) or not password:
            return None, "Trojan password missing"

    if tp in ("ss", "ssr"):
        if not isinstance(proxy.get("cipher"), str) or not proxy.get("cipher"):
            return None, "cipher missing"
        if not isinstance(proxy.get("password"), str) or not proxy.get("password"):
            return None, "password missing"

    if tp == "hysteria2":
        if not isinstance(proxy.get("password"), str) or not proxy.get("password"):
            return None, "Hysteria2 password missing"

    return proxy, ""

def main():
    try:
        with open(SOURCE_FILE, "r", encoding="utf-8") as f:
            raw_data = yaml.safe_load(f)
    except Exception as e:
        print(f"[FATAL] source YAML parse failed: {e}")
        sys.exit(1)

    if not isinstance(raw_data, dict):
        print("[FATAL] source YAML root is not an object")
        sys.exit(1)

    proxies = raw_data.get("proxies")
    if not isinstance(proxies, list):
        print("[FATAL] proxies is missing or not a list")
        sys.exit(1)

    fixed_proxies = []
    dropped = []

    for index, proxy in enumerate(proxies, 1):
        fixed, reason = validate_proxy(proxy, index)
        if fixed is None:
            name = proxy.get("name", f"proxy-{index}") if isinstance(proxy, dict) else f"proxy-{index}"
            dropped.append((index, name, reason))
            print(f"[DROP] proxy {index}: {name}: {reason}")
        else:
            fixed_proxies.append(fixed)

    if not fixed_proxies:
        print("[FATAL] all proxies were rejected; refusing to overwrite output")
        sys.exit(1)

    # 上游异常保护：如果超过 80% 节点被清除，拒绝生成/提交新配置。
    drop_ratio = len(dropped) / len(proxies) if proxies else 1
    if proxies and drop_ratio > 0.80:
        print(
            f"[FATAL] too many proxies dropped: "
            f"{len(dropped)}/{len(proxies)} ({drop_ratio:.1%}); "
            "refusing to generate output"
        )
        sys.exit(1)

    raw_data["proxies"] = fixed_proxies

    # 写入后立即重新解析，作为第二道 YAML 结构检查。
    try:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            yaml.safe_dump(
                raw_data,
                f,
                allow_unicode=True,
                sort_keys=False,
                default_flow_style=False
            )

        with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
            final_data = yaml.safe_load(f)

        if not isinstance(final_data, dict) or not isinstance(final_data.get("proxies"), list):
            raise ValueError("output YAML structure invalid")

    except Exception as e:
        print(f"[FATAL] output validation failed: {e}")
        sys.exit(1)

    print("")
    print("========== CLEAN SUMMARY ==========")
    print(f"Source proxies : {len(proxies)}")
    print(f"Valid proxies  : {len(fixed_proxies)}")
    print(f"Dropped proxies: {len(dropped)}")
    print(f"Output         : {OUTPUT_FILE}")
    print("====================================")

if __name__ == "__main__":
    main()
