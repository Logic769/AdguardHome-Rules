#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""统计 AdGuard Home 查询日志中的「实际拦截来源」，输出公开聚合 JSON。

运行在 AGH 所在服务器（root）：
  /root/dsh-scripts/adg-attribution.py

数据源：
  - /opt/adgh/work/data/querylog.json （AGH JSONL 查询日志，仅在本机读取）
  - releases/latest/download/Black-with-sources.txt （域名 -> 上游源映射，缓存 6 小时）

输出：
  /www/wwwroot/www.logic769.xyz/api/adg-attribution.json （只含聚合统计，不含具体查询域名）
"""
import datetime
import json
import os
import tempfile
import urllib.request
from collections import Counter, defaultdict

QUERYLOG = os.environ.get("AGH_QUERYLOG", "/opt/adgh/work/data/querylog.json")
SOURCE_URL = os.environ.get(
    "AGH_SOURCE_URL",
    "https://github.com/Logic769/AdguardHome-Rules/releases/latest/download/Black-with-sources.txt",
)
SOURCE_CACHE = os.environ.get(
    "AGH_SOURCE_CACHE", "/root/dsh-scripts/cache/Black-with-sources.txt"
)
OUT_FILE = os.environ.get(
    "AGH_ATTRIBUTION_OUT",
    "/www/wwwroot/www.logic769.xyz/api/adg-attribution.json",
)
BLACK_FILTER_ID = int(os.environ.get("AGH_BLACK_FILTER_ID", "1775567760"))
WHITE_FILTER_ID = int(os.environ.get("AGH_WHITE_FILTER_ID", "1775567761"))
SOURCE_MAX_AGE = int(os.environ.get("AGH_SOURCE_MAX_AGE", str(6 * 3600)))
DOMAIN_SPACE_LABEL = "域名空间（含全部子域）"


def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_time(value):
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+0000"
    # Python 3.6 的 %z 不认 +08:00 这种带冒号写法，先归一化。
    if len(text) >= 6 and text[-3] == ":" and text[-6] in "+-":
        text = text[:-3] + text[-2:]
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.datetime.strptime(text, fmt)
        except ValueError:
            pass
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            parsed = datetime.datetime.strptime(text, fmt)
            return parsed.replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            pass
    return None


def refresh_source_cache() -> None:
    """没有缓存或缓存超过 6 小时时，从 GitHub（含 gh-proxy 兜底）下载。"""
    os.makedirs(os.path.dirname(SOURCE_CACHE), exist_ok=True)
    try:
        fresh = os.path.getmtime(SOURCE_CACHE) > (datetime.datetime.now().timestamp() - SOURCE_MAX_AGE)
        if fresh and os.path.getsize(SOURCE_CACHE) > 1024:
            return
    except OSError:
        pass
    urls = [
        SOURCE_URL,
        "https://gh-proxy.org/" + SOURCE_URL,
        "https://gh-proxy.com/" + SOURCE_URL,
    ]
    last_error = None
    for url in urls:
        temp_name = None
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (AGH attribution)"})
            with urllib.request.urlopen(request, timeout=120) as response, tempfile.NamedTemporaryFile(
                mode="wb", dir=os.path.dirname(SOURCE_CACHE), prefix=".black-sources-", delete=False
            ) as handle:
                temp_name = handle.name
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    handle.write(chunk)
            os.chmod(temp_name, 0o644)
            os.replace(temp_name, SOURCE_CACHE)
            return
        except Exception as error:  # noqa: BLE001 - 下载失败时保留旧缓存
            last_error = error
            if temp_name:
                try:
                    os.unlink(temp_name)
                except OSError:
                    pass
    if not os.path.exists(SOURCE_CACHE):
        raise RuntimeError("无法下载 Black-with-sources.txt: " + str(last_error))


def load_source_map():
    mapping = {}
    rules_by_source = Counter()
    domain_spaces = set()
    version = None
    with open(SOURCE_CACHE, encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            line = raw.rstrip("\r\n")
            if line.startswith("! Version:"):
                version = line.split(":", 1)[1].strip()
                continue
            if not line or line.startswith("!"):
                continue
            if line.startswith("||") and line.endswith("^") and " # From: " not in line:
                domain = line[2:-1].strip().lower().strip(".")
                if domain:
                    domain_spaces.add(domain)
                    rules_by_source[DOMAIN_SPACE_LABEL] += 1
                continue
            if " # From: " not in line:
                continue
            left, source = line.rsplit(" # From: ", 1)
            domain = left.strip().lower().strip(".")
            if domain.startswith("||") and domain.endswith("^"):
                domain = domain[2:-1]
            if not domain:
                continue
            mapping[domain] = source.strip()
            rules_by_source[source.strip()] += 1
    return mapping, rules_by_source, version, domain_spaces


def normalize_rule(text: str) -> str:
    value = (text or "").strip().lower().strip(".")
    if value.startswith("||"):
        value = value[2:]
    if value.endswith("^"):
        value = value[:-1]
    return value.strip(".")


def analyze_querylog(mapping, domain_spaces):
    total = 0
    blocked = 0
    counts = Counter()
    unique_domains = defaultdict(set)
    unmapped = 0
    unmapped_domains = set()
    first_time = None
    last_time = None
    with open(QUERYLOG, encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            try:
                item = json.loads(raw)
            except json.JSONDecodeError:
                continue
            total += 1
            stamp = parse_time(item.get("T"))
            if stamp:
                first_time = stamp if first_time is None or stamp < first_time else first_time
                last_time = stamp if last_time is None or stamp > last_time else last_time
            result = item.get("Result") or {}
            if not result.get("IsFiltered"):
                continue
            reason = result.get("Reason")
            if reason is not None and str(reason) != "3":
                continue
            blocked += 1
            qh = (item.get("QH") or "").strip().lower().strip(".")
            chosen = None
            for rule in result.get("Rules") or []:
                if not isinstance(rule, dict):
                    continue
                try:
                    filter_id = int(rule.get("FilterListID"))
                except (TypeError, ValueError):
                    filter_id = None
                if filter_id == WHITE_FILTER_ID:
                    continue
                rule_text = (rule.get("Text") or "").strip()
                candidate = normalize_rule(rule_text)
                if candidate in mapping:
                    chosen = mapping[candidate]
                    break
                # AGH 的域名空间规则是 `||父域^`，不带来源注释；
                # 它覆盖全部子域，不能硬算到某个上游源，单独成桶。
                if candidate in domain_spaces:
                    chosen = DOMAIN_SPACE_LABEL
                    break
            if chosen:
                counts[chosen] += 1
                if qh:
                    unique_domains[chosen].add(qh)
            else:
                unmapped += 1
                if qh:
                    unmapped_domains.add(qh)
    hours = None
    if first_time and last_time:
        hours = round((last_time - first_time).total_seconds() / 3600, 2)
    return {
        "total": total,
        "blocked": blocked,
        "counts": counts,
        "unique_domains": unique_domains,
        "unmapped": unmapped,
        "unmapped_domains": len(unmapped_domains),
        "window_start": first_time.isoformat().replace("+00:00", "Z") if first_time else None,
        "window_end": last_time.isoformat().replace("+00:00", "Z") if last_time else None,
        "window_hours": hours,
    }


def write_json(payload) -> None:
    os.makedirs(os.path.dirname(OUT_FILE), exist_ok=True)
    handle, temp_name = tempfile.mkstemp(dir=os.path.dirname(OUT_FILE), prefix=".adg-attribution-")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, separators=(",", ":"))
        os.chmod(temp_name, 0o644)
        os.replace(temp_name, OUT_FILE)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise
    try:
        os.chown(OUT_FILE, 1000, 1000)
    except OSError:
        pass


def build_payload():
    refresh_source_cache()
    mapping, rules_by_source, version, domain_spaces = load_source_map()
    if not mapping:
        raise RuntimeError("Black-with-sources.txt 没有解析出任何来源映射")
    data = analyze_querylog(mapping, domain_spaces)
    total_rules = sum(rules_by_source.values())
    sources = []
    for name, rules in rules_by_source.items():
        events = int(data["counts"].get(name, 0))
        sources.append(
            {
                "name": name,
                "events": events,
                "share": round(events * 100.0 / data["blocked"], 2) if data["blocked"] else 0.0,
                "unique_domains": len(data["unique_domains"].get(name, set())),
                "rules": int(rules),
                "rule_share": round(rules * 100.0 / total_rules, 2) if total_rules else 0.0,
            }
        )
    sources.sort(key=lambda row: (-row["events"], -row["rules"], row["name"]))
    return {
        "available": True,
        "generated_at": utc_now(),
        "source": "AdGuard Home querylog",
        "window_start": data["window_start"],
        "window_end": data["window_end"],
        "window_hours": data["window_hours"],
        "total_queries": data["total"],
        "blocked_queries": data["blocked"],
        "blocked_pct": round(data["blocked"] * 100.0 / data["total"], 2) if data["total"] else 0.0,
        "filter_id": BLACK_FILTER_ID,
        "source_map": {"version": version, "rules": total_rules},
        "sources": sources,
        "unmapped_events": data["unmapped"],
        "unmapped_share": round(data["unmapped"] * 100.0 / data["blocked"], 2) if data["blocked"] else 0.0,
        "unmapped_domains": data["unmapped_domains"],
    }


def main() -> int:
    try:
        payload = build_payload()
        write_json(payload)
        top = ", ".join(str(row["name"]) + "=" + str(row["events"]) for row in payload["sources"][:6])
        print("adg-attribution: " + str(payload["blocked_queries"]) + " / " + str(payload["total_queries"]) + " blocked; " + top)
        return 0
    except Exception as error:  # noqa: BLE001 - 统计失败时保留上一份 JSON，但不让 cron 报错
        print("adg-attribution: " + str(error))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
