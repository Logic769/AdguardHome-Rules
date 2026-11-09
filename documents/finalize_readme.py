#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""构建后处理 README：补齐订阅文件条数，并写入 AGH 实际拦截归因。

由 GitHub Actions 在派生 Black-adblock / Black-domains-* 之后运行。
"""
import datetime
import json
import os
import re
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
CACHE_JSON = ROOT / "documents" / "upstream-attribution.json"
ATTRIBUTION_URL = os.environ.get(
    "ATTRIBUTION_URL", "https://www.logic769.xyz/api/adg-attribution.json"
)
COUNT_FILES = [
    "Black-adblock.txt",
    "Black-with-sources.txt",
    "Black-domains-cn-final.txt",
    "Black-domains-dedup.txt",
    "Black-domains-small.txt",
]


def count_rules(path: Path):
    if not path.exists():
        return None
    count = 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            value = line.strip()
            if value and not value.startswith("!") and not value.startswith("#"):
                count += 1
    return count


def patch_subscription_counts(text: str) -> str:
    counts = {name: count_rules(ROOT / name) for name in COUNT_FILES}
    bt = chr(96)
    pattern = re.compile(r"^\| " + bt + r"([^" + bt + r"]+)" + bt + r" \|")
    lines = text.splitlines(keepends=True)
    output = []
    for line in lines:
        match = pattern.match(line)
        count = counts.get(match.group(1)) if match else None
        if count is not None and "见 Release" in line:
            parts = line.split("|")
            for index, part in enumerate(parts):
                if part.strip() == "见 Release":
                    parts[index] = " " + format(count, ",") + " "
            line = "|".join(parts)
        output.append(line)
    return "".join(output)


def fetch_attribution():
    try:
        request = urllib.request.Request(
            ATTRIBUTION_URL,
            headers={"User-Agent": "AdguardHome-Rules README Builder"},
        )
        with urllib.request.urlopen(request, timeout=20) as response:
            data = json.load(response)
        if data.get("available") is not False:
            CACHE_JSON.write_text(
                json.dumps(data, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            return data
    except Exception as error:  # noqa: BLE001 - 回退到仓库内上一份快照
        print("attribution fetch failed: " + str(error))
    if CACHE_JSON.exists():
        try:
            return json.loads(CACHE_JSON.read_text(encoding="utf-8"))
        except Exception as error:  # noqa: BLE001
            print("attribution cache read failed: " + str(error))
    return None


def number(value):
    try:
        number_value = float(value)
        if number_value.is_integer():
            return format(int(number_value), ",")
        return format(number_value, ",.2f")
    except (TypeError, ValueError):
        return "—"


def percent(value):
    try:
        return format(float(value), ".2f") + "%"
    except (TypeError, ValueError):
        return "—"


def local_time(value):
    if not value:
        return "—"
    try:
        text = str(value).replace("Z", "+00:00")
        parsed = datetime.datetime.fromisoformat(text)
        return (parsed + datetime.timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S") + " (UTC+8)"
    except (TypeError, ValueError):
        return str(value)


def build_attribution_section(data):
    title = "### 实际拦截贡献（AdGuard Home 查询日志）"
    if not data or data.get("available") is False:
        return title + "\n\n> 统计接口暂不可用，下一次构建会自动重试。\n"
    window = "—"
    if data.get("window_start") and data.get("window_end"):
        hours = data.get("window_hours")
        window = local_time(data["window_start"]) + " ~ " + local_time(data["window_end"])
        if hours is not None:
            window += "（约 " + format(float(hours), ".1f") + " 小时）"
    rows = []
    for row in (data.get("sources") or [])[:10]:
        rows.append(
            "| " + str(row.get("name", "—")) + " | " + number(row.get("events")) + " | "
            + percent(row.get("share")) + " | " + number(row.get("unique_domains")) + " | "
            + number(row.get("rules")) + " | " + percent(row.get("rule_share")) + " |"
        )
    rest = (data.get("sources") or [])[10:]
    if rest:
        rows.append(
            "| 其他 " + str(len(rest)) + " 个源 | "
            + number(sum(float(row.get("events") or 0) for row in rest)) + " | "
            + percent(sum(float(row.get("share") or 0) for row in rest)) + " | — | "
            + number(sum(float(row.get("rules") or 0) for row in rest)) + " | "
            + percent(sum(float(row.get("rule_share") or 0) for row in rest)) + " |"
        )
    if data.get("unmapped_events"):
        rows.append(
            "| 未映射（可能是自定义规则/新规则） | " + number(data.get("unmapped_events")) + " | "
            + percent(data.get("unmapped_share")) + " | " + number(data.get("unmapped_domains")) + " | — | — |"
        )
    table = "\n".join(rows) if rows else "| — | — | — | — | — | — |"
    return (
        title + "\n\n"
        + "> 统计生成：" + local_time(data.get("generated_at")) + "；统计窗口：" + window + "；共 "
        + number(data.get("total_queries")) + " 次查询，"
        + number(data.get("blocked_queries")) + " 次被拦截（" + percent(data.get("blocked_pct")) + "）。\n"
        + "> 数据来自我的 AdGuard Home 查询日志，只统计聚合命中来源，不包含具体查询内容；"
        + "服务器每 15 分钟更新，本页随每次构建刷新。\n"
        + "> 注：同一域名被多个上游同时收录时，实际拦截事件按来源数平均分摊（1/N）；「域名空间」规则以 `||父域^` 形式覆盖全部子域，无法对应单一上游源，单独统计。\n\n"
        + "| 上游源 | 实际拦截事件 | 事件占比 | 命中唯一域名 | 规则条数 | 规则占比 |\n"
        + "| --- | ---: | ---: | ---: | ---: | ---: |\n"
        + table
        + "\n"
    )


def merge_attribution(text: str, section: str) -> str:
    marker = "\n---\n\n## 五、规则为什么这么写？"
    if marker not in text:
        text = re.sub(r"\n### 实际拦截贡献.*$", "", text, flags=re.S)
        return text.rstrip() + "\n\n" + section + "\n"
    head, tail = text.split(marker, 1)
    head = re.sub(r"\n### 实际拦截贡献.*$", "", head, flags=re.S)
    return head.rstrip() + "\n\n" + section + marker + tail


def main():
    text = README.read_text(encoding="utf-8")
    text = patch_subscription_counts(text)
    data = fetch_attribution()
    text = merge_attribution(text, build_attribution_section(data))
    README.write_text(text, encoding="utf-8")
    print("README updated: subscription counts + attribution")


if __name__ == "__main__":
    main()
