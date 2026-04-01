import requests
import datetime
import time
import os
import re
from dataclasses import dataclass, field
from typing import Optional

script_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(script_dir)

block_source_urls = {
    "秋风的规则": "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
    "广告规则": "https://raw.githubusercontent.com/huantian233/HT-AD/main/AD.txt",
    "DD自用": "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt",
    "大萌主": "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt",
    "逆向涉猎": "https://raw.githubusercontent.com/790953214/qy-Ads-Rule/main/black.txt",
    "下个ID见": "https://raw.githubusercontent.com/2Gardon/SM-Ad-FuckU-hosts/master/SMAdHosts",
    "那个谁520": "https://raw.githubusercontent.com/qq5460168/666/master/rules.txt",
    "1hosts": "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/adblock.txt",
    "茯苓的广告规则": "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/main/FuLingRules/FuLingBlockList.txt",
    "AdBlockDNSFilters1": "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnslite.txt",
    "AdBlockDNSFilters2": "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockfilterslite.txt",
    "Ad-set-hosts": "https://raw.githubusercontent.com/rentianyu/Ad-set-hosts/master/adguard",
    "GOODBYEADS": "https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/dns.txt",
    "10007_auto": "https://raw.githubusercontent.com/lingeringsound/10007_auto/master/reward",
    "Malicious URL Blocklist": "https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt",
    "xndeye adblock_list": "https://raw.githubusercontent.com/xndeye/adblock_list/refs/heads/release/easylist.txt",
    "Menghuibanxian": "https://raw.githubusercontent.com/Menghuibanxian/AdguardHome/refs/heads/main/Black.txt",
    "anti-AD": "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-easylist.txt",
    "AdBlock DNS Filters": "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt",
    "ABP": "https://raw.githubusercontent.com/damengzhu/abpmerge/refs/heads/main/abpmerge.txt"
}

white_source_urls = {
    "茯苓允许列表": "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/main/FuLingRules/FuLingAllowList.txt",
    "666": "https://raw.githubusercontent.com/qq5460168/666/master/allow.txt",
    "个人自用白名单": "https://raw.githubusercontent.com/qq5460168/dangchu/main/white.txt",
    "BlueSkyXN": "https://raw.githubusercontent.com/BlueSkyXN/AdGuardHomeRules/master/ok.txt",
    "GOODBYEADS": "https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/allow.txt"
}

custom_block_file = "my-blocklist.txt"
custom_white_file = "my-whitelist.txt"

block_filename = os.environ.get("OUTPUT_BLOCK_FILENAME", "Black.txt")
white_filename = os.environ.get("OUTPUT_WHITE_FILENAME", "White.txt")
conflict_filename = os.environ.get("OUTPUT_CONFLICT_FILENAME", "Conflict.txt")
block_output_file = os.path.join(root_dir, block_filename)
white_output_file = os.path.join(root_dir, white_filename)
conflict_output_file = os.path.join(root_dir, conflict_filename)

readme_title = os.environ.get("README_TITLE", "平稳的规则")
release_tag = os.environ.get("RELEASE_TAG")
AUTHOR = "logic769"


@dataclass
class ParsedRule:
    domain: str
    is_whitelist: bool
    modifiers: list[str] = field(default_factory=list)
    original_line: str = ""
    source: str = ""
    
    def to_adguard_rule(self) -> str:
        rule = f"||{self.domain}^"
        if self.modifiers:
            rule += "$" + ",".join(self.modifiers)
        return rule
    
    def get_domain_key(self) -> str:
        return self.domain.lower()


class RuleParser:
    SUPPORTED_MODIFIERS = {
        'important', 'badfilter', 'dnsrewrite', 'client', 
        'script', 'image', 'stylesheet', 'object', 'xmlhttprequest',
        'object-subrequest', 'subdocument', 'ping', 'websocket',
        'third-party', '~third-party', 'match-case', 'cname',
        'redirect', 'redirect-rule', 'removeparam', 'empty', 'mp4',
        'media', 'popup', 'font', 'other', 'cookie', 'stealth',
        'urlblock', 'extension', 'jsinject', 'content', 'generichide',
        'genericblock', 'popunder', 'app', 'network', 'all'
    }
    
    @staticmethod
    def parse_line(line: str, source: str = "") -> Optional[ParsedRule]:
        line = line.strip()
        
        if not line:
            return None
        
        if line.startswith(('!', '#', '/', '[')):
            return None
        
        is_whitelist = line.startswith('@@')
        if is_whitelist:
            line = line[2:]
        
        modifiers = []
        if '$' in line:
            parts = line.split('$', 1)
            line = parts[0]
            modifier_str = parts[1] if len(parts) > 1 else ""
            
            if modifier_str:
                raw_modifiers = [m.strip() for m in modifier_str.split(',')]
                for mod in raw_modifiers:
                    mod_lower = mod.lower().split('=')[0].lstrip('~')
                    if mod_lower in RuleParser.SUPPORTED_MODIFIERS:
                        modifiers.append(mod)
                    elif mod_lower.startswith('dnsrewrite'):
                        modifiers.append(mod)
                    elif mod_lower.startswith('client'):
                        modifiers.append(mod)
                    elif mod_lower.startswith('redirect'):
                        modifiers.append(mod)
        
        line = line.replace("||", "").replace("^", "")
        
        if line.startswith("*."):
            line = line[2:]
        if line.startswith("."):
            line = line[1:]
        
        if line.startswith("0.0.0.0 ") or line.startswith("127.0.0.1 "):
            parts = line.split()
            if len(parts) >= 2:
                line = parts[1]
        
        if "~" in line:
            line = line.split("~")[0]
        
        line = line.strip()
        
        if "." not in line:
            return None
        
        if " " in line or "<" in line or "/" in line:
            return None
        
        if line in {"localhost", "127.0.0.1", "0.0.0.0"}:
            return None
        
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$', line):
            if not re.match(r'^[\w.-]+$', line):
                return None
        
        return ParsedRule(
            domain=line,
            is_whitelist=is_whitelist,
            modifiers=modifiers,
            original_line=line,
            source=source
        )


def download_file(url: str, friendly_name: str) -> Optional[str]:
    try:
        print(f"  正在下载: {friendly_name}")
        headers = {
            "User-Agent": "Mozilla/5.0 (GitHub Actions; +https://github.com)",
            "Accept": "*/*",
        }
        resp = requests.get(url, headers=headers, timeout=60)
        resp.raise_for_status()
        return resp.text
    except requests.exceptions.RequestException as e:
        print(f"  下载失败: {url}, 错误: {e}")
        return None


@dataclass
class RuleCollection:
    rules: dict[str, ParsedRule] = field(default_factory=dict)
    
    def add_rule(self, rule: ParsedRule) -> bool:
        key = rule.get_domain_key()
        if key not in self.rules:
            self.rules[key] = rule
            return True
        else:
            existing = self.rules[key]
            if rule.modifiers and not existing.modifiers:
                self.rules[key] = rule
                return True
            elif rule.modifiers and existing.modifiers:
                merged_modifiers = list(set(existing.modifiers + rule.modifiers))
                if len(merged_modifiers) > len(existing.modifiers):
                    existing.modifiers = merged_modifiers
            return False
    
    def get_domains(self) -> set[str]:
        return set(self.rules.keys())


def process_source_to_rules(url: str, source_name: str) -> tuple[RuleCollection, RuleCollection]:
    """
    处理单个规则源，返回 (黑名单集合, 白名单集合)
    自动检测并分离混合的黑白名单规则
    """
    content = download_file(url, source_name)
    if not content:
        return RuleCollection(), RuleCollection()
    
    block_rules = RuleCollection()
    white_rules = RuleCollection()
    mixed_detected = False
    
    lines = content.splitlines()
    for line in lines:
        parsed = RuleParser.parse_line(line, source_name)
        if not parsed:
            continue
        
        if parsed.is_whitelist:
            white_rules.add_rule(parsed)
            mixed_detected = True
        else:
            block_rules.add_rule(parsed)
    
    if mixed_detected:
        print(f"  [混合规则检测] {source_name} 包含混合的黑白名单规则，已自动分离")
    
    print(f"  从 {source_name} 添加了 {len(block_rules.rules)} 条黑名单规则, {len(white_rules.rules)} 条白名单规则")
    
    return block_rules, white_rules


def process_all_sources(urls_dict: dict) -> tuple[RuleCollection, RuleCollection]:
    """
    处理所有规则源，自动分离混合规则
    返回 (合并后的黑名单集合, 合并后的白名单集合)
    """
    all_block_rules = RuleCollection()
    all_white_rules = RuleCollection()
    
    for name, url in urls_dict.items():
        block_rules, white_rules = process_source_to_rules(url, name)
        
        for rule in block_rules.rules.values():
            all_block_rules.add_rule(rule)
        
        for rule in white_rules.rules.values():
            all_white_rules.add_rule(rule)
        
        time.sleep(1)
    
    return all_block_rules, all_white_rules


def process_local_file(filename: str, source_name: str, is_whitelist_file: bool = False) -> tuple[RuleCollection, RuleCollection]:
    """
    处理本地规则文件
    is_whitelist_file: 标识该文件是否为白名单文件（用于默认分类）
    返回 (黑名单集合, 白名单集合)
    """
    full_path = os.path.join(script_dir, filename)
    if not os.path.exists(full_path):
        print(f"\n  本地文件 {filename} 不存在，跳过。")
        return RuleCollection(), RuleCollection()
    
    print(f"\n  正在处理本地文件: {filename}")
    
    block_rules = RuleCollection()
    white_rules = RuleCollection()
    
    with open(full_path, "r", encoding="utf-8") as f:
        for line in f:
            parsed = RuleParser.parse_line(line, source_name)
            if not parsed:
                continue
            
            if parsed.is_whitelist:
                white_rules.add_rule(parsed)
            elif is_whitelist_file:
                white_rules.add_rule(parsed)
            else:
                block_rules.add_rule(parsed)
    
    print(f"  从 {filename} 添加了 {len(block_rules.rules)} 条黑名单规则, {len(white_rules.rules)} 条白名单规则")
    
    return block_rules, white_rules


def merge_collections(*collections: RuleCollection) -> RuleCollection:
    """
    合并多个规则集合
    """
    merged = RuleCollection()
    for collection in collections:
        for rule in collection.rules.values():
            merged.add_rule(rule)
    return merged


def find_conflict_rules(block_rules: RuleCollection, white_rules: RuleCollection) -> dict[str, tuple[ParsedRule, ParsedRule]]:
    """
    查找同时存在于黑名单和白名单中的规则
    返回 {域名: (黑名单规则, 白名单规则)} 的字典
    """
    conflict_rules: dict[str, tuple[ParsedRule, ParsedRule]] = {}
    
    block_domains = block_rules.get_domains()
    white_domains = white_rules.get_domains()
    
    for domain in block_domains & white_domains:
        conflict_rules[domain] = (block_rules.rules[domain], white_rules.rules[domain])
    
    return conflict_rules


def write_rules_to_file(filename: str, rules_collection: RuleCollection, title: str, description: str, author: str):
    print(f"\n正在将规则写入到 {os.path.basename(filename)}...")
    
    sorted_domains = sorted(rules_collection.rules.keys())
    
    try:
        with open(filename, "w", encoding="utf-8") as f:
            beijing_tz = datetime.timezone(datetime.timedelta(hours=8))
            now_beijing = datetime.datetime.now(beijing_tz)

            f.write(f"! Title: {title}\n")
            f.write(f"! Description: {description}\n")
            f.write(f"! Author: {author}\n")
            f.write(f"! Version: {now_beijing.strftime('%Y%m%d%H%M%S')}\n")
            f.write(f"! Last Updated: {now_beijing.strftime('%Y-%m-%d %H:%M:%S')} (UTC+8)\n")
            f.write(f"! Total Rules: {len(sorted_domains)}\n")
            f.write("!\n")

            for domain in sorted_domains:
                rule = rules_collection.rules[domain]
                adguard_rule = rule.to_adguard_rule()
                f.write(f"{adguard_rule} # From: {rule.source}\n")
        print(f"文件 {os.path.basename(filename)} 写入成功！")
    except IOError as e:
        print(f"写入文件失败: {filename}, 错误: {e}")


def write_conflict_to_file(filename: str, conflict_rules: dict, title: str, description: str, author: str):
    print(f"\n正在将冲突规则写入到 {os.path.basename(filename)}...")
    
    sorted_domains = sorted(conflict_rules.keys())
    
    try:
        with open(filename, "w", encoding="utf-8") as f:
            beijing_tz = datetime.timezone(datetime.timedelta(hours=8))
            now_beijing = datetime.datetime.now(beijing_tz)

            f.write(f"! Title: {title}\n")
            f.write(f"! Description: {description}\n")
            f.write(f"! Author: {author}\n")
            f.write(f"! Version: {now_beijing.strftime('%Y%m%d%H%M%S')}\n")
            f.write(f"! Last Updated: {now_beijing.strftime('%Y-%m-%d %H:%M:%S')} (UTC+8)\n")
            f.write(f"! Total Rules: {len(sorted_domains)}\n")
            f.write("!\n")

            for domain in sorted_domains:
                block_rule, white_rule = conflict_rules[domain]
                block_adguard = block_rule.to_adguard_rule()
                white_adguard = white_rule.to_adguard_rule()
                f.write(f"{domain} # Block: {block_adguard} (from {block_rule.source}), White: {white_adguard} (from {white_rule.source})\n")
        print(f"文件 {os.path.basename(filename)} 写入成功！")
    except IOError as e:
        print(f"写入文件失败: {filename}, 错误: {e}")


def update_readme(block_rules: RuleCollection, white_rules: RuleCollection, conflict_rules: dict):
    print("\n正在更新 README.md...")
    repo_name = os.environ.get("GITHUB_REPOSITORY", "your_username/your_repo")
    branch_name = os.environ.get("GITHUB_REF_NAME") or "main"

    if release_tag:
        base_url = f"https://github.com/{repo_name}/releases/download/{release_tag}"
    else:
        base_url = f"https://raw.githubusercontent.com/{repo_name}/{branch_name}"

    beijing_tz = datetime.timezone(datetime.timedelta(hours=8))
    now_beijing = datetime.datetime.now(beijing_tz)

    all_block_sources = list(block_source_urls.keys())
    if os.path.exists(os.path.join(script_dir, custom_block_file)):
        all_block_sources.append("Custom Blocklist (本地)")

    all_white_sources = list(white_source_urls.keys())
    if os.path.exists(os.path.join(script_dir, custom_white_file)):
        all_white_sources.append("Custom Whitelist (本地)")

    block_sources_md = "\n".join([f"- {name}" for name in all_block_sources])
    white_sources_md = "\n".join([f"- {name}" for name in all_white_sources])

    code_fence = "```"

    readme_content = f"""# {readme_title}

# 自动更新的 AdGuard Home 规则

项目作者: {AUTHOR}

本项目通过 GitHub Actions 自动合并、去重多个来源的 AdGuard Home 规则。
支持自动检测并分离上游规则中的混合黑白名单。
支持保留规则修饰符（如 $important, $script 等）以实现精准过滤。
黑白名单完全独立，同时存在的规则会单独列在冲突规则中。

最后更新时间: {now_beijing.strftime('%Y-%m-%d %H:%M:%S')} (UTC+8)

最终黑名单规则数: {len(block_rules.rules)}

最终白名单规则数: {len(white_rules.rules)}

冲突规则数: {len(conflict_rules)}

订阅链接

拦截规则 (Blocklist)

{code_fence}
{base_url}/{os.path.basename(block_output_file)}
{code_fence}

允许规则 (Whitelist)

{code_fence}
{base_url}/{os.path.basename(white_output_file)}
{code_fence}

冲突规则 (Conflict)

{code_fence}
{base_url}/{os.path.basename(conflict_output_file)}
{code_fence}

规则来源

黑名单来源 (Blocklist Sources)

{block_sources_md}

白名单来源 (Whitelist Sources)

{white_sources_md}

由 GitHub Actions 自动构建。
"""
    try:
        with open(os.path.join(root_dir, "README.md"), "w", encoding="utf-8") as f:
            f.write(readme_content)
        print("README.md 更新成功！")
    except IOError as e:
        print(f"写入 README.md 失败: {e}")


def main():
    print("=" * 60)
    print("AdGuard Home 规则处理脚本 (重构版)")
    print("支持: 自动分离混合规则、规则去重、保留修饰符、黑白名单独立、冲突规则检测")
    print("=" * 60)
    
    print("\n--- 第一步: 处理白名单规则源 ---")
    white_source_block, white_source_white = process_all_sources(white_source_urls)
    
    print("\n--- 第二步: 处理黑名单规则源 ---")
    block_source_block, block_source_white = process_all_sources(block_source_urls)
    
    print("\n--- 第三步: 处理本地自定义规则 ---")
    local_block, local_white = process_local_file(custom_block_file, "Custom Blocklist", is_whitelist_file=False)
    local_white_file_rules, _ = process_local_file(custom_white_file, "Custom Whitelist", is_whitelist_file=True)
    
    print("\n--- 第四步: 合并所有规则 ---")
    all_white_rules = merge_collections(
        white_source_white,
        white_source_block,
        block_source_white,
        local_white,
        local_white_file_rules
    )
    
    all_block_rules = merge_collections(
        block_source_block,
        local_block
    )
    
    print(f"  合并后黑名单共: {len(all_block_rules.rules)} 条")
    print(f"  合并后白名单共: {len(all_white_rules.rules)} 条")
    
    print("\n--- 第五步: 检测冲突规则 ---")
    conflict_rules = find_conflict_rules(all_block_rules, all_white_rules)
    print(f"  检测到 {len(conflict_rules)} 条冲突规则（同时存在于黑名单和白名单）")
    
    print(f"\n最终统计:")
    print(f"  最终黑名单: {len(all_block_rules.rules)} 条")
    print(f"  最终白名单: {len(all_white_rules.rules)} 条")
    print(f"  冲突规则: {len(conflict_rules)} 条")
    
    write_rules_to_file(
        block_output_file,
        all_block_rules,
        "AdGuard Custom Blocklist",
        "自动合并的广告拦截规则（与白名单完全独立，保留修饰符）",
        AUTHOR,
    )
    write_rules_to_file(
        white_output_file,
        all_white_rules,
        "AdGuard Custom Whitelist",
        "自动合并的白名单规则（与黑名单完全独立，保留修饰符）",
        AUTHOR,
    )
    write_conflict_to_file(
        conflict_output_file,
        conflict_rules,
        "AdGuard Conflict Rules",
        "同时存在于黑名单和白名单的规则",
        AUTHOR,
    )

    update_readme(all_block_rules, all_white_rules, conflict_rules)
    
    print("\n" + "=" * 60)
    print("规则处理完成！")
    print("=" * 60)


if __name__ == "__main__":
    main()
