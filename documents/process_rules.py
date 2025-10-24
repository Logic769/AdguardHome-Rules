import requests
import datetime
import time
import os

# ===================== 配置区 =====================

# 脚本与项目根路径
script_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(script_dir)

# 黑名单规则源（网络）
block_source_urls = {
    "秋风的规则": "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
    "GitHub加速": "https://raw.githubusercontent.com/521xueweihan/GitHub520/refs/heads/main/hosts",
    "广告规则": "https://raw.githubusercontent.com/huantian233/HT-AD/main/AD.txt",
    "DD自用": "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt",
    "消失DD": "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/dns.txt",
    "大萌主": "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt",
    "逆向涉猎": "https://raw.githubusercontent.com/790953214/qy-Ads-Rule/main/black.txt",
    "下个ID见": "https://raw.githubusercontent.com/2Gardon/SM-Ad-FuckU-hosts/master/SMAdHosts",
    "那个谁520": "https://raw.githubusercontent.com/qq5460168/666/master/rules.txt",
    "1hosts": "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/adblock.txt",
    "茯苓的广告规则": "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/Master/FuLingRules/FuLingBlockList.txt",
    "AdBlockDNSFilters1": "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnslite.txt",
    "AdBlockDNSFilters2": "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockfilterslite.txt",
    "Ad-set-hosts": "https://raw.githubusercontent.com/rentianyu/Ad-set-hosts/master/adguard",
    "GOODBYEADS": "https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/dns.txt",
    "10007_auto": "https://raw.githubusercontent.com/lingeringsound/10007_auto/master/reward",
    "AWAvenue-Ads-Rule": "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
    "github520": "https://raw.hellogithub.com/hosts",
    "GitHub Hosts": "https://github-hosts.tinsfox.com/hosts",
    "Malicious URL Blocklist": "https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt",
    "Menghuibanxian": "https://raw.githubusercontent.com/Menghuibanxian/AdguardHome/refs/heads/main/Black.txt"
}

# 白名单规则源（网络）
white_source_urls = {
    "茯苓允许列表": "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/Master/FuLingRules/FuLingAllowList.txt",
    "666": "https://raw.githubusercontent.com/qq5460168/666/master/allow.txt",
    "个人自用白名单": "https://raw.githubusercontent.com/qq5460168/dangchu/main/white.txt",
    "冷漠白名单": "https://file-git.trli.club/file-hosts/allow/Domains",
    "BlueSkyXN": "https://raw.githubusercontent.com/BlueSkyXN/AdGuardHomeRules/master/ok.txt",
    "GOODBYEADS": "https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/allow.txt",
    "冷漠白名单2": "https://github.com/Potterli20/file/releases/download/github-hosts/allow.txt",
    "冷漠白名单3": "https://github.com/Potterli20/file/releases/download/github-hosts/ad-edge-hosts.txt"
}

# 本地自定义规则文件（与脚本同目录）
custom_block_file = "my-blocklist.txt"
custom_white_file = "my-whitelist.txt"

# 输出文件名（通过环境变量覆盖）
block_filename = os.environ.get("OUTPUT_BLOCK_FILENAME", "Black.txt")
white_filename = os.environ.get("OUTPUT_WHITE_FILENAME", "White.txt")
block_output_file = os.path.join(root_dir, block_filename)
white_output_file = os.path.join(root_dir, white_filename)

# README 开头标题（通过环境变量覆盖）
readme_title = os.environ.get("README_TITLE", "平稳的规则")

# Release 标签（用于 README 直链）
release_tag = os.environ.get("RELEASE_TAG")

# ===================== 脚本区 =====================

def download_file(url: str, friendly_name: str):
    """下载指定 URL 的内容"""
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

def process_line(line: str) -> str:
    """清洗单行规则，提取域名"""
    line = line.strip()

    if not line or line.startswith(('!', '#', '/', '[', '@')):
        return ""

    line = line.replace("@@", "").replace("||", "").replace("^", "")
    if "$" in line:
        line = line.split("$", 1)[0]

    if line.startswith("*."):
        line = line[2:]
    if line.startswith("."):
        line = line[1:]

    if line.startswith("0.0.0.0 ") or line.startswith("127.0.0.1 "):
        parts = line.split()
        if len(parts) >= 2:
            line = parts[1]

    if "." not in line or " " in line or "<" in line or "/" in line:
        return ""

    if line in {"localhost", "127.0.0.1", "0.0.0.0"}:
        return ""

    return line.strip()

def process_urls_to_dict(urls_dict: dict) -> dict:
    """下载并处理 URL 字典，返回一个 {规则: 来源名称} 的字典"""
    rules_dict: dict[str, str] = {}
    for name, url in urls_dict.items():
        content = download_file(url, name)
        if not content:
            continue

        lines = content.splitlines()
        count = 0
        for line in lines:
            processed_line = process_line(line)
            if processed_line and processed_line not in rules_dict:
                rules_dict[processed_line] = name
                count += 1
        print(f"  从 {name} 添加了 {count} 条新规则。")
        time.sleep(1)
    return rules_dict

def process_local_file(filename: str, source_name: str) -> dict:
    """读取并处理本地规则文件，如果文件不存在则跳过"""
    full_path = os.path.join(script_dir, filename)
    if not os.path.exists(full_path):
        print(f"\n  本地文件 {filename} 不存在，跳过。")
        return {}

    print(f"\n  正在处理本地文件: {filename}")
    rules_dict: dict[str, str] = {}
    count = 0
    with open(full_path, "r", encoding="utf-8") as f:
        for line in f:
            processed_line = process_line(line)
            if processed_line and processed_line not in rules_dict:
                rules_dict[processed_line] = source_name
                count += 1
    print(f"  从 {filename} 添加了 {count} 条自定义规则。")
    return rules_dict

def write_rules_to_file(filename: str, rules_dict: dict, title: str, description: str, author: str):
    """将规则字典写入文件，并添加作者与更新时间等头信息"""
    print(f"\n正在将规则写入到 {os.path.basename(filename)}...")
    sorted_rules = sorted(rules_dict.keys())
    try:
        with open(filename, "w", encoding="utf-8") as f:
            beijing_tz = datetime.timezone(datetime.timedelta(hours=8))
            now_beijing = datetime.datetime.now(beijing_tz)

            f.write(f"! Title: {title}\n")
            f.write(f"! Description: {description}\n")
            f.write(f"! Author: {author}\n")
            f.write(f"! Version: {now_beijing.strftime('%Y%m%d%H%M%S')}\n")
            f.write(f"! Last Updated: {now_beijing.strftime('%Y-%m-%d %H:%M:%S')} (UTC+8)\n")
            f.write(f"! Total Rules: {len(sorted_rules)}\n")
            f.write("!\n")

            for rule in sorted_rules:
                source = rules_dict[rule]
                f.write(f"{rule} # From: {source}\n")
        print(f"文件 {os.path.basename(filename)} 写入成功！")
    except IOError as e:
        print(f"写入文件失败: {filename}, 错误: {e}")

def update_readme(block_rules_dict: dict, white_rules_dict: dict):
    """生成并更新 README.md 文件（链接指向 Release 资源）"""
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

项目作者: zhuanshenlikaini

本项目通过 GitHub Actions 自动合并、去重多个来源的 AdGuard Home 规则，并排除白名单。

最后更新时间: {now_beijing.strftime('%Y-%m-%d %H:%M:%S')} (UTC+8)

最终黑名单规则数: {len(block_rules_dict)}

最终白名单规则数: {len(white_rules_dict)}

订阅链接

拦截规则 (Blocklist)

{code_fence}
{base_url}/{os.path.basename(block_output_file)}
{code_fence}

允许规则 (Whitelist)

{code_fence}
{base_url}/{os.path.basename(white_output_file)}
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
    """主执行函数"""
    print("--- 开始处理白名单 ---")
    white_rules_dict = process_urls_to_dict(white_source_urls)
    white_rules_dict.update(process_local_file(custom_white_file, "Custom Whitelist"))

    print("\n--- 开始处理黑名单 ---")
    block_rules_dict = process_urls_to_dict(block_source_urls)
    block_rules_dict.update(process_local_file(custom_block_file, "Custom Blocklist"))

    print("\n--- 最终处理 ---")
    initial_block_count = len(block_rules_dict)
    print(f"合并后黑名单共: {initial_block_count} 条")
    print(f"合并后白名单共: {len(white_rules_dict)} 条")

    final_block_rules_dict = {
        rule: source
        for rule, source in block_rules_dict.items()
        if rule not in white_rules_dict
    }

    final_block_count = len(final_block_rules_dict)
    removed_count = initial_block_count - final_block_count

    print(f"从黑名单中移除了 {removed_count} 条白名单规则。")
    print(f"最终生效黑名单共: {final_block_count} 条。")

    write_rules_to_file(
        block_output_file,
        final_block_rules_dict,
        "AdGuard Custom Blocklist",
        "自动合并的广告拦截规则",
        "zhuanshenlikaini",
    )
    write_rules_to_file(
        white_output_file,
        white_rules_dict,
        "AdGuard Custom Whitelist",
        "自动合并的白名单规则",
        "zhuanshenlikaini",
    )

    update_readme(final_block_rules_dict, white_rules_dict)

if __name__ == "__main__":
    main()
