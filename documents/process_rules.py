import requests
import datetime
import time
import os
import re
from dataclasses import dataclass
from typing import Optional

script_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(script_dir)

# ============================================================================
# 规则语义与本脚本的忠实化处理
# ----------------------------------------------------------------------------
# AdGuard Home 会把「不带 || 和 ^ 的纯域名行」当作 hosts 型规则，匹配方式是
# 「精确主机名相等」（urlfilter/dnsengine.go: ruleIndex[hostname]），
# 因此本脚本只输出域名本身。为了让输出不偏离上游规则的原意，做如下处理：
#
#  1. 带「上下文修饰符」的规则一律丢弃，例如：
#       ||example.com^$domain=a.com|b.com      （只在 a.com/b.com 上生效）
#       ||example.com^$third-party             （只拦第三方请求）
#       ||example.com^$script,$image           （只拦特定资源类型）
#       ||example.com^$path=/union/            （只拦特定路径）
#     这些条件在 DNS 层无法表达。若保留域名、丢掉条件，就会把「只在某站点生效」
#     的规则放大成「全局拦截」——这是本仓库历史上最主要的误杀来源
#     （例如 ||gw.tmall.com^$path=/union/ 被放大成整个天猫网关被拦）。
#
#  2. $badfilter 是「取消规则」的否定语义，直接丢弃，绝不能当拦截执行。
#
#  3. $important / $dnsrewrite 不改变「拦不拦」，保留为普通拦截规则
#     （纯域名输出无法携带修饰符；$dnsrewrite=NOERROR;; 等空回答规则，
#      在 DNS 世界的实际效果同样是「该域名解析不到」，拦截强度不降低）。
#
#  4. 上游 @@ 例外（黑名单源里混着的白名单）只采纳「无修饰符的全局例外」，
#     并且必须是「有争议」的域名：被拦截的上游源少于 EXCEPTION_MAX_BLOCK_SOURCES 个。
#     原因：部分名单自带很长的私人白名单（如「那个谁520」近 3000 条 @@），
#     照单全收会把公认的广告/追踪域名放行——实测被 17 个源共同拦截的
#     als.baidu.com、被 16 个源拦截的 nsclick.baidu.com 都因一句 @@ 而漏拦。
#     被 3 个以上独立名单共同认定为拦截目标的域名，不采纳单个名单的例外。
#
#  5. 域名规范化：统一小写、严格校验，剔除裸 IP、首尾点、通配符、
#     公共后缀（com.cn 之类）等永远匹配不到的垃圾规则。
#
#  6. 核心服务保护名单（NEVER_BLOCK）：系统更新、连通性检测、推送通道、
#     加密 DNS、证书吊销、NTP、阿里系 App 网络/风控（ACS）等，
#     无论上游怎么写都永不拦截。
# ============================================================================

block_source_urls = {
    "秋风的规则": "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
"晴雅":"https://raw.githubusercontent.com/3316134332/qy-Ads-Rule/refs/heads/main/black.txt",
"困了想睡觉":"https://raw.githubusercontent.com/Kuner-mw/DNS-Kuner/main/FilterRules/blacklist.txt",
"海哥":"https://raw.githubusercontent.com/2771936993/HG/main/hg1.txt",
    "秋风的规则补充": "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-Replenish.txt",
"natsuki":"https://raw.githubusercontent.com/Natsuki-Kaede/Natsuki-List/refs/heads/main/adguardhome.txt",
    "DD自用": "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt",
    "smad": "https://raw.githubusercontent.com/2Gardon/SM-Ad-FuckU-hosts/refs/heads/master/SMAdHosts",
    "大萌主": "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt",
    "10007": "https://raw.githubusercontent.com/lingeringsound/10007_auto/master/adb.txt",
    "逆向涉猎": "https://raw.githubusercontent.com/790953214/qy-Ads-Rule/main/black.txt",
    "neodavhost": "https://raw.githubusercontent.com/neodevpro/neodevhost/master/adblocker",
    "下个ID见": "https://raw.githubusercontent.com/2Gardon/SM-Ad-FuckU-hosts/master/SMAdHosts",
    "adsethost": "https://raw.githubusercontent.com/rentianyu/Ad-set-hosts/master/adguard",
    "1hosts": "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/adblock.txt",
    "茯苓的广告规则": "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/main/FuLingRules/FuLingBlockList.txt",
    "GOODBYEADS": "https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/dns.txt",
    "Malicious URL Blocklist": "https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt",
    "xndeye adblock_list": "https://raw.githubusercontent.com/xndeye/adblock_list/refs/heads/release/dns.txt",
    "anti-AD": "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-easylist.txt",
    "AdBlock DNS Filters": "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt",
    "ABP": "https://raw.githubusercontent.com/damengzhu/abpmerge/refs/heads/main/abpmerge.txt",
    "那个谁520": "https://raw.githubusercontent.com/qq5460168/666/master/rules.txt",
    "oisd/small": "https://small.oisd.nl/",
    "乘风广告规则": "https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/refs/heads/master/rule.txt",
    "本地规则": "https://raw.githubusercontent.com/Logic769/Adguardhome-local-rules/main/blacklist.txt"
}

white_source_urls = {
    "本地规则": "https://raw.githubusercontent.com/Logic769/Adguardhome-local-rules/main/whitelist.txt"
}

# 保留「拦截语义」的修饰符：带这些修饰符的规则仍然拦截，只是修饰符本身无法写进纯域名输出
KEEP_MODIFIERS = {'important', 'dnsrewrite'}
# 否定语义修饰符：出现即丢弃整条规则
DROP_MODIFIERS = {'badfilter'}
# 采纳上游例外的上限：被拦截的上游源数达到此值即视为「公认拦截目标」，不采纳例外
EXCEPTION_MAX_BLOCK_SOURCES = 3

# 广告 / 追踪特征词：用于判断上游 @@ 例外是否值得采纳
AD_MARKERS = re.compile(
    r'(^|[.\-_])(ad|ads|adx|adnxs|adsystem|adservice|adserver|advert|advertis\w*|adv|adz|'
    r'adclick|adlog|adtrack|adtech|adview|admaster|adpop|adpush|'
    r'doubleclick|googlesyndication|googleadservices|google-analytics|googletagmanager|'
    r'analytics|analytic\w*|analysis|stat|stats|statistic\w*|cnzz|umeng|talkingdata|'
    r'mmstat|alimama|tanx|simba|miaozhen|ipinyou|admaster|'
    r'adjust|appsflyer|kochava|singular|tenjin|countly|flurry|bugly|crashlytics|'
    r'track|tracker|tracking|click|clk|beacon|pixel|metric\w*|monitor\w*|collect|collector|telemetry|'
    r'promo|promotion|sponsor|affiliate|aff|dsp|ssp|rtb|'
    r'mopub|inmobi|unityads|applovin|vungle|chartboost|ironsrc|mintegral|pangle|gdt|mobads|'
    r'log|logs|logger)([.\-_]|$)', re.I)

# 核心服务保护名单：无论上游怎么写都永不拦截
NEVER_BLOCK = {
    # Apple 系统更新 / 证书
    "mesu.apple.com", "swscan.apple.com", "swcdn.apple.com", "gdmf.apple.com",
    "appldnld.apple.com", "ocsp.apple.com", "ocsp2.apple.com", "crl.apple.com",
    "doh.dns.apple.com", "captive.apple.com",
    # Windows / 微软
    "dns.msftncsi.com", "msftconnecttest.com", "www.msftconnecttest.com",
    "crl.microsoft.com", "www.microsoft.com", "update.microsoft.com",
    "windowsupdate.microsoft.com", "licensing.mp.microsoft.com",
    # Android / Google 推送与基础服务
    "mtalk.google.com", "alt1-mtalk.google.com", "alt2-mtalk.google.com",
    "alt3-mtalk.google.com", "alt4-mtalk.google.com", "alt5-mtalk.google.com",
    "alt6-mtalk.google.com", "alt7-mtalk.google.com", "alt8-mtalk.google.com",
    # 公共加密 DNS
    "doh.pub", "dot.pub", "dns.qq.com", "doh.alidns.com", "dns.alidns.com",
    "mozilla.cloudflare-dns.com", "cloudflare-dns.com", "dns.google",
    "one.one.one.one", "dns.quad9.net",
    # NTP 对时
    "pool.ntp.org", "cn.pool.ntp.org", "0.android.pool.ntp.org",
    "1.android.pool.ntp.org", "2.android.pool.ntp.org", "3.android.pool.ntp.org",
    "time.windows.com", "time.apple.com", "ntp.aliyun.com", "ntp.tencent.com",
    # 连通性检测（被拦后系统/App 会显示「无网络」）
    "connectivitycheck.gstatic.com", "connectivitycheck.android.com",
    "connectivitycheck.platform.hicloud.com", "connectivitycheck.platform.dbankcloud.com",
    "connectivitycheck.cbg-app.huawei.com.cn", "connectivitycheck.vivo.com.cn",
    # 证书吊销检查
    "crl.edge.digicert.com", "ocsp.godaddy.com", "ocsp.crlocsp.cn",
    "crl.globalsign.com", "ocsp.sectigo.com",
    # 阿里系 App 网络/风控（ACS/JMACS/MSGACS/AMDC）：被拦后淘宝、天猫、天猫校园等
    # 系 App 会判定为「无网络」，且这些接口不承载广告
    "acs.m.taobao.com", "acs.wapa.taobao.com", "acs4baichuan.m.taobao.com",
    "acs4public.m.taobao.com", "openacs.m.taobao.com", "openacs4uc.m.taobao.com",
    "openjmacs.m.taobao.com", "openjmacs4uc.m.taobao.com",
    "accscdn.m.taobao.com", "accscdn4public.m.taobao.com",
    "amdcopen.m.taobao.com", "amdc.alipay.com",
    "gaode-acs.m.taobao.com", "gaode-jmacs.m.taobao.com",
    "xjp-jmacs.m.taobao.com", "xjp-msgacs.m.taobao.com",
    "youku-acs.m.taobao.com", "youku-jmacs.m.taobao.com",
    "umengacs.m.taobao.com", "umengjmacs.m.taobao.com", "unitacs.m.taobao.com",
    # 注意：不要放行 w.m.taobao.com —— 它的 CNAME 指向
    # adsz.wagbridge.taobao.alimama.com（阿里妈妈广告投放网关），拦截是正确的
    "gw.tmall.com", "mapi.m.taobao.com", "mtop.taobao.com",
    # 支付 / 账号关键接口
    "paydns.wechatpay.cn", "api-unionid.meituan.com",
    # 手机厂商系统接口（安全/账号/游戏中心，被拦会导致 App 功能异常）
    "api.miui.security.xiaomi.com", "api.sec.miui.com", "api.sec.intl.miui.com",
    "api.developer.xiaomi.com", "api.comm.miui.com", "sec-cdn.static.xiaomi.net",
    "api-cn.cdo.heytapmobi.com",
    "api-push.meizu.com", "api-game.meizu.com", "aider-res.meizu.com",
    "game.res.meizu.com", "gateway.kugou.com",
    # 短信验证码（被拦会导致登录/注册收不到码）
    "auth.wosms.cn", "code.sms.mob.com", "sdkapi.sms.mob.com",
    # 推送通道
    "api.tuisong.baidu.com", "push.m.youku.com", "sdk.open.talk.gepush.com",
    # 贴吧/百度 静态资源（拦了会让 App 缺图少样式）
    "tieba-ares.cdn.bcebos.com", "static.tieba.baidu.com",
    "staticsns.cdn.bcebos.com", "pic.rmb.bdstatic.com",
    # 其它常见静态资源 / 工具
    "bbs-static.miyoushe.com", "static-res.qq.com", "cdn.yyb.gtimg.com",
    "s.img.mix.sina.com.cn", "bucket-ynote-online-cdn.note.youdao.com",
    "e.weather.com.cn", "dl.zuimeitianqi.com",
}

# 「整个域名空间拦截」名单：以 AdGuard 网络语法 `||域名^` 输出，连**所有子域**一起拦。
#
# 为什么需要它：部分广告/追踪域名用「随机哈希子域」轮换（例如
# 9e59f633….rdt.tfogc.com、4848fd4d….jomoxc.com），纯域名的精确匹配永远追不上；
# 上游名单也只能拦到当时那一批哈希值。
# `||example.com^` 在 AdGuard 里本身就覆盖 example.com 及其全部子域，
# 所以这里只写父域名即可。这些行**不能带行尾注释**（网络规则不剥离 `#` 注释），
# 因此单独成段输出。
BLOCK_DOMAIN_SPACES = [
    # 贴吧/百度信息流广告：随机哈希子域轮换（上游只拦到具体哈希）
    "rdt.tfogc.com",
    "jomoxc.com",
    # general.starrydyn.com 的 CNAME 指向 x.starrydyn.11101.baidu-itm.com（百度流量/广告基建）
    "starrydyn.com",
    # 百度广告资源域：纯域名只拦得到 sofire.baidu.com 本身，
    # App 实际请求的是 factors.sofire.baidu.com 这类子域（实测漏拦）
    "sofire.baidu.com",
    "sofire.bdstatic.com",
    # 广告 SDK 商（避免其后续新增子域再次漏拦）
    "litemob.net",
    "lingjuad.com",
    "luckas.cn",
    "8ziben.com",
    # YY 广告联盟
    "union-dracoapi.yy.com",
]

# 常见多级公共后缀（兜底用；优先使用在线 PSL）
PSL_FALLBACK = {
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn", "co.jp", "ne.jp",
    "or.jp", "ac.jp", "go.jp", "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk",
    "com.hk", "org.hk", "edu.hk", "gov.hk", "com.tw", "org.tw", "edu.tw",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.kr", "or.kr", "com.br",
    "com.mx", "com.sg", "com.my", "com.tr", "com.ru", "co.in", "co.nz", "com.ua",
}

block_filename = os.environ.get("OUTPUT_BLOCK_FILENAME", "Black.txt")
white_filename = os.environ.get("OUTPUT_WHITE_FILENAME", "White.txt")
conflict_filename = os.environ.get("OUTPUT_CONFLICT_FILENAME", "Conflict.txt")
block_output_file = os.path.join(root_dir, block_filename)
white_output_file = os.path.join(root_dir, white_filename)
conflict_output_file = os.path.join(root_dir, conflict_filename)

readme_title = os.environ.get("README_TITLE", "激进的规则")
release_tag = os.environ.get("RELEASE_TAG")
AUTHOR = "logic769"

DOMAIN_RE = re.compile(
    r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$')
IPV4_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')

stats = {
    "kept": 0, "kept_scoped_ad": 0, "dropped_context": 0, "dropped_badfilter": 0,
    "exc_global": 0, "exc_scoped_dropped": 0, "exc_ad_ignored": 0,
    "invalid": 0, "regex_skipped": 0, "cosmetic_skipped": 0, "comment_skipped": 0,
}


@dataclass
class ParsedRule:
    domain: str
    is_whitelist: bool
    modifiers: list
    original_line: str
    source: str


def load_public_suffixes() -> set:
    """拉取公共后缀列表；失败则用内置兜底集合。"""
    try:
        resp = requests.get(
            "https://publicsuffix.org/list/public_suffix_list.dat",
            headers={"User-Agent": "Mozilla/5.0 (GitHub Actions)"}, timeout=60)
        resp.raise_for_status()
        suffixes = set()
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            if line.startswith("!"):
                suffixes.add(line[1:].lower())
            else:
                suffixes.add(line.lower())
        if suffixes:
            print(f"  已加载公共后缀 {len(suffixes)} 条")
            return suffixes
    except requests.exceptions.RequestException as e:
        print(f"  公共后缀列表下载失败({e})，使用内置兜底集合")
    return set(PSL_FALLBACK)


def extract_domain(raw: str) -> Optional[str]:
    """从规则文本中提取域名，无法忠实表达时返回 None。"""
    s = raw.strip()
    if not s:
        return None

    # hosts 语法：0.0.0.0 example.com / 127.0.0.1 example.com
    parts = s.split()
    if len(parts) >= 2 and (parts[0] in {"0.0.0.0", "127.0.0.1", "::", "::1"}
                            or IPV4_RE.match(parts[0])):
        s = parts[1]
    elif len(parts) > 1:
        # 含空格的其它形式无法忠实表达
        return None

    if s.startswith("||"):
        s = s[2:]
    elif s.startswith("|"):
        s = s[1:]
    if s.endswith("^"):
        s = s[:-1]

    if s.startswith("*."):
        s = s[2:]
    if s.startswith("."):
        s = s[1:]

    if '/' in s or '<' in s or '>' in s or '~' in s or '|' in s or '^' in s or '*' in s:
        return None

    s = s.strip().strip('.').lower()
    if not s or '.' not in s:
        return None
    if IPV4_RE.match(s) or ':' in s:
        return None
    # 注意：AdGuard Home 的域名校验不允许下划线（urlfilter/internal/ufnet hasValidChars
    # 只接受字母/数字/连字符），含下划线的行会被当成 URL 子串规则并连带行尾注释一起
    # 解析，等于永不生效，所以这里直接剔除（例如 recommend_list.baidu.com）。
    if '_' in s:
        return None
    if not DOMAIN_RE.match(s):
        return None
    return s


def parse_line(line: str, source: str = "") -> Optional[ParsedRule]:
    line = line.strip()

    if not line:
        return None
    if line.startswith(('!', '#')):
        stats["comment_skipped"] += 1
        return None
    if '##' in line or line.startswith(('#@#', '#?#')):
        stats["cosmetic_skipped"] += 1
        return None
    if line.startswith('/'):
        stats["regex_skipped"] += 1
        return None
    if line.startswith('['):
        return None

    is_whitelist = line.startswith('@@')
    if is_whitelist:
        line = line[2:]

    modifiers = []
    if '$' in line:
        line, modifier_str = line.split('$', 1)
        for mod in modifier_str.split(','):
            mod = mod.strip()
            if mod:
                modifiers.append(mod)

    names = [m.split('=')[0].lstrip('~').lower() for m in modifiers]

    # 否定语义：绝不能当拦截执行
    if any(n in DROP_MODIFIERS for n in names):
        stats["dropped_badfilter"] += 1
        return None

    domain = extract_domain(line)
    if not domain:
        stats["invalid"] += 1
        return None

    # 上下文修饰符（$domain= / $third-party / $script / $path= ...）在 DNS 层无法表达。
    # 但如果规则的目标域名本身就是广告/追踪端点，保留它作为全局拦截是符合本名单目的的
    # （也维持了修复前的拦截强度）；否则必须丢弃，否则会把「只在某站点生效」的规则
    # 放大成全局拦截——这正是历史上最主要的误杀来源。
    unknown = [n for n in names if n not in KEEP_MODIFIERS]
    if unknown:
        if not is_whitelist and AD_MARKERS.search(domain):
            stats["kept_scoped_ad"] += 1
        else:
            stats["dropped_context"] += 1
            return None

    stats["exc_global" if is_whitelist else "kept"] += 1
    return ParsedRule(domain=domain, is_whitelist=is_whitelist,
                      modifiers=modifiers, original_line=line, source=source)


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


def process_source_to_rules(url: str, source_name: str, psl: set,
                            force_whitelist: bool = False):
    """处理单个规则源，返回 (黑名单字典, 白名单字典)。

    force_whitelist=True 时（白名单源），该源的所有条目都按白名单处理，
    避免白名单源里写成纯域名的条目被误当成拦截规则。
    """
    content = download_file(url, source_name)
    if not content:
        return {}, {}

    block_rules: dict = {}
    white_rules: dict = {}
    mixed_detected = False

    for line in content.splitlines():
        parsed = parse_line(line, source_name)
        if not parsed:
            continue
        # 公共后缀（com.cn 之类）永远匹配不到具体主机，直接丢弃
        if parsed.domain in psl:
            stats["invalid"] += 1
            continue

        if parsed.is_whitelist or force_whitelist:
            white_rules[parsed.domain] = source_name
            if parsed.is_whitelist:
                mixed_detected = True
        else:
            block_rules[parsed.domain] = source_name

    if mixed_detected:
        print(f"  [混合规则检测] {source_name} 含 @@ 例外，已分离到白名单")

    print(f"  从 {source_name} 添加了 {len(block_rules)} 条黑名单, {len(white_rules)} 条白名单")
    return block_rules, white_rules


def process_all_sources(urls_dict: dict, psl: set, force_whitelist: bool = False):
    all_block_rules: dict = {}
    all_white_rules: dict = {}
    block_source_counts: dict = {}   # 域名 -> 有多少个源把它列为拦截

    for name, url in urls_dict.items():
        block_rules, white_rules = process_source_to_rules(
            url, name, psl, force_whitelist=force_whitelist)

        for rule, source in block_rules.items():
            block_source_counts[rule] = block_source_counts.get(rule, 0) + 1
            if rule not in all_block_rules:
                all_block_rules[rule] = source

        for rule, source in white_rules.items():
            if rule not in all_white_rules:
                all_white_rules[rule] = source

        time.sleep(1)

    return all_block_rules, all_white_rules, block_source_counts


def merge_rules(*rule_dicts: dict) -> dict:
    merged: dict = {}
    for rules_dict in rule_dicts:
        for rule, source in rules_dict.items():
            if rule not in merged:
                merged[rule] = source
    return merged


def find_conflict_rules(block_rules: dict, white_rules: dict) -> dict:
    conflict_rules = {}
    for rule, block_source in block_rules.items():
        if rule in white_rules:
            conflict_rules[rule] = (block_source, white_rules[rule])
    return conflict_rules


def write_rules_to_file(filename: str, rules_dict: dict, title: str,
                        description: str, author: str, domain_spaces=None):
    print(f"\n正在将规则写入到 {os.path.basename(filename)}...")
    domain_spaces = domain_spaces or []
    try:
        with open(filename, "w", encoding="utf-8") as f:
            beijing_tz = datetime.timezone(datetime.timedelta(hours=8))
            now_beijing = datetime.datetime.now(beijing_tz)

            f.write(f"! Title: {title}\n")
            f.write(f"! Description: {description}\n")
            f.write(f"! Author: {author}\n")
            f.write(f"! Version: {now_beijing.strftime('%Y%m%d%H%M%S')}\n")
            f.write(f"! Last Updated: {now_beijing.strftime('%Y-%m-%d %H:%M:%S')} (UTC+8)\n")
            f.write(f"! Total Rules: {len(rules_dict) + len(domain_spaces)}\n")
            f.write("!\n")

            # 域名空间规则（含子域）必须写在最前面，且**不能带行尾注释**：
            # AdGuard 的网络规则不会剥离行尾 `#`，带了注释整条就失效了。
            if domain_spaces:
                f.write("!\n! ==== 域名空间拦截（含全部子域，AdGuard 网络语法）====\n")
                for d in sorted(domain_spaces):
                    f.write(f"||{d}^\n")
                f.write("!\n")

            for rule in sorted(rules_dict):
                if isinstance(rules_dict[rule], tuple):
                    block_source, white_source = rules_dict[rule]
                    f.write(f"{rule} # Block from: {block_source}, White from: {white_source}\n")
                else:
                    f.write(f"{rule} # From: {rules_dict[rule]}\n")
        print(f"文件 {os.path.basename(filename)} 写入成功！"
              f"（含 {len(domain_spaces)} 条域名空间规则）")
    except IOError as e:
        print(f"写入文件失败: {filename}, 错误: {e}")


def update_readme(block_rules_dict: dict, white_rules_dict: dict, conflict_rules_dict: dict):
    print("\n正在更新 README.md...")
    repo_name = os.environ.get("GITHUB_REPOSITORY", "your_username/your_repo")
    branch_name = os.environ.get("GITHUB_REF_NAME") or "main"

    if release_tag:
        base_url = f"https://github.com/{repo_name}/releases/latest/download"
    else:
        base_url = f"https://raw.githubusercontent.com/{repo_name}/{branch_name}"

    beijing_tz = datetime.timezone(datetime.timedelta(hours=8))
    now_beijing = datetime.datetime.now(beijing_tz)

    all_block_sources = list(block_source_urls.keys())
    all_white_sources = list(white_source_urls.keys())

    block_sources_md = "\n".join([f"- {name}" for name in all_block_sources])
    white_sources_md = "\n".join([f"- {name}" for name in all_white_sources])

    code_fence = "```"

    readme_content = f"""# {readme_title}

# 自动更新的 AdGuard Home 规则

项目作者: {AUTHOR}

本项目通过 GitHub Actions 自动合并、去重多个来源的 AdGuard Home 规则。
支持自动检测并分离上游规则中的混合黑白名单。
黑白名单完全独立，同时存在的规则会单独列在冲突规则中。

最后更新时间: {now_beijing.strftime('%Y-%m-%d %H:%M:%S')} (UTC+8)

最终黑名单规则数: {len(block_rules_dict)}（另有 {len(BLOCK_DOMAIN_SPACES)} 条域名空间规则，含全部子域）

最终白名单规则数: {len(white_rules_dict)}

冲突规则数: {len(conflict_rules_dict)}

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

## 规则语义（重要）

本仓库输出的规则是**纯域名行**，AdGuard Home 会按 hosts 型规则处理，
匹配方式是**精确主机名相等**（`urlfilter/dnsengine.go` 中的 `ruleIndex[hostname]`）。
也就是说 `example.com` 只会拦截对 `example.com` 本身的查询，不会拦截子域。

为避免误杀，构建时对上游规则做了**忠实化处理**（详见 `documents/process_rules.py` 文件头）：

- 丢弃带上下文修饰符的规则（`$domain=`、`$third-party`、`$script`、`$path=` 等）：
  这些条件在 DNS 层无法表达，保留域名会让「只在某站点生效」的规则变成全局拦截。
- 丢弃 `$badfilter`（取消规则）——它是否定语义，不能当作拦截执行。
- 采纳上游**无修饰符的全局例外**时要求该域名「有争议」：被 3 个以上独立名单共同
  拦截的域名不采纳任何单个名单的例外（部分名单自带近 3000 条私人白名单，
  照单全收会把 `als.baidu.com`（17 个源拦）、`nsclick.baidu.com`（16 个源拦）
  这类公认广告域放行，实测导致贴吧广告回流）。
- 域名统一小写并严格校验，剔除裸 IP、下划线、首尾点、通配符与公共后缀
  （下划线在 AdGuard 的域名校验里非法，此类规则在 AGH 中永远不会生效）。
- **核心服务保护名单**：系统更新、连通性检测（被拦会显示「无网络」）、推送通道、
  加密 DNS、证书吊销、NTP，以及阿里系 App 的 ACS/JMACS/MSGACS 网络与风控接口，
  无论上游怎么写都永不拦截。
- **域名空间拦截**（文件开头 `==== 域名空间拦截（含全部子域）====` 段，
  当前 {len(BLOCK_DOMAIN_SPACES)} 条）：以 AdGuard 网络语法 `||域名^` 输出，
  连**全部子域**一起拦。纯域名是精确主机名匹配，父域拦不住子域——实测
  `sofire.baidu.com` 拦住了，但 App 请求的是 `factors.sofire.baidu.com`；
  轮换哈希域（`9e59f633….rdt.tfogc.com`）更是永远追不上。这些行**不带行尾注释**：
  AdGuard 的网络规则不剥离 `#`，带了注释整条就失效。

本次构建统计：保留 {stats['kept']} 条（其中带上下文修饰符但目标本身是广告域的 {stats['kept_scoped_ad']} 条），
丢弃上下文规则 {stats['dropped_context']} 条，丢弃 badfilter {stats['dropped_badfilter']} 条，
采纳全局例外 {stats['exc_global']} 条，忽略带广告特征的上游例外 {stats['exc_ad_ignored']} 条，
剔除无效域名 {stats['invalid']} 条。

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
    print("AdGuard Home 规则处理脚本（忠实化版）")
    print("=" * 60)

    psl = load_public_suffixes()

    print("\n--- 第一步: 处理白名单规则源 ---")
    _wsb, white_source_white, _ = process_all_sources(
        white_source_urls, psl, force_whitelist=True)

    print("\n--- 第二步: 处理黑名单规则源 ---")
    block_source_block, block_source_white, block_counts = process_all_sources(
        block_source_urls, psl)

    print("\n--- 第三步: 合并所有规则 ---")
    # 白名单 = 白名单源 + 黑名单源里混着的 @@ 例外（后者本仓库以前是丢弃的）
    all_white_rules = merge_rules(white_source_white, block_source_white)
    # 白名单源里不会产出拦截规则；这里仅合并黑名单源
    all_block_rules = merge_rules(block_source_block)
    assert not _wsb, "白名单源不应产出拦截规则"

    print(f"  合并后黑名单共: {len(all_block_rules)} 条")
    print(f"  合并后白名单共: {len(all_white_rules)} 条")

    print("\n--- 第四步: 应用核心服务保护名单与白名单 ---")
    protected_in_black = sorted(d for d in all_block_rules if d in NEVER_BLOCK)
    for d in protected_in_black:
        all_white_rules.setdefault(d, "核心服务保护名单")
        del all_block_rules[d]
    print(f"  核心服务保护名单命中并放行: {len(protected_in_black)} 条")

    ad_exceptions = sorted(
        d for d in all_white_rules
        if all_white_rules[d] != "本地规则"       # 用户自己的白名单永远优先
        and d not in NEVER_BLOCK
        and (AD_MARKERS.search(d)                # 名字就是广告/追踪特征
             # 或：被 3 个以上独立名单共同拦截 => 公认拦截目标，不采纳单个名单的例外
             or block_counts.get(d, 0) >= EXCEPTION_MAX_BLOCK_SOURCES))
    for d in ad_exceptions:
        del all_white_rules[d]
    stats["exc_ad_ignored"] = len(ad_exceptions)
    print(f"  被忽略的上游例外(广告特征或≥{EXCEPTION_MAX_BLOCK_SOURCES}源共识): "
          f"{len(ad_exceptions)} 条")

    print("\n--- 第五步: 检测冲突规则 ---")
    conflict_rules = find_conflict_rules(all_block_rules, all_white_rules)
    print(f"  检测到 {len(conflict_rules)} 条冲突规则（同时存在于黑名单和白名单）")

    # 白名单优先：冲突条目从黑名单中剔除，避免只订阅黑名单时仍然误杀
    for rule in conflict_rules:
        all_block_rules.pop(rule, None)
    print(f"  冲突条目已从黑名单移除，剩余黑名单: {len(all_block_rules)} 条")

    # 白名单只保留真正起作用的条目：
    #   ① 用户本地白名单（always 发布）
    #   ② 核心服务保护名单里确实被上游拦过的
    #   ③ 与黑名单冲突、需要放行的
    # 其余「上游全局例外」如果本来就没被任何黑名单命中，放进来也没有任何效果，只会撑大文件。
    effective_white: dict = dict(white_source_white)
    for d in protected_in_black:
        effective_white.setdefault(d, "核心服务保护名单")
    for d, src in all_white_rules.items():
        if d in conflict_rules:
            effective_white.setdefault(d, src)
    trimmed = len(all_white_rules) - len(effective_white)
    all_white_rules = effective_white
    print(f"  白名单裁剪掉不产生效果的条目: {trimmed} 条")

    print("\n最终统计:")
    print(f"  最终黑名单: {len(all_block_rules)} 条 "
          f"(另有 {len(BLOCK_DOMAIN_SPACES)} 条域名空间规则)")
    print(f"  最终白名单: {len(all_white_rules)} 条")
    print(f"  冲突规则: {len(conflict_rules)} 条")
    print(f"  解析统计: {stats}")

    write_rules_to_file(
        block_output_file, all_block_rules,
        "AdGuard Custom Blocklist",
        "自动合并的广告拦截规则（与白名单完全独立）", AUTHOR,
        domain_spaces=BLOCK_DOMAIN_SPACES)
    write_rules_to_file(
        white_output_file, all_white_rules,
        "AdGuard Custom Whitelist",
        "自动合并的白名单规则（与黑名单完全独立）", AUTHOR)
    write_rules_to_file(
        conflict_output_file, conflict_rules,
        "AdGuard Conflict Rules",
        "同时存在于黑名单和白名单的规则", AUTHOR)

    update_readme(all_block_rules, all_white_rules, conflict_rules)

    print("\n" + "=" * 60)
    print("规则处理完成！")
    print("=" * 60)


if __name__ == "__main__":
    main()
