import requests
import datetime
import os
import re
import sys
import time
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
"困了想睡觉":"https://raw.githubusercontent.com/Kuner-mw/DNS-Kuner/main/FilterRules/blacklist.txt",
"海哥":"https://raw.githubusercontent.com/2771936993/HG/main/hg1.txt",
"natsuki":"https://raw.githubusercontent.com/Natsuki-Kaede/Natsuki-List/refs/heads/main/adguardhome.txt",
    "DD自用": "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt",
    "smad": "https://raw.githubusercontent.com/2Gardon/SM-Ad-FuckU-hosts/refs/heads/master/SMAdHosts",
    "大萌主": "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt",
    "10007": "https://raw.githubusercontent.com/lingeringsound/10007_auto/master/adb.txt",
    "逆向涉猎": "https://raw.githubusercontent.com/rssvcn/qy-Ads-Rule/main/black.txt",
    "neodavhost": "https://raw.githubusercontent.com/neodevpro/neodevhost/master/adblocker",
    "adsethost": "https://raw.githubusercontent.com/rentianyu/Ad-set-hosts/master/adguard",
    "1hosts": "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/adblock.txt",
    "茯苓的广告规则": "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/main/FuLingRules/FuLingBlockList.txt",
    "GOODBYEADS": "https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/dns.txt",
    "AdGuard DNS filter": "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
    "Malicious URL Blocklist": "https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt",
    "xndeye adblock_list": "https://raw.githubusercontent.com/xndeye/adblock_list/refs/heads/release/dns.txt",
    "anti-AD": "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-easylist.txt",
    "AdBlock DNS Filters": "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt",
    "hagezi Pro": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
    "ABP": "https://raw.githubusercontent.com/damengzhu/abpmerge/refs/heads/main/abpmerge.txt",
    "那个谁520": "https://raw.githubusercontent.com/qq5460168/666/master/rules.txt",
    "oisd/big": "https://big.oisd.nl/",
    # 2026-10 新增 5 源：全部是「更新快 + 与上面 24 源重叠低」的增量源
    #   Phishing Army        每 4 小时重建（聚合 9 家钓鱼库）
    #   ShadowWhisperer      Malware / Tracking 两类，Tracking 是广告类增量最大的一支
    #   BlocklistProject     Scam（诈骗站）
    #   HaGeZi Encrypted DNS 专门收录 DoH/DoT 端点，用于防客户端绕过本机过滤
    "Phishing Army": "https://phishing.army/download/phishing_army_blocklist_extended.txt",
    "ShadowWhisperer Malware": "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Malware",
    "ShadowWhisperer Tracking": "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Tracking",
    "BlocklistProject Scam": "https://blocklistproject.github.io/Lists/scam.txt",
    "HaGeZi Encrypted DNS": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/doh.txt",
    "本地规则": "https://raw.githubusercontent.com/Logic769/Adguardhome-local-rules/main/blacklist.txt"
}

white_source_urls = {
    "本地规则": "https://raw.githubusercontent.com/Logic769/Adguardhome-local-rules/main/whitelist.txt"
}

# 保留「拦截语义」的修饰符：带这些修饰符的规则仍然拦截，只是修饰符本身无法写进纯域名输出
KEEP_MODIFIERS = {'important', 'dnsrewrite'}
# 否定语义修饰符：出现即丢弃整条规则
DROP_MODIFIERS = {'badfilter'}
# 用户本地名单在源表里的名字（本地黑名单、本地白名单都用它）
LOCAL_SOURCE_NAME = "本地规则"
# 采纳上游例外的上限：被拦截的上游源数达到此值即视为「公认拦截目标」，不采纳例外
EXCEPTION_MAX_BLOCK_SOURCES = 3

# ============================================================================
# 「知名站点护栏」：只作用于下面 TOP_GUARD_SOURCES 里的新源
# ----------------------------------------------------------------------------
# 背景：Phishing Army / ShadowWhisperer / BlocklistProject 这类**聚合型**名单会把
# 整个二级主域写进去（例如 amap.com、hao123.com、t.cn、bitly.com、tinyurl.com）。
# 对纯拦截器来说这没问题，但本仓库是给「全家在用」的公共 DNS 服务的：
# 拦掉 amap.com 就是高德地图不能定位，拦掉 t.cn/tinyurl 就是别人发来的短链全废。
#
# 实测：不设护栏时 5 个新源会额外拦掉 OpenDNS top10000 里的 244 个真实站点。
# 护栏口径 = 精确命中 top10000 任意一条就不收录（含 google.co.in 这类多级后缀）。
# 注意：只保护**域名本身**，不保护其子域——ads.google.com 这类广告子域照常拦。
# 老源不套用护栏，避免改变既有输出。
# ============================================================================
TOP_GUARD_SOURCES = {
    "Phishing Army",
    "ShadowWhisperer Malware",
    "ShadowWhisperer Tracking",
    "BlocklistProject Scam",
    "HaGeZi Encrypted DNS",
}
TOP_DOMAINS_FILE = os.path.join(script_dir, "top-domains.txt")
TOP_DOMAINS: set = set()

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
    # 广告 SDK：以前漏了 sdk，导致 sdk-api.beizi.biz、pangolin-sdk-toutiao.com
    # 这类明确的广告 SDK 域既不被识别为广告、其上游例外还会被采纳
    r'sdk|sdkapi|bid|union|report\w*|impression\w*|'
    r'mopub|inmobi|unityads|applovin|vungle|chartboost|ironsrc|mintegral|pangle|gdt|mobads|'
    r'log|logs|logger)([.\-_]|$)', re.I)

# 核心服务保护名单：无论上游怎么写都永不拦截
NEVER_BLOCK = {
    # Apple 系统更新 / 证书
    "mesu.apple.com", "swscan.apple.com", "swcdn.apple.com", "gdmf.apple.com",
    "appldnld.apple.com", "ocsp.apple.com", "ocsp2.apple.com", "crl.apple.com",
    # 注：doh.dns.apple.com 不在保护名单里 —— 用户本地黑名单明确要拦它（防 DoH 绕过过滤）
    "captive.apple.com",
    # Windows / 微软
    "dns.msftncsi.com", "msftconnecttest.com", "www.msftconnecttest.com",
    "crl.microsoft.com", "www.microsoft.com", "update.microsoft.com",
    "windowsupdate.microsoft.com", "licensing.mp.microsoft.com",
    # Android / Google 推送与基础服务
    "mtalk.google.com", "alt1-mtalk.google.com", "alt2-mtalk.google.com",
    "alt3-mtalk.google.com", "alt4-mtalk.google.com", "alt5-mtalk.google.com",
    "alt6-mtalk.google.com", "alt7-mtalk.google.com", "alt8-mtalk.google.com",
    # 公共加密 DNS
    # 注：dns.qq.com 不在保护名单里 —— 用户本地黑名单明确要拦它（DoH 会绕过本 DNS 过滤）
    "doh.pub", "dot.pub", "doh.alidns.com", "dns.alidns.com",
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
    # 2026-10-26 新增 5 个聚合源后的回归：ShadowWhisperer Tracking 把
    # Google 安全浏览（Safe Browsing）整族当追踪端点拦了。Safe Browsing 是
    # Chrome / Android / Safari 判断「这个网址是不是钓鱼/挂马」的安全能力，
    # 拦掉之后浏览器失去恶意站点告警 —— 这是安全降级，不是去广告。
    "safebrowsing.google.com", "alt1-safebrowsing.google.com",
    "alt2-safebrowsing.google.com", "android-safebrowsing.google.com",
    "safebrowsing-cache.google.com", "safebrowsing.cache.l.google.com",
    "sb-ssl.google.com", "safebrowsingohttpgateway.googleapis.com",
    "google-ohttp-relay-safebrowsing.fastly-edge.com",
    "ohttp-relay-safebrowsing-android.google.fastly-edge.com",
    "ohttp-relay-safebrowsing-chrome.google.fastly-edge.com",
    # A-GPS 辅助定位（拦了会导致 Android 冷启动定位变慢／失败）
    "supl.google.com",
    # Apple 定位服务 / 地图 / 图片 CDN（2026-10-27 实探 CNAME 确认是功能性主机，
    # 不是埋点：gsp*-ssl -> gsp*.ls-apple.com.akadns.net（定位服务），
    # cl1/cl2/cl3 -> applemaps.qtlcdn.com（地图切片/内容），
    # iphone-ld -> gsp*.aaplimg.com（图片资源）。
    # 注：同批被拦的 Apple 反馈/诊断类（cstat、iphonediags、cssubmissions、
    # radarsubmissions、littlebuddy、appleseed、feedback 等）**故意不保护**，
    # 那些是「向 Apple 回传」的通道，拦掉正是想要的。
    "gsp1-ssl.apple.com", "gsp2-ssl.apple.com", "gsp3-ssl.apple.com",
    "gsp8-ssl.apple.com", "gsp9-ssl.apple.com", "gsp10-ssl.apple.com",
    "cl1.apple.com", "cl2.apple.com", "cl3.apple.com",
    "iphone-ld.apple.com",
    # 公共 DNS 的等价别名：上面保护 dns.google，这里补上它的同义域名，
    # 否则会出现「dns.google 放行但 dns.google.com 被拦」的不一致
    "dns.google.com", "google-public-dns-a.google.com", "google-public-dns-b.google.com",
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
    # 哔哩哔哩直播弹幕 / 核心接口（2026-10-26 实测：这些主机被上游源当埋点拦掉，
    # 结果弹幕长连接直接断。注意它们名字里带 chat / broadcast，很容易被误认成埋点，
    # 实际是长连接入口 —— chat.bilibili.com CNAME -> broadcastlv-sh.chat.biliapi.com）
    "chat.bilibili.com", "broadcast.chat.bilibili.com",
    "broadcast.chat.biliapi.com", "broadcastlv.chat.bilibili.com",
    "broadcastlv-sh.chat.biliapi.com",
    # interface.bilibili.com 是 API 网关别名（301 -> www.bilibili.com）
    "interface.bilibili.com",
    # boss.hdslb.com 是 B 站对象存储桶（实测返回 401 UnauthorizedAccess 而非 NoSuchBucket）
    "boss.hdslb.com",
    # 贴吧/百度 静态资源（拦了会让 App 缺图少样式）
    # 注：staticsns.cdn.bcebos.com 已移出保护名单 —— 它是一个 BCE 存储桶，
    # 你自己在本地黑名单里明确要拦、且有 6 个上游源共同拦截，按你的规则执行
    "tieba-ares.cdn.bcebos.com", "static.tieba.baidu.com",
    "pic.rmb.bdstatic.com",
    # 2026-10-26 新增 5 个聚合源后的真实查询重放发现：ShadowWhisperer Tracking
    # 把这两个「名字里带 config / chat 的**配置与站点主机**」当埋点整条拦了。
    # chat.z.ai 是智谱 Z.ai 官网（z.ai 307 -> chat.z.ai，HTTP 200），
    # config.edge.skype.com 是 Skype/Teams 的配置下发端点（返回 JSON 配置）。
    # 两者都不是追踪端点，拦掉是纯误杀。
    "chat.z.ai", "config.edge.skype.com",
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
    # 2026-10-01 复查后逐个核实加入：这些父域已被上游列为拦截，但其子域因
    # 「精确主机名匹配」全部漏网（实测 154 条）；已确认整段都是广告/追踪端点。
    # 注意：像 snssdk.com（字节 API）、pddpic.com（拼多多图床）、voicecloud.cn（讯飞登录）、
    # static.yximgs.com（快手图床）、browser.miui.com（小米浏览器 API）、sms.mob.com（短信验证）
    # 这类「父域被拦但子域是功能接口」的**一律不升级**，否则会重演天猫校园式故障。
    "pangolin-sdk-toutiao.com",   # 穿山甲广告 SDK（13 个源拦）
    "we-stats.com",               # 数据统计/上报，54 个子域（3 个源拦）
    "bloblohub.com",              # 追踪聚合，49 个子域（10 个源拦）
    "irs03.com",                  # 广告/跳转，20 个子域（12 个源拦）
    "112.2o7.net",                # Adobe Analytics（Omniture）埋点，1295 个子域
    "net.daraz.com",              # -access-logs-*.net.daraz.com 埋点（6 个源拦）
    "giocdn.com",                 # GrowingIO 统计 CDN（7 个源拦）
    # 2026-10-26 复查后加入：以下父域都已被上游按「精确主机名」拦进黑名单，
    # 但它们的子域全部漏拦（实测数据来自生产 querylog，已剔除自造测试查询）。
    # 加入前逐个 dig 探活：**子域里没有功能性服务**，整段都是埋点/遥测端点，才写进这里。
    #
    # 反面教训（务必保留）：broadcast.chat.bilibili.com 原本也被列入，
    # 它确实被「海哥」以精确主机名拦着，但真机 dig 显示父域 CNAME 到
    # broadcast.chat.biliapi.com → 122.248.50.173，是 B 站直播弹幕的长连接入口，
    # 升级成 ||broadcast.chat.bilibili.com^ 会直接断弹幕。已剔除。
    # 同理以下父域虽被上游精确拦着、但子域含真实功能，**一律不升级**：
    #   umeng.com / umengcloud.com / getui.com / cnzz.com / wosms.cn / hpplay.cn /
    #   zlink.toutiao.com / pardot.com / adriver.ru / viayoo.com / cdnjtzy.com /
    #   ksapisrv.com / bilibili.cn / bytedance.com / broadcast.chat.bilibili.com
    "clarity.ms",                     # 微软 Clarity：s./t./j./i. 全是 vmss-clarity-ingest 埋点
    "metric.gstatic.com",             # Google DoT 探测遥测：<uuid>-dnsotls-ds.metric.gstatic.com
    "ctobsnssdk.com",                 # 字节 CTO 观测 SDK：toblog./tobapplog./toapplog. 纯日志上报
    "sdk-log.partner.sm.cn",          # 神马搜索 SDK 日志上报
    "log.mmstat.com",                 # 阿里妈妈埋点（gm.mmstat.com 在父域 mmstat.com 下，不受影响）
    "i.posthog.com",                  # PostHog 摄入端点（app.posthog.com 控制台在父域 posthog.com 下，不受影响）
    "nexusedgeio.com",                # 广告跳转，父域 A 记录为空，仅随机子域（aeci*.）有应答
    "dm.gg",                          # 广告跳转，父域与 ad. 子域均无应答
]

# 「自动升级为域名空间」的禁止名单：
# 上游偶尔会写 `||*.pddpic.com^` 这种把**整个平台内容 CDN**一起拦的规则，
# 照做会让 App 没图没视频（实测海哥名单里就有一句 `||*.pddpic.com^`，
# 而「那个谁520」正在放行 img./static./funimg.pddpic.com）。
# 这些域名空间只允许通过上面的手工清单加入，不允许被 ||*.X^ 自动放大。
SPACE_NEVER_PROMOTE = {
    "pddpic.com", "hdslb.com", "alicdn.com", "qhimg.com", "360buyimg.com",
    "douyinpic.com", "xhscdn.com", "sinaimg.com", "gtimg.cn", "qpic.cn",
    "bdstatic.com", "himg.com", "yximgs.com", "pstatp.com", "byteimg.com",
    "bytegoofy.com", "bytescm.com", "volccdn.com", "tbcache.com", "taobaocdn.com",
    "alikunlun.com", "myqcloud.com", "jdimg.com", "bytecdntp.com", "ksapisrv.com",
    "dbankcdn.com", "hicloud.com", "bytegeckoext.com", "bytedance.com",
}

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


# 解析过程中收集到的「通配规则」还原结果（全局收集，主流程最后统一使用）
WILDCARD_SPACE_FOUND: set = set()   # 来自 `||*.X^`：父域整段拦截
WILDCARD_ALLOW_FOUND: set = set()   # 来自 `@@||前缀*X^`：把后缀整段放行
# 用户本地黑名单里的域名：优先于一切上游私人白名单
# （实测 alistgo.com / i.meituan.com / www.bytedance.com 曾被「那个谁520」的白名单挤掉）
LOCAL_BLOCK_SET: set = set()
# 每个上游源的贡献统计（写进 README 的「上游名单」表格，每次构建自动刷新）
SOURCE_STATS: list = []
# 抓取失败的源（任何一个源失败都会让构建失败，避免"静默少一个源"）
FAILED_SOURCES: list = []


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


def agh_valid_domain(name: str) -> bool:
    """严格复刻 AdGuard Home urlfilter/internal/ufnet 的域名校验。

    只有通过这里的域名，写成 hosts 型规则才会被 AGH 真正解析成 HostRule；
    否则 AGH 会退化成 URL 子串规则，并连带行尾的 ` # From: xxx` 注释一起解析，
    等于永远不生效（实测产物里有 16 条这样的死规则）。
    TLD 额外要求：长度 ≥2 且首尾都是字母（isValidTLDLabel）。
    """
    if not name or len(name) > 253 or "." not in name:
        return False
    labels = name.split(".")
    for lb in labels[:-1]:
        if not (1 <= len(lb) <= 63) or lb[0] == "-" or lb[-1] == "-":
            return False
        if any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in lb):
            return False
    tld = labels[-1]
    if len(tld) < 2 or not tld[0].isalpha() or not tld[-1].isalpha():
        return False
    if any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in tld):
        return False
    return True


def wildcard_suffix(pattern: str) -> Optional[str]:
    """把「只带一个 * 的通配规则」还原成可用的域名后缀。

    例：`||*.07879.com^` -> 07879.com ；`||storage*360buyimg.com^` -> 360buyimg.com
    含多个 `*`（如 `tnc*-aliec*.zijieapi.com`）无法还原，返回 None。
    """
    if pattern.count("*") != 1:
        return None
    suffix = pattern.split("*", 1)[1]
    if suffix.startswith("."):
        suffix = suffix[1:]
    suffix = suffix.rstrip("^").strip().strip(".")
    suffix = suffix.lower()
    if not suffix or "." not in suffix or "*" in suffix:
        return None
    return suffix if agh_valid_domain(suffix) else None


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
    # 上游手工维护的名单里偶有行尾中文标点（如 `||x.com^、`），
    # 这类规则以前会整条被丢弃
    s = s.rstrip("、，。；;,·． \t")

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
    # 中文域名等 IDN：DNS 查询里只会是 punycode 形式，这里做等价转换
    # （例如 `广告.tmall.com` -> `xn--hoq60d.tmall.com`）
    if any(ord(c) > 127 for c in s):
        try:
            s = s.encode("idna").decode("ascii")
        except (UnicodeError, ValueError):
            stats["invalid"] += 1
            return None
    # 注意：AdGuard Home 的域名校验不允许下划线（urlfilter/internal/ufnet hasValidChars
    # 只接受字母/数字/连字符），含下划线的行会被当成 URL 子串规则并连带行尾注释一起
    # 解析，等于永不生效，所以这里直接剔除（例如 recommend_list.baidu.com）。
    if '_' in s:
        return None
    if not DOMAIN_RE.match(s):
        return None
    if not agh_valid_domain(s):
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

    # 行内注释：`||example.com^$important  # 说明`、`0.0.0.0 example.com  # 说明`
    # 必须在这里剥掉。否则 `# 说明` 会混进修饰符里（变成 "important # 说明"
    # 这种未知修饰符），整条规则被静默丢弃——实测有 8 条白名单因此失效，
    # 而构建日志完全看不出问题。
    if "#" in line:
        cut = re.split(r"\s+#", line, 1)[0].strip()
        if not cut:
            stats["comment_skipped"] += 1
            return None
        line = cut

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
    reclassified = False

    # 通配规则还原（必须在「extract_domain 失败即丢弃」之前处理）：
    #  ① 上游 `||*.X^`：原意是拦 X 的全部子域，纯域名格式会降级成「只拦 X 本身」，
    #     子域全漏 -> 还原成域名空间拦截 `||X^`（实测 298 个父域）
    #  ② 用户自己白名单里「只含一个 *」的放行（@@||storage*360buyimg.com^）
    #     在 DNS 层等于没写 -> 还原成域名空间放行 `@@||360buyimg.com^`
    #     只处理用户自己的名单：上游常见的 `@@||*.4399.com^` 是别人的「整站放行」，
    #     照搬会让广告域跟着放行。
    if not is_whitelist and line.startswith("||*."):
        parent = wildcard_suffix(line)
        if parent:
            WILDCARD_SPACE_FOUND.add(parent)
            domain = domain or parent
    elif is_whitelist and "*" in line and source == LOCAL_SOURCE_NAME:
        suffix = wildcard_suffix(line)
        if suffix:
            WILDCARD_ALLOW_FOUND.add(suffix)
            domain = domain or suffix

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
    """下载规则源；失败会重试 3 次并记入 FAILED_SOURCES（主流程据此让构建失败）。

    以前这里失败只打印一行，主流程继续把「少了整个源」的结果当成功发布——
    上游偶发 429/503 会静默造成名单缩水且没有任何告警。
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (GitHub Actions; +https://github.com)",
        "Accept": "*/*",
    }
    last_err = None
    for attempt in range(1, 4):
        try:
            print(f"  正在下载: {friendly_name}" + (f"（第 {attempt} 次）" if attempt > 1 else ""))
            resp = requests.get(url, headers=headers, timeout=60)
            resp.raise_for_status()
            # 规则文件全部是 UTF-8；不显式指定时 requests 会按响应头猜，
            # 缺 charset 时可能落到 ISO-8859-1，把中文注释变成乱码
            resp.encoding = resp.encoding or "utf-8"
            if resp.encoding.lower() in ("iso-8859-1", "latin-1"):
                resp.encoding = "utf-8"
            return resp.text
        except requests.exceptions.RequestException as e:
            last_err = e
            if attempt < 3:
                time.sleep(3 * attempt)
    print(f"  !! 下载失败(已重试 3 次): {friendly_name} {url} 错误: {last_err}")
    if friendly_name not in FAILED_SOURCES:
        FAILED_SOURCES.append(friendly_name)
    return None


def load_top_domains() -> set:
    """读取 top-domains.txt（知名站点护栏清单），缺失时返回空集并告警。

    这张表是「不要为了拦广告把真实站点拦死」的底线：只要命中，就走
    TOP_GUARD_SOURCES 的源一律不收录（见文件顶部 TOP_GUARD_SOURCES 注释）。
    文件不存在时**不**让构建失败——护栏是保护措施，缺它构建也该照常跑完。
    """
    if not os.path.exists(TOP_DOMAINS_FILE):
        print(f"  [护栏] 未找到 {TOP_DOMAINS_FILE}，本次不启用知名站点护栏")
        return set()
    try:
        with open(TOP_DOMAINS_FILE, "r", encoding="utf-8") as fh:
            doms = {
                ln.strip().lower().lstrip(".")
                for ln in fh
                if ln.strip() and not ln.strip().startswith("#")
            }
        print(f"  [护栏] 已加载 {len(doms)} 条知名站点")
        return doms
    except OSError as e:
        print(f"  [护栏] 读取失败 {e}，本次不启用护栏")
        return set()


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
    guarded = 0
    demoted = 0
    # 只有「新源」套用护栏：老源直接不套，免得无意改变既有输出
    use_guard = source_name in TOP_GUARD_SOURCES and bool(TOP_DOMAINS)
    # HaGeZi Encrypted DNS 只收多级子域：二级主域里混着大量真实 DoH 服务商官网
    # （alidns.com / dnspod.com / dns.sb / cleanbrowsing.org …），拦掉伤的是
    # 正常使用这些解析器的人，而真正要防的「客户端偷偷切 DoH」用的是子域端点。
    # 另外整段排除 dnscrypt-cert.*：DNSCrypt 的证书查询靠它，拦了直接打挂 dnscrypt-proxy。
    doh_mode = source_name == "HaGeZi Encrypted DNS"

    for line in content.splitlines():
        parsed = parse_line(line, source_name)
        if not parsed:
            continue
        # 公共后缀（com.cn 之类）永远匹配不到具体主机，直接丢弃
        if parsed.domain in psl:
            stats["invalid"] += 1
            continue

        if not parsed.is_whitelist:
            if doh_mode:
                if "dnscrypt-cert" in parsed.domain:
                    demoted += 1
                    continue
                if parsed.domain.count(".") < 2:
                    demoted += 1
                    continue
            if use_guard and parsed.domain in TOP_DOMAINS:
                guarded += 1
                continue

        if parsed.is_whitelist or force_whitelist:
            white_rules[parsed.domain] = source_name
            if parsed.is_whitelist:
                mixed_detected = True
        else:
            block_rules[parsed.domain] = source_name
            if source_name == LOCAL_SOURCE_NAME:
                LOCAL_BLOCK_SET.add(parsed.domain)

    if mixed_detected:
        print(f"  [混合规则检测] {source_name} 含 @@ 例外，已分离到白名单")

    SOURCE_STATS.append({
        "name": source_name,
        "url": url,
        "lines": len(content.splitlines()),
        "blocks": len(block_rules),
        "white": len(white_rules),
        "role": "白名单源" if force_whitelist else "黑名单源",
        "guarded": guarded,
        "demoted": demoted,
    })

    extra = ""
    if guarded:
        extra += f", 知名站点护栏挡掉 {guarded} 条"
    if demoted:
        extra += f", 非多级子域/证书域剔除 {demoted} 条"
    print(f"  从 {source_name} 添加了 {len(block_rules)} 条黑名单, {len(white_rules)} 条白名单{extra}")
    return block_rules, white_rules


def process_all_sources(urls_dict: dict, psl: set, force_whitelist: bool = False):
    all_block_rules: dict = {}
    all_white_rules: dict = {}
    block_source_counts: dict = {}   # 域名 -> 有多少个「不同的源文件」把它列为拦截
    seen_urls: dict = {}             # 域名 -> {规范化 URL}

    def norm_url(u: str) -> str:
        # 同一份名单常被不同写法引用（/refs/heads/ 与直链、大小写差异），
        # 直接按 URL 计数会把同一份名单算两次，让「≥3 源共识」判定失真
        return re.sub(r"/refs/heads/", "/", u)

    for name, url in urls_dict.items():
        block_rules, white_rules = process_source_to_rules(
            url, name, psl, force_whitelist=force_whitelist)

        nu = norm_url(url)
        for rule, source in block_rules.items():
            s = seen_urls.setdefault(rule, set())
            if nu not in s:
                s.add(nu)
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
                        description: str, author: str, domain_spaces=None,
                        allow_spaces=None):
    print(f"\n正在将规则写入到 {os.path.basename(filename)}...")
    domain_spaces = domain_spaces or []
    allow_spaces = allow_spaces or []
    try:
        with open(filename, "w", encoding="utf-8") as f:
            beijing_tz = datetime.timezone(datetime.timedelta(hours=8))
            now_beijing = datetime.datetime.now(beijing_tz)

            f.write(f"! Title: {title}\n")
            f.write(f"! Description: {description}\n")
            f.write(f"! Author: {author}\n")
            f.write(f"! Version: {now_beijing.strftime('%Y%m%d%H%M%S')}\n")
            f.write(f"! Last Updated: {now_beijing.strftime('%Y-%m-%d %H:%M:%S')} (UTC+8)\n")
            f.write(f"! Total Rules: {len(rules_dict) + len(domain_spaces) + len(allow_spaces)}\n")
            f.write("!\n")

            # 域名空间规则（含子域）必须写在最前面，且**不能带行尾注释**：
            # AdGuard 的网络规则不会剥离行尾 `#`，带了注释整条就失效了。
            if domain_spaces:
                f.write("!\n! ==== 域名空间拦截（含全部子域，AdGuard 网络语法）====\n")
                for d in sorted(domain_spaces):
                    f.write(f"||{d}^\n")
                f.write("!\n")
            if allow_spaces:
                f.write("!\n! ==== 域名空间放行（含全部子域，AdGuard 网络语法）====\n")
                for d in sorted(allow_spaces):
                    f.write(f"@@||{d}^\n")
                f.write("!\n")

            for rule in sorted(rules_dict):
                if isinstance(rules_dict[rule], tuple):
                    block_source, white_source = rules_dict[rule]
                    f.write(f"{rule} # Block from: {block_source}, White from: {white_source}\n")
                else:
                    f.write(f"{rule} # From: {rules_dict[rule]}\n")
        print(f"文件 {os.path.basename(filename)} 写入成功！"
              f"（含 {len(domain_spaces)} 条空间拦截 / {len(allow_spaces)} 条空间放行）")
    except IOError as e:
        print(f"写入文件失败: {filename}, 错误: {e}")


def update_readme(block_rules_dict: dict, white_rules_dict: dict, conflict_rules_dict: dict,
                  domain_spaces=None, allow_spaces=None):
    domain_spaces = domain_spaces or []
    allow_spaces = allow_spaces or []
    print("\n正在更新 README.md...")
    repo_name = os.environ.get("GITHUB_REPOSITORY", "your_username/your_repo")
    branch_name = os.environ.get("GITHUB_REF_NAME") or "main"

    if release_tag:
        base_url = f"https://github.com/{repo_name}/releases/latest/download"
    else:
        base_url = f"https://raw.githubusercontent.com/{repo_name}/{branch_name}"

    beijing_tz = datetime.timezone(datetime.timedelta(hours=8))
    now_beijing = datetime.datetime.now(beijing_tz)

    # 上游名单表格（每次构建自动统计贡献条数）
    block_rows, white_rows = [], []
    for s in sorted(SOURCE_STATS, key=lambda x: -x["blocks"]):
        link = s["url"]
        if s["role"] == "白名单源":
            label = f"{s['name']}（白名单）" if s["name"] == LOCAL_SOURCE_NAME else s["name"]
            white_rows.append(f"| {label} | {s['white']:,} | <{link}> |")
        else:
            cnt = f"{s['blocks']:,}"
            if s["white"]:
                cnt += f"（另含 {s['white']:,} 条例外）"
            label = f"{s['name']}（你自己的名单）" if s["name"] == LOCAL_SOURCE_NAME else s["name"]
            block_rows.append(f"| {label} | {cnt} | <{link}> |")
    block_table = "\n".join(block_rows)
    white_table = "\n".join(white_rows) or "| — | 0 | — |"
    n_block_src = sum(1 for s in SOURCE_STATS if s["role"] == "黑名单源")
    n_white_src = sum(1 for s in SOURCE_STATS if s["role"] == "白名单源")

    code_fence = "```"
    raw_base = f"https://raw.githubusercontent.com/{repo_name}/{branch_name}"
    block_url = f"{base_url}/{os.path.basename(block_output_file)}"
    white_url = f"{base_url}/{os.path.basename(white_output_file)}"
    conflict_url = f"{base_url}/{os.path.basename(conflict_output_file)}"
    block_raw = f"{raw_base}/{os.path.basename(block_output_file)}"
    white_raw = f"{raw_base}/{os.path.basename(white_output_file)}"
    conflict_raw = f"{raw_base}/{os.path.basename(conflict_output_file)}"
    total_block = len(block_rules_dict) + len(domain_spaces)
    # 只有在「推荐地址」和「备用直链」确实不同的时候才提备用地址（本地试跑时两者相同）
    note_block = (f"\n> 打不开就用备用直链：`{block_raw}`\n"
                  if block_raw != block_url else "")
    note_white = (f"\n> 打不开就用备用直链：`{white_raw}`\n"
                  if white_raw != white_url else "")

    readme_content = f"""# {readme_title} · 自动更新的 AdGuard Home 规则

> **一句话说明**：把 {n_block_src} 个开源广告拦截名单合并、去重、纠错，自动生成两个可以直接订阅的
> AdGuard Home 规则文件（拦截 + 允许）。每 6 小时自动重建一次，本页面上的数字和名单同步刷新。

| 项目 | 当前状态 |
| --- | --- |
| 最后构建时间 | **{now_beijing.strftime('%Y-%m-%d %H:%M:%S')} (UTC+8)** |
| 拦截规则 | **{len(block_rules_dict):,}** 条 + {len(domain_spaces)} 条「域名空间」（连全部子域一起拦） |
| 允许规则 | **{len(white_rules_dict):,}** 条 + {len(allow_spaces)} 条「域名空间放行」 |
| 冲突规则（同时被拦又被放行） | {len(conflict_rules_dict):,} 条 |
| 上游来源 | {n_block_src} 个黑名单源 + {n_white_src} 个白名单源（明细见下方表格） |
| 构建方式 | GitHub Actions 自动构建，也可在 Actions 页面手动触发 |

---

## 一、这是给谁用的？

- 你在手机、电脑或路由器上装了 **AdGuard Home**（或兼容 AdGuard 语法的 DNS 过滤器），
  想让 App 开屏广告、信息流广告、统计埋点在 **DNS 层**就被拦掉；
- 你不想自己维护十几份规则名单，也不清楚哪些名单质量好。

直接订阅下面两个链接就行。本项目**只做「合并 + 清洗」**，不生产规则，
规则来自下方「上游名单」表格里列出的开源项目。

> ⚠️ **DNS 过滤的能力边界**：它只能拦「域名」，拦不住同一个域名下混排的内容
> （例如贴吧用自己的 API 下发广告位），也看不到 HTTPS 里的内容。
> 所以「某个 App 的广告没干净」不一定代表规则有错，详见第五节。

---

## 二、三分钟部署（新手向）

### 第 0 步：先有一个 AdGuard Home

还没装的话，Docker 一条命令即可（其它方式见
<https://adguard.com/zh_cn/adguard-home/getting-started.html>）：

{code_fence}bash
docker run -d --name adguardhome \\
  -v /opt/adguardhome/work:/opt/adguardhome/work \\
  -v /opt/adguardhome/conf:/opt/adguardhome/conf \\
  -p 53:53/tcp -p 53:53/udp -p 3000:3000/tcp \\
  --restart unless-stopped adguard/adguardhome
{code_fence}

装好后浏览器打开 `http://设备IP:3000`，跟着向导设置管理账号，并把设备/路由器的 DNS 指向它。

### 第 1 步：添加「拦截清单」

1. 进入 AdGuard Home 后台 → 左侧菜单 **过滤器** → **DNS 拦截清单**
2. 点 **添加拦截清单**
3. 名称随便填（例如 `AdGuard-Rules-Black`），URL 填：

{code_fence}
{block_url}
{code_fence}

4. 点 **保存**
{note_block}

### 第 2 步：添加「允许清单」（强烈建议，别跳过）

同一个页面切换到 **DNS 允许清单** 标签 → 添加：

{code_fence}
{white_url}
{code_fence}
{note_white}

**为什么必须两个都加**：任何公共拦截名单都难免少量误杀（上游名单常把某些 App 的
网关、风控、CDN 域名一起拦掉，表现就是「App 显示无网络」）。允许清单负责把这些放行。
只订阅拦截清单，遇到「无网络」的概率会高很多。

### 第 3 步：更新并验证

- **立即生效**：过滤器页面点一次 **「更新」**（默认 12 小时自动更新一次，
  可在 设置 → 常规 → 过滤器更新间隔 调整）
- **验证是否生效**（把 `127.0.0.1` 换成你的 AdGuard Home 地址）：

{code_fence}bash
nslookup doubleclick.net 127.0.0.1    # 广告域：应返回 0.0.0.0 或解析失败
nslookup gw.tmall.com 127.0.0.1       # 天猫校园网关：应能正常解析（保护名单在管）
nslookup dns.msftncsi.com 127.0.0.1   # 系统联网检测：应能正常解析
{code_fence}

### 第 4 步：你自己的规则放哪

本项目只负责「公共部分」。你要单独拦/放某个域名时，有两个选择：

1. **临时/少量**：AdGuard Home 里的 过滤器 → **自定义规则**，直接写
   `||example.com^`（拦）或 `@@||example.com^`（放）；
2. **长期/较多**：放到你自己的名单仓库里再让本项目合并（当前已接入
   `本地规则` 源，见下方表格）。自己的黑名单 **优先级高于上游任何私人白名单**。

### 国内下载慢？

GitHub 直连慢的话，在地址前面套一层公共加速前缀即可，例如：

{code_fence}
https://gh-proxy.org/{block_url}
{code_fence}

---

## 三、三个文件分别是干什么的

| 文件 | 作用 | 条数 | 订阅地址（推荐） | 备用地址（分支直链） |
| --- | --- | --- | --- | --- |
| `{os.path.basename(block_output_file)}` | **拦截**：广告、追踪、统计、恶意域名 | {total_block:,} | <{block_url}> | <{block_raw}> |
| `{os.path.basename(white_output_file)}` | **允许**：保护名单 + 你自己的白名单，用来纠正误杀 | {len(white_rules_dict) + len(allow_spaces):,} | <{white_url}> | <{white_raw}> |
| `{os.path.basename(conflict_output_file)}` | **冲突**：同时出现在黑名单和白名单里的域名（仅供排查，一般不用订阅） | {len(conflict_rules_dict):,} | <{conflict_url}> | <{conflict_raw}> |

> 两个地址内容一样：**推荐地址**指向最新 Release（每次构建更新同名文件，永久有效）；
> **备用地址**直接读仓库分支文件（Release 还没发布完时可临时用）。

文件格式说明：

- 绝大多数行是**纯域名 + 行尾注释**，例如 `example.com # From: 某名单`，
  AdGuard Home 按 hosts 规则处理，**精确匹配该主机名**；
- 文件开头有一段以 `||域名^` 写法的**域名空间规则**（数量见上表），
  这类规则会**连全部子域一起拦**，用来对付「广告域用随机子域轮换」的情况；
  它们**不带行尾注释**——AdGuard 的网络规则不会剥离 `#`，带了注释整条就失效。

---

## 四、上游名单（每次构建自动统计）

### 黑名单源（拦截规则来源）

| 来源 | 本次贡献条数 | 仓库 / 地址 |
| --- | --- | --- |
{block_table}

### 白名单源（放行规则来源）

| 来源 | 本次贡献条数 | 仓库 / 地址 |
| --- | --- | --- |
{white_table}

> 统计的是「本次构建从该源解析出的条数」，同一域名被多个源收录时会去重，
> 所以各源之和会大于最终条数。

---

## 五、规则为什么这么写？（进阶：合并与纠错规则）

### 1. 会丢弃的东西

- **带上下文修饰符的规则**（`$domain=`、`$third-party`、`$script`、`$path=` 等）：
  这类条件在 DNS 层无法表达，硬留着会把「只在某站点生效」的规则变成全局拦截，
  是历史上最主要的误杀来源（曾把 `gw.tmall.com` 的 `$path=/union/` 规则放大成
  「天猫校园整个网关被拦 → App 显示无网络」）。
- **`$badfilter`**（取消规则）：它是否定语义，不能当拦截执行。
- **死规则**：裸 IP、含下划线的域名、首尾点、公共后缀（`com.cn` 之类）、
  以及 TLD 不是「≥2 字符且首尾为字母」的域名——这些在 AdGuard Home 里
  通不过域名校验，会被退化成 URL 子串规则并连注释一起解析，永远不可能命中。

### 2. 上游 `@@` 例外（白名单）只采纳「有争议」的

部分名单自带很长的私人白名单（有的近 3000 条 `@@`）。照单全收会把公认广告域放行
（实测 `als.baidu.com` 被 17 个源共同拦截、`nsclick.baidu.com` 被 16 个源拦截，
却因一句 `@@` 被放行，直接导致贴吧广告回流）。
因此：**被 3 个以上独立名单共同拦截的域名，不采纳任何单个名单的例外。**

### 3. 优先级

1. 核心服务保护名单（系统更新、联网检测、推送通道、支付、加密 DNS、NTP 等）
   —— 永不拦截，防止「App 显示无网络」；
2. **你自己的本地名单** —— 你的黑名单优先于上游一切私人白名单；
3. 上游拦截规则。

### 4. 通配规则的处理

- 上游 `||*.X^` 的原意是「拦 X 的全部子域」，纯域名格式却会把它降级成
  「只拦 X 本身」，子域全漏。本项目把它还原成域名空间规则 `||X^`（覆盖全部子域），
  本次 {len(domain_spaces)} 条；
- 但**平台内容 CDN**（拼多多图床 `pddpic.com`、B 站 `hdslb.com`、
  快手 `yximgs.com`、字节 `pstatp.com` 等）以及「有子域被上游放行」的父域
  **不会被自动升级**，避免把「没图没视频」这种故障引入；
- 你自己白名单里「只含一个 `*`」的放行（如 `@@||storage*360buyimg.com^`）会还原成
  `@@||360buyimg.com^`，否则它们在 DNS 层等于没写。

### 5. 抓取与构建的可靠性

- 每个源失败会重试 3 次（退避 3s/6s），**仍失败则构建失败、不发布新版**——
  宁可停更一次，也不发布「悄悄少了一个源」的残缺名单；
- 同一份名单被配成两个源时按源文件去重，避免「多源共识」判定被重复计数放大；
- 中文域名（IDN）按 IDNA 转成 punycode 再输出；
- **行内注释会被剥离**：`||example.com^$important  # 说明` 只取规则本身。不剥离的话
  注释会混进修饰符，整条规则被当成「未知修饰符」静默丢弃——实测有 8 条白名单
  因此失效，而构建日志完全看不出问题。

### 6. 本次构建统计

保留 {stats['kept']:,} 条（其中带上下文修饰符但目标本身是广告域的 {stats['kept_scoped_ad']:,} 条），
丢弃上下文规则 {stats['dropped_context']:,} 条，丢弃 badfilter {stats['dropped_badfilter']:,} 条，
采纳全局例外 {stats['exc_global']:,} 条，忽略不可信的上游例外 {stats['exc_ad_ignored']:,} 条，
剔除无效域名 {stats['invalid']:,} 条。

---

## 六、自动构建做了什么

{code_fence}text
拉取上游名单（{n_block_src} 个黑名单源 + 本地黑白名单）
   ↓  解析 adblock / hosts 两种语法，剔除上下文修饰符、$badfilter、死规则
   ↓  分离上游的 @@ 例外，只采纳「有争议」的
   ↓  新源套用知名站点护栏（top-domains.txt：命中就不收，避免拦死真实站点）
   ↓  合并去重 + 冲突消解（保护名单 > 你的本地名单 > 上游）
   ↓  还原 ||*.X^ 为域名空间规则（含平台 CDN 安全过滤）
   ↓  输出 Black.txt / White.txt / Conflict.txt
   ↓  重建本 README（数量、上游贡献、构建时间）并提交
   ↓  创建 Release（供 releases/latest/download 永久订阅地址使用）
{code_fence}

---

## 七、常见问题

**Q：更新后广告还在？**
先确认点过过滤器页面的「更新」，再检查该广告是不是由 App 自己的 API 下发
（DNS 层拦不到）；可用 AdGuard Home 的「查询日志」看该请求是否被拦。

**Q：某个 App 打不开 / 显示无网络？**
回到 过滤器 → 查询日志，看它的请求是不是被拦了；确认后把域名加进
允许清单（自定义规则写 `@@||域名^`），或提交到你自己的本地名单仓库。

**Q：为什么同一域名有时拦有时不拦？**
AdGuard Home 的查询日志里 `Result.Rules` 会给出命中的规则来源，
据此能判断是保护名单、你自己的规则，还是某个上游源。

**Q：能用多久 / 会被删吗？**
订阅地址用 `releases/latest/download`，每次构建都会更新同名文件，地址永久有效。

---

构建时间：{now_beijing.strftime('%Y-%m-%d %H:%M:%S')} (UTC+8) · 项目作者：{AUTHOR} ·
本 README 由 `documents/process_rules.py` 的 `update_readme()` 在每次构建时自动生成，
请勿手工修改（会被下一次构建覆盖）。
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

    # 护栏清单必须在处理黑名单源之前加载（process_source_to_rules 会读全局 TOP_DOMAINS）
    global TOP_DOMAINS
    TOP_DOMAINS = load_top_domains()

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

    # 先把 `||*.X^` 还原出来的父域做安全过滤，再进保护名单逻辑：
    #   ① 在 SPACE_NEVER_PROMOTE 里的（平台内容 CDN）不升级
    #   ② 任何来源的白名单里出现了它的子域（说明这段里有功能主机）不升级
    promoted_spaces: set = set()
    skipped_promote: dict = {}
    for p in sorted(WILDCARD_SPACE_FOUND):
        if p in SPACE_NEVER_PROMOTE:
            skipped_promote[p] = "内容CDN保护名单"
            continue
        if any(w == p or w.endswith("." + p) for w in all_white_rules):
            skipped_promote[p] = "有子域被上游放行"
            continue
        promoted_spaces.add(p)
    if skipped_promote:
        print(f"  ||*.X^ 还原的父域中，{len(skipped_promote)} 个因风险被跳过: "
              f"{list(skipped_promote.items())[:6]}")
    print(f"  确认升级为域名空间拦截: {len(promoted_spaces)} 个父域")

    protected_in_black = sorted(d for d in all_block_rules if d in NEVER_BLOCK)
    for d in protected_in_black:
        all_white_rules.setdefault(d, "核心服务保护名单")
        del all_block_rules[d]
    print(f"  核心服务保护名单命中并放行: {len(protected_in_black)} 条")

    ad_exceptions = sorted(
        d for d in all_white_rules
        if all_white_rules[d] != LOCAL_SOURCE_NAME   # 用户自己的白名单永远优先
        and d not in NEVER_BLOCK
        and (AD_MARKERS.search(d)                # 名字就是广告/追踪特征
             # 或：被 3 个以上独立名单共同拦截 => 公认拦截目标，不采纳单个名单的例外
             or block_counts.get(d, 0) >= EXCEPTION_MAX_BLOCK_SOURCES))
    for d in ad_exceptions:
        del all_white_rules[d]
    stats["exc_ad_ignored"] = len(ad_exceptions)
    print(f"  被忽略的上游例外(广告特征或≥{EXCEPTION_MAX_BLOCK_SOURCES}源共识): "
          f"{len(ad_exceptions)} 条")

    # 你自己黑名单里明确要拦的域名，不允许被别人的私人白名单挤掉
    user_priority = sorted(
        d for d in all_white_rules
        if d in LOCAL_BLOCK_SET
        and all_white_rules[d] != LOCAL_SOURCE_NAME
        and d not in NEVER_BLOCK)
    for d in user_priority:
        del all_white_rules[d]
    if user_priority:
        print(f"  本地黑名单优先，撤销了 {len(user_priority)} 条上游白名单: "
              f"{user_priority[:8]}{'…' if len(user_priority) > 8 else ''}")

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

    # 域名空间拦截 = 手工核实过的清单 ∪ 通过安全过滤的 `||*.X^` 还原父域
    domain_spaces = sorted((set(BLOCK_DOMAIN_SPACES) | promoted_spaces)
                           - NEVER_BLOCK - set(white_source_white))
    # 通配放行规则（@@||前缀*X^）还原成 `@@||X^`，否则这些放行在 DNS 层等于没写
    allow_spaces = sorted(WILDCARD_ALLOW_FOUND - set(domain_spaces))

    print("\n最终统计:")
    print(f"  最终黑名单: {len(all_block_rules)} 条 "
          f"(另有 {len(domain_spaces)} 条域名空间拦截，其中来自 ||*.X^ 还原的 "
          f"{len(promoted_spaces)} 条，跳过 {len(skipped_promote)} 条)")
    print(f"  最终白名单: {len(all_white_rules)} 条 "
          f"(另有 {len(allow_spaces)} 条域名空间放行)")
    print(f"  冲突规则: {len(conflict_rules)} 条")
    print(f"  解析统计: {stats}")

    if FAILED_SOURCES:
        print("\n" + "!" * 60)
        print(f"构建失败：以下 {len(FAILED_SOURCES)} 个上游源抓取失败（已重试 3 次）："
              f"{FAILED_SOURCES}")
        print("宁可不出新版，也不发布一份「悄悄少了几个源」的名单。")
        print("!" * 60)
        sys.exit(1)

    write_rules_to_file(
        block_output_file, all_block_rules,
        "AdGuard Custom Blocklist",
        "自动合并的广告拦截规则（与白名单完全独立）", AUTHOR,
        domain_spaces=domain_spaces)
    write_rules_to_file(
        white_output_file, all_white_rules,
        "AdGuard Custom Whitelist",
        "自动合并的白名单规则（与黑名单完全独立）", AUTHOR,
        allow_spaces=allow_spaces)
    write_rules_to_file(
        conflict_output_file, conflict_rules,
        "AdGuard Conflict Rules",
        "同时存在于黑名单和白名单的规则", AUTHOR)

    update_readme(all_block_rules, all_white_rules, conflict_rules,
              domain_spaces=domain_spaces, allow_spaces=allow_spaces)

    print("\n" + "=" * 60)
    print("规则处理完成！")
    print("=" * 60)


if __name__ == "__main__":
    main()
