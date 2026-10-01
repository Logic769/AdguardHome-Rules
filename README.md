# 激进的规则

# 自动更新的 AdGuard Home 规则

项目作者: logic769

本项目通过 GitHub Actions 自动合并、去重多个来源的 AdGuard Home 规则。
支持自动检测并分离上游规则中的混合黑白名单。
黑白名单完全独立，同时存在的规则会单独列在冲突规则中。

最后更新时间: 2026-10-01 14:28:45 (UTC+8)

最终黑名单规则数: 399060（另有 314 条域名空间拦截，含全部子域）

最终白名单规则数: 461（另有 3 条域名空间放行）

冲突规则数: 347

订阅链接

拦截规则 (Blocklist)

```
https://github.com/Logic769/AdguardHome-Rules/releases/latest/download/Black.txt
```

允许规则 (Whitelist)

```
https://github.com/Logic769/AdguardHome-Rules/releases/latest/download/White.txt
```

冲突规则 (Conflict)

```
https://github.com/Logic769/AdguardHome-Rules/releases/latest/download/Conflict.txt
```

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
- 域名统一小写并严格校验：裸 IP、下划线、首尾点、公共后缀、以及 **TLD 不是「长度≥2
  且首尾为字母」** 的域名全部剔除——这类行在 AGH 里通不过域名校验，会退化成 URL 子串
  规则并连带行尾注释一起解析，纯属死规则（实测清掉 16 条，如 `azvjflj.cn1`）。
- 抓取失败（重试 3 次后仍失败）时**构建直接失败、不发布新版**：以前只打印一行日志，
  「悄悄少了一个源」的名单照样发布，上游偶发 429/503 就会造成静默缩水。
- **本地黑名单优先**：你写在本地名单里的拦截目标，不允许被上游别人的私人白名单
  （如 `@@||alistgo.com^`）挤掉；只有核心服务保护名单仍然优先于它。
- 中文等 IDN 域名按 IDNA 转成 punycode 再输出（`广告.tmall.com` → `xn--4rr70v.tmall.com`），
  以前这类规则会被当成非法域名整条丢弃。
- **通配规则还原**：上游 `||*.X^` 的原意是「拦 X 的全部子域」，纯域名格式以前会把它
  降级成「只拦 X 本身」，子域全漏。现在还原为域名空间规则（`||X^`），本次 298 条。
  用户自己白名单里「只有一个 `*`」的放行（如 `@@||storage*360buyimg.com^`）还原为
  `@@||360buyimg.com^`；上游的 `@@||*.X^` 一概不还原，避免把别人的「整站放行」搬进来。
- 同一份名单被配成两个源（`smad` 与「下个ID见」是同一份 SMAdHosts）时按源文件去重计数，
  否则「≥3 源共识」的判定会被重复计数放大。
- **核心服务保护名单**：系统更新、连通性检测（被拦会显示「无网络」）、推送通道、
  加密 DNS、证书吊销、NTP，以及阿里系 App 的 ACS/JMACS/MSGACS 网络与风控接口，
  无论上游怎么写都永不拦截。
  例外（2026-10-01 按你的决定调整）：`dns.qq.com`、`doh.dns.apple.com` 移出保护名单
  （DoH 会绕过本 DNS 过滤，你的本地黑名单明确要拦）；`staticsns.cdn.bcebos.com`
  （百度 BCE 存储桶，6 个源共同拦截）也按你的本地规则执行拦截。
  `paydns.wechatpay.cn`（支付）、`acs4baichuan.m.taobao.com`（阿里风控）、
  `gw.tmall.com` 继续保持放行，避免再现「App 显示无网络」。
- **域名空间拦截**（文件开头 `==== 域名空间拦截（含全部子域）====` 段，
  当前 314 条）：以 AdGuard 网络语法 `||域名^` 输出，
  连**全部子域**一起拦。纯域名是精确主机名匹配，父域拦不住子域——实测
  `sofire.baidu.com` 拦住了，但 App 请求的是 `factors.sofire.baidu.com`；
  轮换哈希域（`9e59f633….rdt.tfogc.com`）更是永远追不上。这些行**不带行尾注释**：
  AdGuard 的网络规则不剥离 `#`，带了注释整条就失效。
  其中大部分来自上游 `||*.X^` 通配规则的还原，少数是逐个核实后手工加入的广告域。
- **域名空间放行**（白名单文件里 `==== 域名空间放行 ====` 段，当前 3 条）：
  你自己白名单里「只含一个 `*`」的放行规则还原成 `@@||域名^`，
  否则它们在 DNS 层等于没写（例如曾让 `sdk*faceid.qq.com`、`storage*360buyimg.com` 失效）。

本次构建统计：保留 1443993 条（其中带上下文修饰符但目标本身是广告域的 158 条），
丢弃上下文规则 6347 条，丢弃 badfilter 11 条，
采纳全局例外 3767 条，忽略带广告特征的上游例外 540 条，
剔除无效域名 17823 条。

规则来源

黑名单来源 (Blocklist Sources)

- 秋风的规则
- 晴雅
- 困了想睡觉
- 海哥
- 秋风的规则补充
- natsuki
- DD自用
- smad
- 大萌主
- 10007
- 逆向涉猎
- neodavhost
- 下个ID见
- adsethost
- 1hosts
- 茯苓的广告规则
- GOODBYEADS
- Malicious URL Blocklist
- xndeye adblock_list
- anti-AD
- AdBlock DNS Filters
- ABP
- 那个谁520
- oisd/small
- 乘风广告规则
- 本地规则

白名单来源 (Whitelist Sources)

- 本地规则

由 GitHub Actions 自动构建。
