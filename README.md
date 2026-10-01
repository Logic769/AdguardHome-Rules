# 激进的规则

# 自动更新的 AdGuard Home 规则

项目作者: logic769

本项目通过 GitHub Actions 自动合并、去重多个来源的 AdGuard Home 规则。
支持自动检测并分离上游规则中的混合黑白名单。
黑白名单完全独立，同时存在的规则会单独列在冲突规则中。

最后更新时间: 2026-10-01 08:42:45 (UTC+8)

最终黑名单规则数: 398568

最终白名单规则数: 822

冲突规则数: 736

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
- 只采纳上游**无修饰符的全局例外**，且目标域名不带广告特征，避免引入他人私人白名单。
- 域名统一小写并严格校验，剔除裸 IP、下划线、首尾点、通配符与公共后缀。
- **核心服务保护名单**：系统更新、连通性检测（被拦会显示「无网络」）、推送通道、
  加密 DNS、证书吊销、NTP，以及阿里系 App 的 ACS/JMACS/MSGACS 网络与风控接口，
  无论上游怎么写都永不拦截。

本次构建统计：保留 1443432 条（其中带上下文修饰符但目标本身是广告域的 148 条），
丢弃上下文规则 6369 条，丢弃 badfilter 11 条，
采纳全局例外 3765 条，忽略带广告特征的上游例外 174 条，
剔除无效域名 17755 条。

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
