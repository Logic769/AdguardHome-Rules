# 平稳的规则

# 自动更新的 AdGuard Home 规则

项目作者: logic769

本项目通过 GitHub Actions 自动合并、去重多个来源的 AdGuard Home 规则。
支持自动检测并分离上游规则中的混合黑白名单。
黑白名单完全独立，同时存在的规则会单独列在冲突规则中。

最后更新时间: 2026-04-02 00:23:46 (UTC+8)

最终黑名单规则数: 523403

最终白名单规则数: 7442

冲突规则数: 1301

订阅链接

拦截规则 (Blocklist)

```
https://raw.githubusercontent.com/your_username/your_repo/main/Black.txt
```

允许规则 (Whitelist)

```
https://raw.githubusercontent.com/your_username/your_repo/main/White.txt
```

冲突规则 (Conflict)

```
https://raw.githubusercontent.com/your_username/your_repo/main/Conflict.txt
```

规则来源

黑名单来源 (Blocklist Sources)

- 秋风的规则
- 广告规则
- DD自用
- 大萌主
- 逆向涉猎
- 下个ID见
- 那个谁520
- 1hosts
- 茯苓的广告规则
- AdBlockDNSFilters1
- AdBlockDNSFilters2
- Ad-set-hosts
- GOODBYEADS
- 10007_auto
- Malicious URL Blocklist
- xndeye adblock_list
- Menghuibanxian
- anti-AD
- AdBlock DNS Filters
- ABP
- Custom Blocklist (本地)

白名单来源 (Whitelist Sources)

- 茯苓允许列表
- 666
- 个人自用白名单
- BlueSkyXN
- GOODBYEADS
- Custom Whitelist (本地)

由 GitHub Actions 自动构建。
