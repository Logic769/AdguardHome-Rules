# 激进的规则 · 自动更新的 AdGuard Home 规则

> **一句话说明**：把 26 个开源广告拦截名单合并、去重、纠错，自动生成两个可以直接订阅的
> AdGuard Home 规则文件（拦截 + 允许）。每 6 小时自动重建一次，本页面上的数字和名单同步刷新。

| 项目 | 当前状态 |
| --- | --- |
| 最后构建时间 | **2026-10-01 16:24:49 (UTC+8)** |
| 拦截规则 | **399,060** 条 + 309 条「域名空间」（连全部子域一起拦） |
| 允许规则 | **461** 条 + 3 条「域名空间放行」 |
| 冲突规则（同时被拦又被放行） | 347 条 |
| 上游来源 | 26 个黑名单源 + 1 个白名单源（明细见下方表格） |
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

```bash
docker run -d --name adguardhome \
  -v /opt/adguardhome/work:/opt/adguardhome/work \
  -v /opt/adguardhome/conf:/opt/adguardhome/conf \
  -p 53:53/tcp -p 53:53/udp -p 3000:3000/tcp \
  --restart unless-stopped adguard/adguardhome
```

装好后浏览器打开 `http://设备IP:3000`，跟着向导设置管理账号，并把设备/路由器的 DNS 指向它。

### 第 1 步：添加「拦截清单」

1. 进入 AdGuard Home 后台 → 左侧菜单 **过滤器** → **DNS 拦截清单**
2. 点 **添加拦截清单**
3. 名称随便填（例如 `AdGuard-Rules-Black`），URL 填：

```
https://github.com/Logic769/AdguardHome-Rules/releases/latest/download/Black.txt
```

4. 点 **保存**

> 打不开就用备用直链：`https://raw.githubusercontent.com/Logic769/AdguardHome-Rules/main/Black.txt`


### 第 2 步：添加「允许清单」（强烈建议，别跳过）

同一个页面切换到 **DNS 允许清单** 标签 → 添加：

```
https://github.com/Logic769/AdguardHome-Rules/releases/latest/download/White.txt
```

> 打不开就用备用直链：`https://raw.githubusercontent.com/Logic769/AdguardHome-Rules/main/White.txt`


**为什么必须两个都加**：任何公共拦截名单都难免少量误杀（上游名单常把某些 App 的
网关、风控、CDN 域名一起拦掉，表现就是「App 显示无网络」）。允许清单负责把这些放行。
只订阅拦截清单，遇到「无网络」的概率会高很多。

### 第 3 步：更新并验证

- **立即生效**：过滤器页面点一次 **「更新」**（默认 12 小时自动更新一次，
  可在 设置 → 常规 → 过滤器更新间隔 调整）
- **验证是否生效**（把 `127.0.0.1` 换成你的 AdGuard Home 地址）：

```bash
nslookup doubleclick.net 127.0.0.1    # 广告域：应返回 0.0.0.0 或解析失败
nslookup gw.tmall.com 127.0.0.1       # 天猫校园网关：应能正常解析（保护名单在管）
nslookup dns.msftncsi.com 127.0.0.1   # 系统联网检测：应能正常解析
```

### 第 4 步：你自己的规则放哪

本项目只负责「公共部分」。你要单独拦/放某个域名时，有两个选择：

1. **临时/少量**：AdGuard Home 里的 过滤器 → **自定义规则**，直接写
   `||example.com^`（拦）或 `@@||example.com^`（放）；
2. **长期/较多**：放到你自己的名单仓库里再让本项目合并（当前已接入
   `本地规则` 源，见下方表格）。自己的黑名单 **优先级高于上游任何私人白名单**。

### 国内下载慢？

GitHub 直连慢的话，在地址前面套一层公共加速前缀即可，例如：

```
https://gh-proxy.org/https://github.com/Logic769/AdguardHome-Rules/releases/latest/download/Black.txt
```

---

## 三、三个文件分别是干什么的

| 文件 | 作用 | 条数 | 订阅地址（推荐） | 备用地址（分支直链） |
| --- | --- | --- | --- | --- |
| `Black.txt` | **拦截**：广告、追踪、统计、恶意域名 | 399,369 | <https://github.com/Logic769/AdguardHome-Rules/releases/latest/download/Black.txt> | <https://raw.githubusercontent.com/Logic769/AdguardHome-Rules/main/Black.txt> |
| `White.txt` | **允许**：保护名单 + 你自己的白名单，用来纠正误杀 | 464 | <https://github.com/Logic769/AdguardHome-Rules/releases/latest/download/White.txt> | <https://raw.githubusercontent.com/Logic769/AdguardHome-Rules/main/White.txt> |
| `Conflict.txt` | **冲突**：同时出现在黑名单和白名单里的域名（仅供排查，一般不用订阅） | 347 | <https://github.com/Logic769/AdguardHome-Rules/releases/latest/download/Conflict.txt> | <https://raw.githubusercontent.com/Logic769/AdguardHome-Rules/main/Conflict.txt> |

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
| xndeye adblock_list | 222,543（另含 29 条例外） | <https://raw.githubusercontent.com/xndeye/adblock_list/refs/heads/release/dns.txt> |
| AdBlock DNS Filters | 215,847（另含 197 条例外） | <https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt> |
| adsethost | 198,965 | <https://raw.githubusercontent.com/rentianyu/Ad-set-hosts/master/adguard> |
| natsuki | 196,090 | <https://raw.githubusercontent.com/Natsuki-Kaede/Natsuki-List/refs/heads/main/adguardhome.txt> |
| GOODBYEADS | 113,508 | <https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/dns.txt> |
| neodavhost | 110,648 | <https://raw.githubusercontent.com/neodevpro/neodevhost/master/adblocker> |
| 1hosts | 102,241 | <https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/adblock.txt> |
| anti-AD | 93,027（另含 107 条例外） | <https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-easylist.txt> |
| ABP | 57,326（另含 26 条例外） | <https://raw.githubusercontent.com/damengzhu/abpmerge/refs/heads/main/abpmerge.txt> |
| oisd/small | 57,296 | <https://small.oisd.nl/> |
| 那个谁520 | 21,668（另含 2,986 条例外） | <https://raw.githubusercontent.com/qq5460168/666/master/rules.txt> |
| 10007 | 12,594（另含 9 条例外） | <https://raw.githubusercontent.com/lingeringsound/10007_auto/master/adb.txt> |
| 海哥 | 11,906 | <https://raw.githubusercontent.com/2771936993/HG/main/hg1.txt> |
| smad | 4,959 | <https://raw.githubusercontent.com/2Gardon/SM-Ad-FuckU-hosts/refs/heads/master/SMAdHosts> |
| 下个ID见 | 4,959 | <https://raw.githubusercontent.com/2Gardon/SM-Ad-FuckU-hosts/master/SMAdHosts> |
| 大萌主 | 4,510（另含 4 条例外） | <https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt> |
| Malicious URL Blocklist | 3,347 | <https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt> |
| 本地规则（你自己的名单） | 1,004 | <https://raw.githubusercontent.com/Logic769/Adguardhome-local-rules/main/blacklist.txt> |
| 秋风的规则 | 958 | <https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt> |
| 茯苓的广告规则 | 663 | <https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/main/FuLingRules/FuLingBlockList.txt> |
| 逆向涉猎 | 547 | <https://raw.githubusercontent.com/790953214/qy-Ads-Rule/main/black.txt> |
| DD自用 | 464（另含 159 条例外） | <https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt> |
| 晴雅 | 384 | <https://raw.githubusercontent.com/3316134332/qy-Ads-Rule/refs/heads/main/black.txt> |
| 乘风广告规则 | 91（另含 1 条例外） | <https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/refs/heads/master/rule.txt> |
| 困了想睡觉 | 47 | <https://raw.githubusercontent.com/Kuner-mw/DNS-Kuner/main/FilterRules/blacklist.txt> |
| 秋风的规则补充 | 16 | <https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-Replenish.txt> |

### 白名单源（放行规则来源）

| 来源 | 本次贡献条数 | 仓库 / 地址 |
| --- | --- | --- |
| 本地规则（白名单） | 100 | <https://raw.githubusercontent.com/Logic769/Adguardhome-local-rules/main/whitelist.txt> |

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
  本次 309 条；
- 但**平台内容 CDN**（拼多多图床 `pddpic.com`、B 站 `hdslb.com`、
  快手 `yximgs.com`、字节 `pstatp.com` 等）以及「有子域被上游放行」的父域
  **不会被自动升级**，避免把「没图没视频」这种故障引入；
- 你自己白名单里「只含一个 `*`」的放行（如 `@@||storage*360buyimg.com^`）会还原成
  `@@||360buyimg.com^`，否则它们在 DNS 层等于没写。

### 5. 抓取与构建的可靠性

- 每个源失败会重试 3 次（退避 3s/6s），**仍失败则构建失败、不发布新版**——
  宁可停更一次，也不发布「悄悄少了一个源」的残缺名单；
- 同一份名单被配成两个源时按源文件去重，避免「多源共识」判定被重复计数放大；
- 中文域名（IDN）按 IDNA 转成 punycode 再输出。

### 6. 本次构建统计

保留 1,443,995 条（其中带上下文修饰符但目标本身是广告域的 158 条），
丢弃上下文规则 6,347 条，丢弃 badfilter 11 条，
采纳全局例外 3,767 条，忽略不可信的上游例外 540 条，
剔除无效域名 17,824 条。

---

## 六、自动构建做了什么

```text
拉取上游名单（26 个黑名单源 + 本地黑白名单）
   ↓  解析 adblock / hosts 两种语法，剔除上下文修饰符、$badfilter、死规则
   ↓  分离上游的 @@ 例外，只采纳「有争议」的
   ↓  合并去重 + 冲突消解（保护名单 > 你的本地名单 > 上游）
   ↓  还原 ||*.X^ 为域名空间规则（含平台 CDN 安全过滤）
   ↓  输出 Black.txt / White.txt / Conflict.txt
   ↓  重建本 README（数量、上游贡献、构建时间）并提交
   ↓  创建 Release（供 releases/latest/download 永久订阅地址使用）
```

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

构建时间：2026-10-01 16:24:49 (UTC+8) · 项目作者：logic769 ·
本 README 由 `documents/process_rules.py` 的 `update_readme()` 在每次构建时自动生成，
请勿手工修改（会被下一次构建覆盖）。
