# IP 群组

**IP Groups**（`/?tab=ipgroups`）管理具名的 IP 名单，例如各国地址、办公网、合作方出口、已知扫描器。名单来自 sing-box 规则集或普通 CIDR 列表，可以放在挂载目录里，也可以从 HTTPS 地址定期下载。站点在 [WAF 策略](policy.md) 中为群组配置独立的规则：拦截、封禁、试运行、切换规则引擎或调整 PL 与阈值。

群组规则在 WAF 内执行（Coraza `@ipMatchFromFile`），可以预览、估算影响、回滚。与按连接直接断开的 [IP 规则](ip-rules.md) 是两套机制。

## 名单格式

格式按内容自动识别：

| 格式 | 说明 |
| --- | --- |
| sing-box 二进制规则集（`.srs`） | 规则集版本 1–5，与 `sing-box rule-set compile` 输出一致 |
| sing-box 源规则集（JSON） | `{"version": 3, "rules": [{"ip_cidr": [...]}]}` |
| 文本 | 每行一个 IP 或 CIDR，`#` 后为注释 |

从规则集中只取 IP 条件：

| 规则 | 处理 |
| --- | --- |
| 只含 `ip_cidr` / `source_ip_cidr` 的规则，以及由这类规则组成的 `or` 逻辑规则 | 合并进名单 |
| 不含 IP 条件的规则（域名、AdGuard、端口、进程、网络类型等） | 跳过，页面显示跳过的条数 |
| IP 与其他条件混合的规则（如 `ip_cidr` + `port`）、取反的 IP 规则、包含 IP 的 `and` 逻辑规则 | 整个名单拒绝导入：它们无法表示成单纯的地址名单 |

导入时合并重叠和相邻的网段、拆成最少的 CIDR，按内容的 SHA256 命名保存在受管卷（`ipgroups/<名称>.<哈希前12位>.txt`）。IPv4 映射的 IPv6 地址按 IPv4 处理。一个名单最多 `CADDY_UI_IPGROUP_MAX_PREFIXES`（默认 100,000）个前缀。

## 名单来源

| 来源 | 设置 | 检查频率 |
| --- | --- | --- |
| 文件 | `CADDY_UI_IPGROUP_DIR`（Compose 中把宿主机 `./ipgroups` 只读挂载到 `/ipgroups`）中的文件名，不能含目录 | 每分钟比对文件大小和修改时间 |
| URL | 只接受 `https://`，不能在地址中带用户名密码；刷新间隔 1h–720h，默认 24h | 按间隔下载，使用 ETag / Last-Modified 条件请求；失败后 15 分钟重试 |

按国家的名单可以直接使用 MetaCubeX 的 sing-box 规则集，例如 `https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/sing/geo/geoip/jp.srs`（把 `jp` 换成其他国家代码）。名单未变化时服务器返回 304，不会重复下载和发布。

下载跟随最多 5 次重定向且必须保持 https，单个文件最大 32 MiB，二进制规则集解压后最大 64 MiB。需要代理时设 `CADDY_UI_IPGROUP_PROXY=http://代理:端口`，只用于群组下载，不影响源站探测和 Loki 查询；未设置时使用容器的 `HTTPS_PROXY`/`NO_PROXY` 环境变量。

保护措施：

- 空名单、无法解析的名单从不替换当前名单，错误显示在群组上，旧名单继续生效。
- 新名单的前缀数不到当前的一半（且当前至少 20 个）时，暂存为待定更新，页面显示原因，需点 **Approve** 才生效，或 **Discard** 丢弃。防止上游出错把"只允许国内访问"之类的规则变成全部拦截。

## 页面操作

| 操作 | 说明 |
| --- | --- |
| Add / Update | 名称（1–32 位小写字母、数字、`-`、`_`）、来源、文件名或 URL、刷新间隔、备注。保存后立即导入 |
| Refresh now | 忽略变化检测，立即重新读取或下载 |
| Approve / Discard | 处理待定更新 |
| Publish again | 有站点仍在加载旧名单时（例如更新时 Caddy 不可用）重新发布 |
| Delete | 只能删除没有任何站点策略使用的群组 |
| Which groups hold | 查询某个 IP 属于哪些群组 |

名单内容变化后，UI 自动重新生成并发布所有使用该群组的站点 overlay，每个站点在变更历史中记一条 `ipgroup`；群组本身的增删改也记入变更历史（不属于某个站点）。旧名单文件在没有 overlay 引用且超过一天后删除，所以回滚和失败补偿始终能找到原来的文件。

## 群组规则

在 **Policy** 页的 **IP group rules** 中为站点添加规则，按顺序在 CRS 之前执行（第 1 阶段）：

| 动作 | 效果 | 规则编号 | 事件 |
| --- | --- | --- | --- |
| block | 返回 403，不再经过 CRS | 9002000+ | 记录为拦截（DetectionOnly 站点为将拦截） |
| ban | 返回 403，不再经过 CRS，不写审计记录 | 9002000+ | 不产生事件，只在访问日志中以 403 出现；DetectionOnly 站点按 block 记录将拦截，便于上线前观察 |
| trial | 不拦截，把本会拦截的请求写入审计日志 | 9002000+ | 每个命中请求都成为一条"将拦截"事件 |
| engine | 对这些客户端切换规则引擎：On / DetectionOnly / Off | 9002500+ | 规则命中写入审计记录（不单独产生事件） |
| tune | 对这些客户端改 blocking/detection PL、入站/出站阈值；留空的项沿用站点策略 | 9002500+ | 事件按该群组的 PL 和阈值计分、判定 |

每条规则选择一个或多个群组（最多 16 个）：**inside any** 表示属于其中任意一个，**outside all** 表示一个都不属于。多个群组在发布时合并成一个名单（`ipgroups/_union.<哈希前12位>.txt`），每个请求只匹配一次；任何成员群组更新后，合并名单随之重新生成并发布。例如：

| 需求 | 规则 |
| --- | --- |
| 只允许中国大陆和日本访问，其他地址直接封禁、不记录 | `cn`、`jp` · outside all · ban |
| 管理后台只允许办公网，拦截的请求要留事件 | `office` · outside all · block |
| 先观察白名单会拦掉多少请求 | `cn`、`jp` · outside all · trial，运行一段时间后看 **Events** 里的将拦截事件 |
| 合作方出口误报多，放宽阈值 | `partners` · inside any · tune · Inbound 10 |
| 内部健康检查不走 WAF | `monitors` · inside any · engine Off |
| 对境外流量提高 PL | `cn` · outside all · tune · Blocking PL 2 |

白名单要用一条规则列出全部允许的群组。分成多条 outside 规则时，每条都会拦下其他群组的客户端。

执行顺序与覆盖：

- block 和 ban 立即结束本请求的判定，CRS 不再检测；
- 多条 engine / tune 规则同时命中时，后面的覆盖前面的；
- engine Off 之后的规则不再执行；
- 提高 blocking PL 时，detection PL 自动提高到不低于它（否则 CRS 规则 901500 会拒绝请求）；
- 源站探测请求（规则 9001200）排在群组规则之前，不受影响，白名单不会让发布验证失败。

客户端地址由 Caddy 根据 `trusted_proxies` 决定，与 IP 规则、事件中的客户端 IP 是同一个地址。

ban 不写审计记录，但 coraza-caddy 仍会为每个被拒请求在 Caddy 错误日志中写一行 `WAF rule violation detected`，这一行由镜像中的模块产生，UI 无法关闭。

## 性能与名单规模

匹配速度取决于镜像：

- **标准镜像**：Coraza 自带的 `@ipMatchFromFile` 对名单逐条比较，找到第一个匹配就停止。白名单规则对每个请求都执行：名单内的请求平均比较一半前缀后再经过 CRS，被封禁的请求要比较全部前缀，耗时与前缀数成正比。
- **带 coraza-ipset 插件的 caddy-with-auth 镜像**（`liukan/caddy-with-auth:coraza-plugins-ipset`）：插件用有序区间二分查找替换同名 operator，规则和匹配结果不变，耗时与名单大小无关。插件说明见 [后端镜像](backend-image.md#ip-匹配插件coraza-ipset)，部署步骤见 [使用 coraza-ipset 镜像部署](ipset-image-deployment.md)。

用 MetaCubeX 的国家名单，在同一台机器、同一份配置下对比两种实现（单核 Caddy，Apple M1 Max，本机回环，keep-alive，前缀数为合并后的数量）：

| 场景 | 前缀数 | 标准镜像 | 带插件的镜像 |
| --- | --- | --- | --- |
| 正常请求经过 CRS 检测（无群组规则，对照） | — | 约 0.38 ms，2,670 次/秒 | 约 0.38 ms，2,650 次/秒 |
| CN + JP 白名单：名单内的请求 | 26,730 | 约 0.46 ms，2,190 次/秒 | 约 0.38 ms，2,660 次/秒 |
| CN + JP 白名单：被封禁的请求 | 26,730 | 约 0.30 ms，3,330 次/秒 | 约 0.055 ms，18,250 次/秒 |
| CN + JP + US 白名单：名单内的请求 | 281,382 | 约 1.06 ms，940 次/秒 | 约 0.37 ms，2,690 次/秒 |
| CN + JP + US 白名单：被封禁的请求 | 281,382 | 约 2.7 ms，360 次/秒 | 约 0.055 ms，18,240 次/秒 |

内存：标准镜像中名单在每个使用它的站点各加载一份（CN + JP 约 1.8 MiB，CN + JP + US 约 19 MiB）。插件把名单存成合并后的区间，按内容在全进程共用一份（CN + JP 约 0.3 MiB，CN + JP + US 约 2 MiB）。

建议：

- **标准镜像**：一条规则的名单控制在 3 万个前缀左右，正常请求只多约 0.1 ms；US 这类大名单（单独就有 26 万个前缀，超过默认上限 10 万）代价高，应在上游拦截。
- **带插件的镜像**：名单大小不再影响请求耗时，上限取决于内存和加载时间（28 万个前缀解析约 0.1 秒），可以按需调高 `CADDY_UI_IPGROUP_MAX_PREFIXES`。
- **站点在 Cloudflare 后面时**：国家白名单仍可以放在 Cloudflare 的 WAF 规则里，被拒请求根本不会到达源站。

### 名单格式与匹配效率

名单格式只影响导入，不影响请求时的速度：.srs、JSON、文本都被展开成同样的前缀名单。效率取决于匹配方式：

| 匹配方式 | 每次查找（CN + JP + US） | 说明 |
| --- | --- | --- |
| 逐条比较（Coraza `@ipMatch`，标准镜像） | 约 2.2–2.9 ms | 随前缀数线性增长 |
| 逐条比较（Caddy `client_ip`） | 约 1.1 ms | 同样线性，名单要写进 Caddy 配置（CN + JP + US 约 5.4 MB），每次重载都要解析 |
| 有序区间二分查找（sing-box 处理 .srs 的方式，coraza-ipset 插件） | 约 55–80 ns | 与名单大小基本无关 |
| MMDB 二叉树查找 | 约 80 ns | IPv4 最多 32 步，与国家数无关 |

MMDB 和 .srs 本身都不慢，慢的是逐条比较。UI 不导入 MMDB：它在 Coraza 中也只能展开成同样的前缀名单，效率与 .srs 相同；而 MetaCubeX 的 `country.mmdb` 有 7.67 MB（全部国家），按国家拆分的 .srs 只需下载用到的部分（CN 36 KB、JP 69 KB、US 518 KB）。

## 预览与影响估算

群组规则是站点策略的一部分：修改后先预览 diff 和影响，再应用。影响估算按每个历史事件的客户端 IP 判断群组成员关系，模拟 block、ban、engine 和 tune 的效果。

block 和 ban 作用于群组的全部请求，但历史里只有被审计过的请求（被拦截、将被拦截、调优模式下有分值的），估算会低估实际影响，页面会提示。上线之前先用 trial 运行一段时间：trial 会把命中的每个请求都记成事件，能看到真实流量。ban 生效后被拒请求不再进入历史，之后的分析和估算看不到它们，请求量只能从访问日志查看。

名单在预览之后发生变化时，草稿失效，需要重新预览。

## REST API

| 端点 | 作用 |
| --- | --- |
| `GET /api/ipgroups` | 全部群组，含当前名单、待定更新、错误、使用它的站点（`sites`）和仍在加载旧名单的站点（`stale`） |
| `PUT /api/ipgroups/{name}` | 创建或修改：`{"source":"url","url":"https://…/geoip-cn.srs","refresh":"24h","note":"…","reason":"…"}`；文件来源用 `"source":"file","file":"office.txt"` |
| `DELETE /api/ipgroups/{name}` | 删除；仍被策略使用时返回 409 |
| `POST /api/ipgroups/{name}/refresh` | 立即导入；`?force=true` 忽略变化检测。返回 `{"changed":…, "group":…}`；来源读取或解析失败返回 502 |
| `POST /api/ipgroups/{name}/approve`、`/discard` | 处理待定更新 |
| `GET /api/ipgroups/lookup?ip=203.0.113.7` | 某个 IP 所属的群组 |

群组规则通过站点策略 API（`PUT /api/sites/{domain}/policy`）的 `ip_groups` 字段设置。`groups` 是群组名列表，`negate: true` 表示 outside all：

```json
{"policy": {"blocking_pl": 1, "inbound_threshold": 5, "outbound_threshold": 4,
  "ip_groups": [
    {"groups": ["cn", "jp"], "negate": true, "action": "ban", "note": "allow CN and JP only"},
    {"groups": ["partners"], "action": "tune", "inbound_threshold": 10},
    {"groups": ["monitors"], "action": "engine", "engine": "Off"}
  ]},
 "reason": "allow CN and JP"}
```

```sh
curl -s -X PUT -H "Authorization: Bearer $CADDY_UI_TOKEN" -H "Content-Type: application/json" \
  -d '{"source":"url","url":"https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/sing/geo/geoip/jp.srs","refresh":"24h","reason":"JP addresses"}' \
  http://127.0.0.1:8080/api/ipgroups/jp
```
