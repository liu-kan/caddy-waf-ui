# WAF 事件

**Events**（`/?tab=events`）列出 Coraza 审计日志中的 WAF 事件，打开单条事件可以看到它为什么被拦、命中了哪些规则、各加了多少分，以及误报时的最小排除建议。

## 事件从哪里来

UI 每 2 秒（`CADDY_UI_INGEST_INTERVAL`）读取一次审计日志，把新记录规范化后写入本地事件文件 `/ui-data/events/events-<日期>.jsonl`，读取位置持久保存，重启后继续。规范化时：

- 按事务 ID 和节点去重；
- 用规则字典补全每条命中的类型、分值、PL 和类别，并重新计算入站/出站分；
- 从 overlay 写入的签名（`SecComponentSignature`）读出当时的模式、策略和 revision；
- 按本地脱敏级别（`CADDY_UI_REDACTION_LOCAL`）处理匹配内容、查询值和请求头：strict 只保留规则、变量名和查询参数名；standard 另外保留匹配片段、非凭据查询值和诊断请求头；full 保留已采集的内容。请求体不进入事件。见 [可配置脱敏](redaction.md)。

事件按动作分三类：

| 动作 | 列表中显示 | 含义 |
| --- | --- | --- |
| `blocked` | BLOCKED | Coraza 实际中断了请求（以中断标志为准，而不是配置了 deny） |
| `would_block` | WOULD BLOCK | DetectionOnly 模式下，分值达到阈值或命中直接拦截规则，但没有拦 |
| `detected` | DETECTED | 有规则命中，但分值低于阈值。主要在开启调优模式后出现，见 [WAF 策略](policy.md#调优模式)；未开启时只有上游返回 4xx/5xx 的才会被记录 |

没有任何规则命中的审计记录（Coraza 会记录上游返回的 404、401、5xx 等响应）和 UI 自己的源站探测请求（规则 9001200）不计入事件，详见 [审计日志与轮转](audit-log.md#写入什么)。

## 事件列表

| 筛选 | 说明 |
| --- | --- |
| Storage | 本地文件或 Grafana Cloud Loki。超过 24 小时的范围在配置了 Loki 时默认查云端 |
| Site | 站点 |
| Action | 三种动作之一 |
| Range | 最近 1 小时、24 小时、7 天、14 天、30 天 |
| Client IP | 精确匹配 |
| Rule id | 包含该规则的事件 |
| Path prefix | 路径前缀 |
| Text | 不区分大小写，在 IP、路径、Host、规则编号、事务 ID、规则消息和变量名中查找。匹配内容默认已脱敏，无法检索 |

每页 50 条，最新的在前。分数列是"阻断分 / 当时的入站阈值"。每个规则编号都链接到 [规则字典](rules.md)；有中文说明的规则可展开 **Meaning** 直接查看。

页面顶部的状态行显示审计日志读取进度、本地事件数量、规则字典的 CRS 版本，以及是否配置了 Loki。事件报告的 CRS 版本与字典不一致时会提示。

## 为什么被拦

打开一条事件，页面依次显示：

- **四个指标**：入站分 / 阈值、出站分 / 阈值、当时的模式与策略（PL、阈值、调优、revision）、CRS 版本与引擎状态。分值按命中的规则重新计算；Coraza 在判定规则里报告了总分时一并显示，便于核对。高于阻断 PL、只记录不阻断的规则所加的分单独标出。
- **每一条命中的规则**：编号、消息、类型和类别、对总分的贡献，匹配到的变量（例如 `ARGS:q`、`REQUEST_FILENAME`），以及中文说明和 CRS 原文注释。

规则类型决定了它在判定中的角色：

| 类型 | 作用 | 举例 |
| --- | --- | --- |
| detection | 命中时加分 | 930130 访问受限文件，+5 |
| decision | 比较总分与阈值，做出拦截判定 | 949110 入站异常分超阈值 |
| blocking | 不看分值，直接拦截 | Coraza 基础配置中的 200002 请求体解析失败 |
| control / correlation | 流程控制、汇总记录 | 901xxx 初始化、980xxx 相关性 |

以 `930130,949110` 为例：930130 发现请求访问 `.env` 这类受限文件，加 5 分；949110 发现入站总分 5 达到阈值 5，于是拦截。要放行的是 930130 的这次匹配，949110 是判定规则，不能也不应该被排除。

记录不完整时页面会提示：命中数超过 50 条被截断，或记录里只有规则编号而没有匹配细节，此时分值无法可靠重算。

事件为 BLOCKED 却没有判定规则、直接拦截规则或自定义规则时，页面会提示原因：通常是请求体超过站点的请求体限制（On 模式下返回 413，见 [WAF 策略](policy.md#请求限制)），也可能是带 `nolog` 的自定义规则。

页面右侧的快捷入口：**Same path**、**Same client**（同路径、同来源最近 14 天的事件）、**Review site policy**、**Analyze this site**、**Open in Grafana Explore**（配置了 `CADDY_UI_GRAFANA_URL` 时）。

## 本地匹配内容

事件里保留多少匹配内容取决于本地脱敏级别。在产生该事件的节点上，点 **Show matched values** 会按事件时间和事务 ID 到原始审计日志或对应的轮转归档（保留 `CADDY_UI_AUDIT_ARCHIVE_HOURS`，默认 48 小时）里找回这条记录，显示每条规则匹配到的变量、匹配片段和值摘录，以及按当前本地策略处理过的请求 URI。

- 只在请求时读取，结果不写入事件文件，也不会上传。
- 内容受当前本地 strict/standard/full 策略约束；standard 隐藏识别出的凭据，显式 full 可保留凭据。
- 原始记录已轮转删除（超过归档保留时间且已读完），或事件来自其他节点时，页面会说明找不到。

本地保留和云端发送的级别可分别调整；Show matched values 同样服从本地级别，strict 不会被这个入口绕过。见 [可配置脱敏](redaction.md)。

## IP 群组

客户端 IP 属于某些 [IP 群组](ip-groups.md) 时，事件标题下显示 **Client IP groups**，点击可查看该地址的群组归属。群组规则的命中也出现在规则列表中：9002000 起为拦截和试运行（"IP group policy: inside office blocked"、"IP group policy (trial): … would be blocked"），9002500 起为引擎和阈值调整。阈值调整规则带有当时生效的 PL 和阈值，事件按这些值计分和判定。

## 人工判定

**Operator review** 记录你对这条事件的判断：

| 判定 | 含义 |
| --- | --- |
| Unreviewed | 未判断（可用于撤销之前的判定） |
| Confirmed false positive | 确认是误报 |
| Confirmed attack | 确认是攻击 |

必须填写原因。判定只保存在本地（`/ui-data/feedback/`），并写入变更历史；它不会自动生成排除或 IP 规则，也不会上传判定内容。

## 误报时怎么处理

**If this was a false positive** 列出参与了判定、可以排除的规则（不含判定规则、UI 自己的规则和高于阻断 PL 的规则），每条规则给出由窄到宽的方案：

| 范围 | 生成的排除 |
| --- | --- |
| narrowest | 该规则 + 精确路径 + 命中的参数（有参数时），例如只在 `/api/posts` 上不检查 `ARGS:content` |
| path prefix | 同一规则和参数，路径放宽到上一级目录，例如 `/api/` 下的所有路径 |
| parameter, whole site | 同一规则只跳过该参数，全站生效 |

不会建议整站移除一条规则；确有需要时在 [规则排除](exclusions.md) 页手动添加。

每个方案都附带影响估算：用该站点近 14 天的事件（最多 2,000 条）模拟应用后，有多少事件不再被拦、涉及多少来源、其中多少来自疑似攻击者。若多条规则各自都能凑够阈值，单独排除其中一条可能显示 0，页面会同时给出全部最窄方案合在一起的效果。

点 **Review →** 打开 [规则排除](exclusions.md) 页，表单已预填；仍需预览 diff 和影响后再应用。只在确认请求合法时才排除。

## REST API

所有 API 都需要 `Authorization: Bearer <CADDY_UI_TOKEN>`。

| 端点 | 作用 |
| --- | --- |
| `GET /api/events` | 事件列表。参数：`range`（`1h`/`24h`/`7d`/`14d`/`30d`，默认 `24h`）或 `from`/`to`（RFC 3339），`site`、`action`、`ip`、`rule`、`path`、`q`、`limit`（1–1000，默认 100）、`offset`、`source=loki`、`cursor`。返回 `{"total":…, "events":[…]}` |
| `GET /api/events/{tx}` | 单个事件；多节点时加 `node` |
| `GET /api/events/{tx}/explain` | 每条命中的解释（含 `note_zh`、`contribution`、`excludable`）和建议的排除及其影响 |

```sh
curl -s -H "Authorization: Bearer $CADDY_UI_TOKEN" \
  "http://127.0.0.1:8080/api/events?range=24h&action=would_block&rule=930130"

curl -s -H "Authorization: Bearer $CADDY_UI_TOKEN" \
  "http://127.0.0.1:8080/api/events/YqBrJkwPrpHwOYMd/explain"
```
