# WAF 策略

**Policy**（`/?tab=policy&domain=<站点>`）按站点调整 CRS 的 paranoia 等级、异常分阈值、调优模式和请求限制。修改先预览 diff 和影响，再应用；每次应用都记入变更历史，可回滚。

策略写成 `SecAction` 规则 9001000–9001005，放在 CRS setup 和 before 文件之后、CRS 规则之前，因此覆盖 `crs-setup.conf.example` 和 before 文件中的同名设置。模式在 [站点与 WAF 模式](sites.md) 页修改。

## Paranoia 等级

| 设置 | 范围 | 说明 |
| --- | --- | --- |
| Blocking level | 1–4，默认 1 | 这一级及以下的规则参与计分和拦截 |
| Detection level | Blocking level–4，默认与 Blocking level 相同 | 更高级别的规则也执行并记录，但不计入阻断分、不拦截 |

| PL | 适用 |
| --- | --- |
| 1 | 默认，误报少 |
| 2 | 增加编码、混淆类攻击检测，有一定误报 |
| 3 | 严格，误报较多 |
| 4 | 极严格，只适合接口很少、可控的 API |

提高 PL 的做法：先把 Detection level 设为 Blocking level + 1 并开启调优模式，运行一周左右；这期间高一级规则的命中会被记录（事件详情中标为只记录不阻断），影响估算据此判断提高 Blocking level 后会新拦截哪些请求。

## 异常分阈值

| 设置 | 范围 | 默认 | 判定规则 |
| --- | --- | --- | --- |
| Inbound threshold | 1–10000 | 5 | 949110 / 949111 |
| Outbound threshold | 1–10000 | 4 | 959100 / 959101 |

一条 CRITICAL 规则加 5 分，ERROR 4 分，WARNING 3 分，NOTICE 2 分。入站阈值 5 意味着一条 CRITICAL 命中就会拦截。调高阈值会放过所有规则的低分组合，通常不如针对单条规则的 [排除](exclusions.md) 精确。

**Early blocking**：在阶段 1 和阶段 3 结束时也做一次判定（949111、959101），请求头阶段就能拦截，不必等到读完请求体。

## 调优模式

Coraza 的 `RelevantOnly` 只记录响应为 4xx/5xx 的请求：被拦截或将被拦截的请求会被记录，而命中规则但未达阈值、正常返回 200 的请求不会。开启 **Tuning mode** 后，规则 9001100 让入站或出站检测分大于 0 的请求都写入审计日志（事件动作为 `detected`）。

作用：

- 降低阈值或提高 PL 前，影响估算需要这些低于阈值的记录；
- 新站点在 DetectionOnly 阶段能看到全部命中，更容易发现误报。

代价是审计日志、本地事件和云端用量增加。调优完成后关闭。

## 请求限制

| 设置 | 留空时 | 说明 |
| --- | --- | --- |
| Allowed methods | CRS 默认：`GET HEAD POST OPTIONS` | 其他方法命中 911100。REST 接口通常需要加上 `PUT PATCH DELETE` |
| Allowed request content types | CRS 默认列表（表单、multipart、XML、JSON 等） | 填写后**替换**默认列表，要把仍需要的类型都写上；格式为 `type/subtype`，不含参数 |
| Request body limit | 基础配置 13107200 字节（12.5 MiB） | 最大 1 GiB。On 模式下请求体达到此大小直接返回 **413**，DetectionOnly 下不拦截 |

有文件上传的站点要特别注意请求体限制：切换到 On 后，超过限制的上传会被 413 拒绝，事件详情显示为没有判定规则的拦截。按业务允许的最大上传调整，或在 Caddy 层面另行限制上传大小。

## 禁用规则组

可以整组关闭以下 CRS 规则文件（`SecRuleRemoveById NNN000-NNN999`）：911、913、920、921、922、930、931、932、933、934、941、942、943、944、950–956。初始化（901）、判定（949/959）和相关性（980）不能关闭。

整组关闭会让该站点失去这一类检测，例如对纯 Node.js 站点关闭 933（PHP 注入）是合理的，关闭 942（SQL 注入）通常不合理。只是个别规则误报时，用 [排除](exclusions.md)。

## IP 群组规则

**IP group rules** 为属于所选 [IP 群组](ip-groups.md) 之一（inside any）或一个都不属于（outside all）的客户端设置独立策略，按顺序在 CRS 之前执行。一条规则可选多个群组，例如 `cn`、`jp` · outside all · ban 只允许这两个国家访问：

| 动作 | 效果 |
| --- | --- |
| block | 返回 403，记录为事件 |
| ban | 返回 403，不记录事件，用于流量大的白名单 |
| trial | 只记录本会拦截的请求，不拦截。上线 block 或 ban 前先用它观察真实流量 |
| engine | 切换规则引擎：On、DetectionOnly 或 Off |
| tune | 改 blocking/detection PL、入站/出站阈值；留空的项沿用上面的站点策略 |

表格末尾留有空行用于新增；群组列可多选（按住 Ctrl，macOS 为 ⌘）；勾选 **Remove** 删除一条。群组规则随站点策略一起预览、估算影响、应用和回滚，规则的语义、执行顺序与示例见 [IP 群组](ip-groups.md#群组规则)。

## 预览与应用

1. 修改表单，选择 **Impact history**（本地或 Grafana Cloud Loki），点 **Preview diff and impact**。
2. 页面显示生成的 overlay diff，以及用该站点近 14 天事件（最多 2,000 条）估算的影响：多少事件会改变结果、多少不再被拦、多少新被拦、涉及多少来源和疑似攻击者，并附上若干样本事件和局限说明。
3. 填写原因，点 **Apply reviewed policy**。

应用时 UI 校验草稿：

- 草稿 30 分钟内有效；同一站点只保留最新的一份，再次预览会替换它；
- 表单内容必须与预览时一致；
- 预览之后 overlay、排除列表、IP 规则、Caddyfile、before/after 文件或策略用到的 IP 群组名单有变化，应用会被拒绝。

被拒绝时重新预览即可。

## REST API

API 直接应用，不经过草稿流程，用于自动化；同样会校验、写快照、记录变更历史，失败时补偿回退。

| 端点 | 作用 |
| --- | --- |
| `GET /api/sites/{domain}/policy` | 当前模式、策略、revision 和排除列表 |
| `PUT /api/sites/{domain}/policy` | 应用策略：`{"policy":{…},"reason":"…"}` |
| `POST /api/sites/{domain}/impact` | 只估算不应用：`{"policy":{…}}`、`{"exclusions":[…]}` 或 `{"mode":"On"}`，可选 `range`（默认 `14d`）和 `source`。返回 `impact` 和 overlay `diff` |

策略字段：`blocking_pl`、`detection_pl`、`inbound_threshold`、`outbound_threshold`、`early_blocking`、`tuning`、`allowed_methods`、`allowed_content_types`、`request_body_limit`、`disabled_groups`、`ip_groups`（见 [IP 群组](ip-groups.md#rest-api)）。省略的数值字段取默认值。

```sh
curl -s -X POST -H "Authorization: Bearer $CADDY_UI_TOKEN" -H "Content-Type: application/json" \
  -d '{"policy":{"blocking_pl":2,"detection_pl":2,"inbound_threshold":5,"outbound_threshold":4,"tuning":true}}' \
  http://127.0.0.1:8080/api/sites/chat.example.com/impact
```
