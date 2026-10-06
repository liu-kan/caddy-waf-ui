# Grafana Cloud 与 Alloy

可选功能。启用后，Grafana Alloy 把脱敏后的 WAF 事件和少量元数据推送到 Grafana Cloud Loki；查看、解释、分析仍在本地 UI 完成，UI 用只读令牌直接查询 Loki。本地不需要运行 Loki、Grafana 或数据库。

不启用时，UI 只使用本地保留的事件（默认 14 天），其余功能不受影响。

## 上传哪些数据

Alloy 只读取 UI 数据卷和日志目录（均只读挂载），配置见 `alloy/config.alloy`。

| 类型（`kind`） | 来源 | 上传的字段 | 不上传 |
| --- | --- | --- | --- |
| `event` | `/ui-data/cloud/events/events-*.jsonl` | 独立云端策略处理的 WAF 事件；strict 默认只保留规则、变量名、路径、分数等 | 原始文件及云端策略去掉的内容；显式 full 可发送已采集的凭据 |
| `change` | `/ui-data/changes/changes.jsonl` | 站点、动作、结果、revision、SHA256、各阶段名称与结果 | 操作人、原因、错误信息、diff、草稿、误报判定 |
| `access` | Caddy `access*.json`（示例 Caddyfile 中配置） | 站点、客户端 IP、对端 IP、方法、路径、状态码、耗时、大小 | 请求头、查询串、User-Agent |
| `runtime` | Caddy `error*.json` | 时间、级别、logger | 消息正文 |

`imported-*.jsonl`（从 Loki 导回本地的事件）、原始审计日志、快照和草稿都不在采集范围内。

索引标签只用取值有限的字段：所有流都有 `job="caddy-waf-ui"` 和 `kind`；`event` 另有 `site`、`action`、`node`；`change` 另有 `site`、`action`、`result`；`runtime` 另有 `level`。`event` 的 `tx`、`ip`、`rule_ids_csv`、`path`、`rev` 写入结构化元数据，不作为标签，避免产生大量时间序列。`access` 的 Host 不建标签（通配站点会收到任意 Host）。

## 配置

在 Grafana Cloud 中为 Loki 创建两个 Access Policy 令牌：一个只有 `logs:write`，给 Alloy；一个只有 `logs:read`，给 UI。

```dotenv
# Alloy 推送地址，包含完整路径
GRAFANA_CLOUD_LOKI_URL=https://logs-prod-012.grafana.net/loki/api/v1/push
# UI 查询地址，不含 /loki/api/v1/push
CADDY_UI_LOKI_URL=https://logs-prod-012.grafana.net
GRAFANA_CLOUD_LOKI_USER=123456
GRAFANA_CLOUD_LOGS_WRITE_TOKEN=glc_...
GRAFANA_CLOUD_LOGS_READ_TOKEN=glc_...
# 多台源站共用一个 Loki 时必须各不相同
CADDY_UI_NODE=origin-01
```

```sh
docker compose --profile cloud config --quiet
docker compose --profile cloud up -d --build
docker compose logs --tail=80 alloy caddy-waf-ui
```

Alloy 的上限为 256 MiB 内存、0.5 CPU（`GOMEMLIMIT=160MiB`），它的读取位置保存在 `alloy-data` 卷，重启后从断点继续。Alloy 不挂载 Docker socket 或 Caddy Admin socket。

在 Grafana Explore 中用 `{job="caddy-waf-ui",kind="event"}` 确认数据已到达。

## 免费层预算

Grafana Cloud 免费层的日志额度为每月 50 GB、保留 14 天，指标为 1 万个活跃序列（以 Grafana 官网当前说明为准）。

| 数据 | 单条大小 | 说明 |
| --- | --- | --- |
| WAF 事件 | 平均约 1.5 KB，最大约 3 KB | 原始审计记录平均约 16 KB，不上传 |
| 访问日志 | 约 0.2 KB | 通常是主要用量：每天 100 万请求约 6 GB/月 |
| 变更、运行日志 | 很小 | 可忽略 |

请求量很大时，可以从 `alloy/config.alloy` 中去掉 `access` 部分，或从 Caddyfile 中删掉 `access.json` 日志。指标默认不上传；启用方法见 [指标](metrics.md)。

## 在本地 UI 查看云端历史

配置了 `CADDY_UI_LOKI_URL` 后：

- **Events** 和 **Analysis** 页的 **Storage** 选择器可以选 "Grafana Cloud Loki"。时间范围超过 24 小时时默认查询 Loki。
- 云端列表按游标分页，用 **Older →** 继续往前翻。查询出错，或同一时间戳的记录过多导致结果可能不完整时，页面会明确提示。
- 打开云端事件时，详情页用 Loki 中同站点近 14 天的事件（最多 2,000 条）做排除建议和影响估算。
- **Policy** 和 **Exclusions** 的影响估算可以通过 **Impact history** 选择云端历史。
- 设置了 `CADDY_UI_GRAFANA_URL` 后，事件详情有 **Open in Grafana Explore** 链接，数据源 UID 由 `CADDY_UI_GRAFANA_LOKI_DATASOURCE` 指定。

### 导回本地

**Events** 页的 **Backfill** 把最近 24 小时、7 天或 14 天的云端事件导入本地（写入 `imported-*.jsonl`，不会再次上传）。导回后按本地事件查询，速度更快，也能参与 **Rules** 页的 14 天统计。单次导入最多 31 天、128 次查询，超出时会报错并要求缩小范围。

多台源站时，设置 `CADDY_UI_LOKI_SYNC_INTERVAL`（例如 `10m`），UI 会定期导入其他节点的事件。默认 `0`，只按需查询。

导回的事件按 `(节点, 事务 ID)` 去重。只有事件产生的那台节点能读取它的原始审计记录（见 [WAF 事件](events.md#本地匹配内容)）。

## REST API

| 端点 | 作用 |
| --- | --- |
| `GET /api/events?source=loki` | 查询云端事件，参数与本地查询相同，另有 `cursor`（取上一页返回的 `next_cursor`）；`more` 为 true 表示还有更早的记录 |
| `GET /api/events/{tx}?node=&ts=` | 本地找不到时到 Loki 查找单个事件；`ts` 可缩小查询范围 |
| `POST /api/loki/backfill` | 导入一段时间的云端事件：`{"from":"2026-10-01T00:00:00Z","to":"2026-10-06T00:00:00Z"}`，最长 31 天 |

```sh
curl -s -H "Authorization: Bearer $CADDY_UI_TOKEN" \
  "http://127.0.0.1:8080/api/events?source=loki&range=7d&rule=930130&limit=50"
```

本地丰富事件不会直接发送；云端队列按独立策略处理。三级含义及历史数据边界见 [可配置脱敏](redaction.md)。
