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

`imported-*.jsonl`（从 Loki 导回本地的事件）、本地事件文件、原始审计日志、快照和草稿都不在采集范围内。导出队列由 UI 写出，不上传云端的部署可以设 `CADDY_UI_CLOUD_EXPORT=false` 停止写出，见 [可配置脱敏](redaction.md#文件与查看)。

索引标签只用取值有限的字段：所有流都有 `job="caddy-waf-ui"` 和 `kind`；`event` 另有 `site`、`action`、`node`；`change` 另有 `site`、`action`、`result`；`runtime` 另有 `level`。`event` 的 `tx`、`ip`、`rule_ids_csv`、`path`、`rev` 写入结构化元数据，不作为标签，避免产生大量时间序列。`access` 的 Host 不建标签（通配站点会收到任意 Host）。

## 对接配置（逐步指南）

接入 Grafana Cloud Loki 与 Alloy 需要在 Grafana Cloud 控制台完成凭据与策略创建，并在本地 `.env` 中完成对接配置。整体分为以下步骤：

### 第 1 步：获取 Loki 用户 ID 与基础 URL

1. 登录 [Grafana Cloud 控制台](https://grafana.com/)（`grafana.com/orgs/<your-org>`）。
2. 在 **My Account / Cloud Portal** 中找到目标 Stack，点击 **Loki** 服务卡片上的 **Details**（或在 Hosted Services 列表中点击 Loki）。
3. 记录页面中显示的连接信息：
   - **User / Tenant ID**：通常为 6 位数字（如 `123456`），对应环境变量 `GRAFANA_CLOUD_LOKI_USER`。
   - **Host URL**：形如 `https://logs-prod-012.grafana.net`。

> [!IMPORTANT]
> **URL 格式关键差异**：
> - **Alloy 推送 URL**（`GRAFANA_CLOUD_LOKI_URL`）：必须包含完整路径 `/loki/api/v1/push`（如 `https://logs-prod-012.grafana.net/loki/api/v1/push`）。
> - **UI 查询 URL**（`CADDY_UI_LOKI_URL`）：必须是根 URL，**绝对不能**包含 `/loki/api/v1/push`（如 `https://logs-prod-012.grafana.net`），因为 UI 内部会自动拼接 `/loki/api/v1/query_range`。

### 第 2 步：创建严格权限分离的 Access Policy 与 Token

基于最小权限安全原则，Alloy（负责推送写入）和本地 UI（负责查询读取）必须使用两个独立的 Access Policy 令牌，杜绝使用全局 API Key 或混用权限：

1. 在 Grafana Cloud 控制台左侧导航进入 **Security** -> **Access Policies**（或在 Loki Details 页面点击 **Manage Access Policies**）。
2. **创建 Alloy 推送策略与令牌**：
   - 点击 **Create access policy**。
   - **Policy Name**：填入 `caddy-waf-alloy-write`。
   - **Scopes**：仅勾选 **`logs:write`**。
   - **Label Policies**：保持默认允许全部标签，或确保允许 `job="caddy-waf-ui"` 及其派生标签。
   - 点击 **Create** 保存策略。
   - 在新创建的策略卡片中点击 **Add token**。
   - **Token Name**：填入 `alloy-logs-write`。
   - 选择 Expiration（如 No expiration 或指定有效周期）。
   - 点击 **Create**，复制生成的令牌字符串（格式通常为 `glc_...`）。保存为 `GRAFANA_CLOUD_LOGS_WRITE_TOKEN`。
3. **创建 UI 只读策略与令牌**：
   - 再次点击 **Create access policy**。
   - **Policy Name**：填入 `caddy-waf-ui-read`。
   - **Scopes**：仅勾选 **`logs:read`**。
   - 点击 **Create** 保存策略。
   - 在该策略卡片中点击 **Add token**。
   - **Token Name**：填入 `ui-logs-read`。
   - 点击 **Create**，复制生成的令牌字符串（格式通常为 `glc_...`）。保存为 `GRAFANA_CLOUD_LOGS_READ_TOKEN`。

### 第 3 步：（可选）配置 Grafana 实例 URL 与数据源 UID

如果希望在本地 UI 的事件详情中直接点击 **Open in Grafana Explore** 直跳 Grafana Cloud 查看对应原始日志行，需记录实例与数据源信息：

1. 记录你的 Grafana Cloud 实例根地址（如 `https://my-company.grafana.net`），对应 `CADDY_UI_GRAFANA_URL`。
2. 打开该 Grafana 实例，进入 **Connections** -> **Data sources**。
3. 找到默认的 Loki 数据源（通常名称为 `grafanacloud-logs`），进入详情页查看其 **UID**。默认通常是 `grafanacloud-logs`，对应 `CADDY_UI_GRAFANA_LOKI_DATASOURCE`。

### 第 4 步：在本地 `.env` 中填入配置

在项目根目录的 `.env` 中加入以下配置：

```dotenv
# ==============================================================================
# Grafana Cloud Loki & Alloy 配置
# ==============================================================================

# Alloy 日志推送端点（必须以 /loki/api/v1/push 结尾）
GRAFANA_CLOUD_LOKI_URL=https://logs-prod-012.grafana.net/loki/api/v1/push

# 本地 UI 查询端点（根域名，绝对不能包含 /loki/api/v1/push）
CADDY_UI_LOKI_URL=https://logs-prod-012.grafana.net

# Loki 用户 ID / Tenant ID（从 Loki Details 页面获取的纯数字）
GRAFANA_CLOUD_LOKI_USER=123456

# Alloy 写入令牌（仅 logs:write 权限）
GRAFANA_CLOUD_LOGS_WRITE_TOKEN=glc_...write_token...

# 本地 UI 查询令牌（仅 logs:read 权限）
GRAFANA_CLOUD_LOGS_READ_TOKEN=glc_...read_token...

# 源站节点标识（单机可设为 caddy-local 或主机名，多台源站共用同一 Loki 时必须唯一）
CADDY_UI_NODE=origin-01

# （可选）Grafana 实例根地址与 Loki 数据源 UID，用于事件详情直跳 Explore
CADDY_UI_GRAFANA_URL=https://my-company.grafana.net
CADDY_UI_GRAFANA_LOKI_DATASOURCE=grafanacloud-logs

# 确保云端导出未被禁用（默认 true，若设为 false 则不生成上传队列）
CADDY_UI_CLOUD_EXPORT=true
```

### 第 5 步：启动带 Cloud Profile 的服务

由于 Alloy 配置在 Compose 中隶属于 `profiles: [cloud]`，启动时必须指定 `--profile cloud`：

```sh
# 1. 检查配置与环境变量是否正确展开
docker compose --profile cloud config --quiet

# 2. 启动包括 Alloy 在内的全部容器
docker compose --profile cloud up -d --build

# 3. 检查容器启动日志
docker compose logs --tail=80 -f alloy caddy-waf-ui
```

Alloy 运行资源上限为 256 MiB 内存与 0.5 CPU（内部设置 `GOMEMLIMIT=160MiB`），文件读取偏移量持久化在 `alloy-data` 卷中，即使重启也会从断点继续读取。Alloy 仅通过只读方式挂载数据卷，不接触 Docker socket 或 Caddy Admin socket。

### 第 6 步：端到端验证

依次验证推送上行与查询下行链路：

1. **触发测试事件**：
   通过 curl 或浏览器向 Caddy 发送触发 WAF 规则的测试请求：
   ```sh
   curl -I "http://127.0.0.1/?test=<script>alert(1)</script>"
   ```
2. **检查 Alloy 推送日志**：
   ```sh
   docker compose logs --tail=50 alloy
   ```
   正常情况下 Alloy 会在 1 秒批处理窗口后将事件推送到 Loki，日志中无 HTTP 401/403/404 等错误。
3. **在 Grafana Explore 确认接收**：
   - 打开 Grafana Cloud 控制台进入 **Explore** 页面。
   - 选择 Loki 数据源（`grafanacloud-logs`）。
   - 在查询框中输入 LogQL：
     ```logql
     {job="caddy-waf-ui", kind="event"}
     ```
   - 点击 **Run query**，确认能检索到刚刚触发的 WAF 拦截事件及其标签（`site`, `action`, `node`）和结构化元数据（`tx`, `ip`, `rule_ids_csv`, `path`, `rev`）。
4. **在本地 UI 验证云端查询**：
   - 访问本地 UI（`http://127.0.0.1:8080/events`）。
   - 将页面顶部的 **Storage** 下拉菜单从 "Local (14d)" 切换为 "Grafana Cloud Loki"。
   - 确认列表中正常呈现云端历史记录，右上角无连接异常提示。
   - 进入单条事件详情，点击 **Open in Grafana Explore** 确认能正确跳转到云端对应的日志片段。

---

## 常见问题与排错

| 现象 / 错误信息 | 原因分析 | 解决对策 |
| --- | --- | --- |
| **HTTP 401 Unauthorized**（Alloy 推送或 UI 查询报 401） | 1. `GRAFANA_CLOUD_LOKI_USER` 用户 ID 填写错误<br>2. Token 复制不完整或包含首尾空格<br>3. Write Token 与 Read Token 颠倒配置 | 1. 登录 Grafana Cloud 查看 Loki Details，核对纯数字 User ID<br>2. 重新复制 Token，确认前缀为 `glc_`<br>3. 检查 Alloy 使用的是 write 令牌，UI 使用的是 read 令牌 |
| **HTTP 403 Forbidden**（推送或查询报 403） | 1. Access Policy 缺少必要 Scope<br>2. Label Policy 策略过滤排除了该标签 | 1. 检查推送令牌所属策略是否勾选了 `logs:write`<br>2. 检查查询令牌所属策略是否勾选了 `logs:read`<br>3. 检查策略的 Label Policies 是否限制了 `job="caddy-waf-ui"` |
| **HTTP 404 Not Found**（推送失败或 UI 查询 404） | URL 路径填写错误 | **重点检查 URL 结尾**：<br>- `GRAFANA_CLOUD_LOKI_URL` **必须**以 `/loki/api/v1/push` 结尾<br>- `CADDY_UI_LOKI_URL` **绝对不能**带 `/loki/api/v1/push`（只需根域名） |
| **Alloy 容器未启动** | 执行 `docker compose up` 时未加 `--profile cloud` | 使用 `docker compose --profile cloud up -d` 启动，或在 `.env` 中加入 `COMPOSE_PROFILES=cloud` 作为默认值 |
| **Alloy 日志正常但 Grafana 无数据** | 1. 本地未触发任何 WAF 事件<br>2. 云端导出功能被关闭（`CADDY_UI_CLOUD_EXPORT=false`） | 1. 发送包含攻击特征的测试请求以产生审计日志<br>2. 检查 `.env` 确认 `CADDY_UI_CLOUD_EXPORT=true`<br>3. 检查容器内 `/ui-data/cloud/events/` 目录下是否有生成的 `events-*.jsonl` 文件 |
| **“Open in Grafana Explore” 跳转空白或报错** | 1. `CADDY_UI_GRAFANA_URL` 未配置<br>2. 数据源 UID 不匹配 | 1. 确认已配置 Grafana 实例根地址（如 `https://org.grafana.net`）<br>2. 在 Grafana 数据源设置中核对 Loki 数据源的真实 UID，并在 `.env` 中设置 `CADDY_UI_GRAFANA_LOKI_DATASOURCE=<uid>` |

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
