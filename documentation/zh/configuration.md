# 配置参考

UI 只通过环境变量配置。Compose 部署时写在 `.env`（权限 0600，不入 Git）；修改后用 `docker compose up -d` 重建容器，`restart` 不会重新读取 `.env`。

所有路径型变量都由运维设置，不来自请求数据。WAF 基线相关的设置（CRS 模式、include 路径、审计 parts）不能通过 UI 或 API 修改。

## 访问与 Caddy

| 变量 | 说明 | 默认值 |
| --- | --- | --- |
| `CADDY_UI_TOKEN` | UI 登录和 API Bearer 共用的令牌。用 `openssl rand -hex 32` 生成；至少 32 个字符，过短或仍为 `.env.example` 占位值时拒绝启动 | 无（必填） |
| `CADDY_UI_BIND` | UI 监听地址 | `0.0.0.0:8080`（Compose 只发布到宿主机 `127.0.0.1:8080`） |
| `CADDY_ADMIN_URL` | Caddy Admin API：`unix:///绝对路径` 或 `http(s)://主机:端口`，不允许带凭据 | 单独运行 `http://caddy:2019`；Compose 中为 `unix:///run/caddy-admin/admin.sock` |
| `CADDY_UI_CADDYFILE` | 发给 `/load` 的 Caddyfile（UI 容器内路径） | `/etc/caddy/Caddyfile` |
| `CADDY_UI_ACTOR_HEADER` | 可信认证代理写入的用户名请求头，例如 caddy-security 设置的头。只用于变更日志里的操作人，不参与授权 | 空 |
| `CADDY_UI_LOG_LEVEL` | UI 自身日志级别：`debug`/`info`/`warn`/`error` | `info` |

## 受管站点与文件

| 变量 | 说明 | 默认值 |
| --- | --- | --- |
| `CADDY_UI_SITES` | `init` 子命令要初始化的站点，逗号或空格分隔 | Compose 中为 `localhost` |
| `CADDY_UI_MANAGED_DIR` | UI 看到的 overlay 目录 | `/ui-managed` |
| `CADDY_UI_INCLUDE_DIR` | Caddy 看到的同一目录，初始化时用于核对 import | `/etc/caddy/ui-managed` |
| `CADDY_UI_BACKUP_DIR` | 配置快照目录 | `/backups` |
| `CADDY_UI_BACKUP_KEEP` | 每个站点、每种类型保留的快照数 | `10` |
| `CADDY_UI_DATA_DIR` | UI 数据卷：事件、汇总、变更日志、草稿、误报判定、读取游标、last_good | `/ui-data` |

## WAF 基线

| 变量 | 说明 | 默认值 |
| --- | --- | --- |
| `CADDY_UI_CRS_MODE` | `embedded` 使用 coraza-caddy 内置的 CRS；`files` 使用挂载的规则文件 | `embedded` |
| `CADDY_UI_CORAZA_CONFIG` | 基础配置 include | embedded：`@coraza.conf-recommended`；files：`/etc/caddy/coraza.conf` |
| `CADDY_UI_CRS_SETUP` | CRS setup include | embedded：`@crs-setup.conf.example`；files：`/etc/caddy/owasp-crs/crs-setup.conf` |
| `CADDY_UI_CRS_RULES` | CRS 规则 include/glob | embedded：`@owasp_crs/*.conf`；files：`/etc/caddy/owasp-crs/rules/*.conf` |
| `CADDY_UI_WAF_BEFORE_FILE` | 运维自有规则，在 CRS 之前加载（Caddy 容器内路径） | 空；Compose 中为 `/etc/caddy/waf-custom/before.conf` |
| `CADDY_UI_WAF_AFTER_FILE` | 运维自有规则，在 CRS 之后加载 | 空；Compose 中为 `/etc/caddy/waf-custom/after.conf` |
| `CADDY_UI_RESPONSE_BODY_ACCESS` | `On`/`Off`。保持 `Off` 可避免流式接口（SSE、大文件下载）被缓冲 | `Off` |
| `CADDY_UI_AUDIT_LOG_PARTS` | Coraza 审计日志记录的部分。`AHKZ` 含方法、URI 和命中规则；`ABHKZ` 另外保留请求头（含 Cookie、Authorization，只在本地）。都不含请求/响应体 | `AHKZ` |
| `CADDY_UI_CRS_RULES_DIR` | 启动时解析该目录下的规则文件，刷新规则字典（后端 CRS 版本不同、或要解释 before/after 中的自定义规则时使用） | 空 |

路径中不能含空白、引号或花括号。改了 before/after 文件内容后，在 UI 中重新应用一次该站点的当前模式，新内容才会生效（每次生成的 revision 不同，会强制 Coraza 建新实例）。

## 审计日志与本地事件

| 变量 | 说明 | 默认值 |
| --- | --- | --- |
| `CADDY_UI_AUDIT_LOG` | Coraza 原始审计日志，Caddy 与 UI 中路径相同 | `/data/logs/coraza-audit.log` |
| `CADDY_UI_AUDIT_ROTATE_MB` | 原始日志超过该大小就改名轮转并让 WAF 重新打开文件；`0` 关闭 | `32` |
| `CADDY_UI_AUDIT_ARCHIVE_HOURS` | 轮转后的原始归档在最后写入后保留的小时数（最少 48），期间可在事件页查看本地匹配内容 | `48` |
| `CADDY_UI_INGEST_INTERVAL` | 读取审计日志的间隔 | `2s` |
| `CADDY_UI_EVENTS_RETENTION_DAYS` | 本地规范化事件保留天数（每日汇总另外长期保留） | `14` |
| `CADDY_UI_EVENTS_DISK_MAX_MB` | 本地规范化事件文件的磁盘上限；到达上限后暂停读取，不删除未上传的事件 | `128` |
| `CADDY_UI_EVENTS_MEMORY_MAX` | 内存中缓存的完整事件条数；更早的事件按磁盘偏移读取 | `1000` |
| `CADDY_UI_REDACTION_LOCAL` | 本地 strict/standard/full；示例文件推荐 standard | Compose 未设时 strict |
| `CADDY_UI_REDACTION_CLOUD` | 云端 strict/standard/full，有效级别不能宽于本地 | strict |
| `CADDY_UI_REDACTION_HIDE` | 两端都隐藏的名称，优先于 keep | 空 |
| `CADDY_UI_REDACTION_KEEP` | 覆盖 standard 内置判断的名称，不突破 strict/hide | 空 |
| `CADDY_UI_CLOUD_DISK_MAX_MB` | 独立云端导出队列上限 | 128 |
| `CADDY_UI_CLOUD_EXPORT` | 是否为 Alloy 写出按云端级别脱敏的事件副本；不上传 Grafana Cloud 时设 `false` 节省磁盘和 CPU。重新打开后会把保留期内的本地事件补入队列 | `true` |
| `CADDY_UI_NODE` | 节点标识，写入每条事件。多台源站共用一个 Loki 时必须各不相同 | 主机名；Compose 中为 `caddy-local` |
| `CADDY_UI_PROBE_URLS` | 每个站点的源站验证 URL，JSON 对象，例如 `{"chat.example.com":"https://origin.internal/__waf_health"}` | 空（跳过请求验证） |

## IP 群组

| 变量 | 说明 | 默认值 |
| --- | --- | --- |
| `CADDY_UI_IPGROUP_DIR` | 文件来源所在目录（UI 容器内），只读挂载 | `/ipgroups` |
| `CADDY_UI_IPGROUP_MAX_PREFIXES` | 单个群组名单的最大前缀数。标准镜像中匹配耗时与前缀数成正比；带 coraza-ipset 插件的镜像中与前缀数无关，上限取决于内存和加载时间。调高前先看 [性能与名单规模](ip-groups.md#性能与名单规模) | `100000` |
| `CADDY_UI_IPGROUP_PROXY` | 只用于群组下载的 HTTP(S) 代理，例如 `http://10.0.0.2:7890`；为空时使用 `HTTPS_PROXY`/`NO_PROXY` | 空 |
| `CADDY_UI_IPGROUP_PATH` | （仅 Compose）挂载到 `/ipgroups` 的宿主机目录 | `./ipgroups` |

详见 [IP 群组](ip-groups.md)。

## Grafana Cloud 与指标

| 变量 | 说明 | 默认值 |
| --- | --- | --- |
| `CADDY_UI_LOKI_URL` | Loki 查询地址（不含 `/loki/api/v1/push`），例如 `https://logs-prod-012.grafana.net` | 空（不查云端历史） |
| `CADDY_UI_LOKI_USER` | Loki 租户 ID。Compose 中取自 `GRAFANA_CLOUD_LOKI_USER` | 空 |
| `CADDY_UI_LOKI_TOKEN` | 仅含 `logs:read` 的令牌。Compose 中取自 `GRAFANA_CLOUD_LOGS_READ_TOKEN` | 空 |
| `CADDY_UI_LOKI_SELECTOR` | 事件流选择器 | `{job="caddy-waf-ui",kind="event"}` |
| `CADDY_UI_LOKI_SYNC_INTERVAL` | 定期把其他节点的事件导入本地；`0` 只按需查询 | `0` |
| `CADDY_UI_GRAFANA_URL` | Grafana 实例地址，用于事件详情里的 Explore 链接 | 空 |
| `CADDY_UI_GRAFANA_LOKI_DATASOURCE` | Explore 链接使用的 Loki 数据源 UID | `grafanacloud-logs` |
| `CADDY_UI_METRICS_TOKEN` | `/metrics` 的 Bearer 令牌；为空时 `/metrics` 返回 404。设置时至少 32 个字符，且不能与 `CADDY_UI_TOKEN` 相同 | 空 |

## 仅 Compose 使用的变量

| 变量 | 说明 | 默认值 |
| --- | --- | --- |
| `CADDY_IMAGE` | 后端镜像标签或 digest | `liukan/caddy-with-auth:latest` |
| `CADDYFILE_PATH` | 宿主机上的 Caddyfile | `./Caddyfile.example` |
| `EXAMPLE_APP_IMAGE` | 示例上游 | `containous/whoami:v1.5.0` |
| `ALLOY_IMAGE` | Alloy 镜像 | `grafana/alloy:v1.20.0` |
| `ALLOY_CONFIG_PATH` | Alloy 配置文件 | `./alloy/config.alloy` |
| `GRAFANA_CLOUD_LOKI_URL` | Alloy 推送地址，含 `/loki/api/v1/push` | 空 |
| `GRAFANA_CLOUD_LOKI_USER` | Loki 租户 ID（Alloy 与 UI 共用） | 空 |
| `GRAFANA_CLOUD_LOGS_WRITE_TOKEN` | 仅含 `logs:write` 的令牌，只给 Alloy | 空 |
| `GRAFANA_CLOUD_LOGS_READ_TOKEN` | 仅含 `logs:read` 的令牌，只给 UI | 空 |
| `GRAFANA_CLOUD_PROMETHEUS_URL` / `_USER` / `GRAFANA_CLOUD_METRICS_WRITE_TOKEN` | 可选的指标上报，见 [指标](metrics.md) | 空 |

## 资源预算（Compose 默认）

| 组件 | 上限 |
| --- | --- |
| Caddy | 512 MiB、1 CPU |
| UI | 256 MiB、0.5 CPU |
| Alloy | 256 MiB、0.5 CPU，`GOMEMLIMIT=160MiB` |
| 规范化事件 | 14 天、128 MiB |
| 分析与影响估算样本 | 最新 2,000 条匹配事件 |

原始审计日志的归档、快照、草稿、汇总和 Alloy 位置文件另占磁盘，不计入 128 MiB。审计目录按两天的轮转量预留空间。

三级含义、配置例子和迁移行为见 [可配置脱敏](redaction.md)。旧 MATCHED_VALUES 仅保留裸二进制兼容，应迁移到新变量。
