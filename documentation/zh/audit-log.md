# 审计日志与轮转

Coraza 把审计记录写入 `CADDY_UI_AUDIT_LOG`（默认 `/data/logs/coraza-audit.log`）。UI 读取它生成本地事件，并负责轮转。原始日志只留在本机，不会上传。

## 写入什么

每个站点的 WAF overlay 都包含以下设置，由 UI 统一生成，不能在 UI 中修改：

| 指令 | 值 | 说明 |
| --- | --- | --- |
| `SecAuditEngine` | `RelevantOnly` | 按响应状态决定是否记录，见下文；调优模式和源站探测会针对单个请求强制记录 |
| `SecAuditLogFormat` | `JSON` | 每行一条记录 |
| `SecAuditLogParts` | `CADDY_UI_AUDIT_LOG_PARTS` | 默认 `AHKZ`：方法、URI、命中规则；`ABHKZ` 另外保留请求头（B） |
| `SecAuditLogFileMode` / `DirMode` | `0640` / `0750` | 只有 UID/GID 65532 可读 |

Coraza 3.8 的 `RelevantOnly` 实际只看状态码：基础配置 `@coraza.conf-recommended` 中 `SecAuditLogRelevantStatus` 为 `^(?:(5|4)(0|1)[0-9])$`，状态为 400–419 或 500–519 的请求才会被记录。因此：

| 请求 | 是否写入原始日志 | 是否成为事件 |
| --- | --- | --- |
| 被拦截（403、400）或 DetectionOnly 下将被拦截 | 是 | 是 |
| 有规则命中但低于阈值，响应 200 | 否；开启调优模式后是 | 调优模式下是（DETECTED） |
| 有规则命中但低于阈值，上游返回 404、401、502 等 | 是 | 是（DETECTED） |
| 没有任何规则命中，上游返回 404、401、502 等 | 是 | 否，读取时跳过 |

最后一类在扫描频繁的站点上数量可观，只占用原始日志的磁盘空间，不进入事件、分析和云端。

UI 的所有功能在 `AHKZ` 下都可用。只有需要在 **Raw Audit Log** 页查看请求头时才改用 `ABHKZ`：请求头包含 Cookie、Authorization 等凭据，只留在本地，规范化事件不会包含它们。修改后在 UI 中对每个站点重新应用一次当前模式，排查完改回 `AHKZ`。

## 读取

UI 每 `CADDY_UI_INGEST_INTERVAL`（默认 2 秒）读取一次新增内容：

- 读取位置保存在 `/ui-data/state/ingest.json`，重启后从断点继续。
- 文件被替换（inode 变化）或被截断后重写（copytruncate），会从头读取；已入库的事件按事务 ID 去重，不会重复。
- 没有任何规则命中、也没有中断的记录，以及 UI 自己的源站探测记录，不生成事件。
- 无法解析的记录被跳过并计入 `waf_ingest_errors_total{kind="parse"}`。

**Events** 和 **Analysis** 页顶部的状态行显示读取进度（已读字节 / 文件大小）、最近一次检查时间和错误。

## 轮转

原始日志超过 `CADDY_UI_AUDIT_ROTATE_MB`（默认 32 MiB，每 30 秒检查一次）时：

1. 改名为 `coraza-audit.log.rotated-<UTC 时间>`，并创建新的空文件；
2. 对每个受管站点重新应用当前模式。新的 revision 让 Coraza 建立新的 WAF 实例，打开新文件；
3. 变更历史中出现操作人为 `audit-maintenance`、原因为 "reopen rotated audit log" 的记录。

UI 继续读取归档文件，直到读完。归档在最后修改超过 48 小时、且已读到末尾后删除；48 小时用于接收长连接请求结束时才写入的记录。

注意：

- 轮转需要至少一个由 UI 管理的 WAF overlay，因为要靠重新应用模式让 Coraza 重新打开文件。
- 每个共享卷只运行一个 UI 实例。
- 中途崩溃时，`/ui-data/audit-reopen.pending` 标记会让下一次检查重试重新打开。
- 不要再对同一文件配置 logrotate 等外部轮转。需要外部轮转时设 `CADDY_UI_AUDIT_ROTATE_MB=0` 关闭 UI 轮转；外部 copytruncate 能被识别，但截断瞬间写入的记录可能丢失。

## 磁盘预算

| 数据 | 位置 | 上限与清理 |
| --- | --- | --- |
| 原始审计日志与归档 | `/data/logs/` | 单文件约 32 MiB 后轮转；归档保留至少 48 小时，读完后删除 |
| 规范化事件 | `/ui-data/events/` | 保留 `CADDY_UI_EVENTS_RETENTION_DAYS`（14 天）；总量上限 `CADDY_UI_EVENTS_DISK_MAX_MB`（128 MiB） |
| 每日汇总 | `/ui-data/rollups/` | 按月存储，长期保留，体积很小 |
| 快照 | `/backups/` | 每站点每种类型 `CADDY_UI_BACKUP_KEEP`（10）份 |
| 变更历史、草稿、误报判定、last_good | `/ui-data/` | 很小 |

规范化事件达到磁盘上限后，UI **暂停读取**审计日志，不会为了腾出空间删除尚未上传的事件；状态行显示 "event disk budget reached"。此时原始日志仍在增长，归档也因未读完而不会被删除。处理方法：缩短保留天数、提高上限，或清理磁盘后等待自动恢复。

审计目录按两天的轮转量预留空间。

## Raw Audit Log 页

**Raw Audit Log**（`/?tab=logs`）直接显示原始审计日志最后 2 MiB 中的记录（包括上面那些没有规则命中的 4xx/5xx 记录），每页 50 条，可按 IP、URI、规则编号或消息搜索，并按 BLOCKED / DETECTED 过滤。它只读当前文件，不读归档，用于排查规范化之前的原始内容。日常查看使用 [WAF 事件](events.md)。

原始记录可能包含请求头，只给可信的运维人员访问 UI。

## 相关指标

| 指标 | 含义 |
| --- | --- |
| `waf_ingest_lag_bytes` | 尚未读取的字节数，持续增长说明读取停滞 |
| `waf_ingest_last_poll_timestamp_seconds` | 最近一次读取时间 |
| `waf_ingest_errors_total{kind}` | `read`、`parse`、`store`（含磁盘上限） |

指标的开启方式见 [指标](metrics.md)。
