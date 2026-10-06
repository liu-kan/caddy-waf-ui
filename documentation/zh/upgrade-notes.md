# 升级说明

本文列出相对上游 caddy-waf-ui 1.2.0 的行为变化，以及从上游部署迁移的步骤。新部署直接看 [快速开始](quick-start.md) 和 [接入现有部署](deployment.md)。

## 部署

| 项目 | 1.2.0 | 现在 |
| --- | --- | --- |
| 后端镜像 | `ghcr.io/developmi/caddy-waf`（`CADDY_WAF_IMAGE`） | `liukan/caddy-with-auth`（`CADDY_IMAGE`），原样运行 |
| 站点定义 | `SITE_ADDRESS`、`BACKEND_UPSTREAM`、`ACME_EMAIL` | 使用你自己的 Caddyfile（`CADDYFILE_PATH`）；受管站点由 `CADDY_UI_SITES` 指定 |
| Admin API | `admin 0.0.0.0:2019`，UI 用 `http://caddy-waf:2019` | 默认 Unix socket `unix//run/caddy-admin/admin.sock`；HTTP 仍支持 |
| UI 挂载 | 证书卷 `/data` 只读 | 只挂载 `/data/logs`（读写，用于轮转）；新增 `/ui-data` 数据卷 |
| 初始化 | `init-ui-managed.sh` | 一次性服务 `runtime-init`（卷属主）和 `ui-config-init`（补齐 overlay） |
| Caddy 健康检查 | `pgrep caddy` | 移除（DHI 运行时没有 shell） |
| 云端 | 无 | 可选 `alloy` 服务（`cloud` profile） |

## WAF 配置

- **内置 CRS**：默认用 coraza-caddy 内置的 CRS（`load_owasp_crs`、`@coraza.conf-recommended`、`@crs-setup.conf.example`、`@owasp_crs/*.conf`），不再需要 `/etc/caddy/coraza.conf` 和磁盘上的 CRS。仍想用挂载文件时设 `CADDY_UI_CRS_MODE=files`。
- **排除编译进 overlay**：`exclusions-<slug>.conf` 现在是 UI 的规范列表，不再被 overlay 用 `Include` 引用；Caddyfile 只 import `ip-rules-<slug>.conf` 和 `waf-<slug>.conf`，并且要放在站点的 `route` 里。
- **revision 与签名**：每次生成的 overlay 在指令内部带新的 revision 和 `SecComponentSignature`，事件据此还原当时的模式和策略。旧格式的 overlay 在下一次修改时重新生成；没有策略行的旧 overlay 按默认 CRS 策略处理。
- **自定义规则**：放到 `waf-custom/before.conf`（CRS 之前）和 `after.conf`（CRS 之后），不要再手写 `coraza_waf` 块。
- `CADDY_UI_INCLUDE_DIR` 只在初始化时用于核对 import，生成的 overlay 不再依赖它。

## 功能变化

| 功能 | 变化 |
| --- | --- |
| IP 规则 | 使用 Caddy `client_ip`（遵循受信代理）。旧的 `remote_ip` 文件仍可读取，保存时改写为 `client_ip`。页面文案已更正：拒绝是断开连接（`abort`），Allowlist 是白名单 |
| 排除 | 新增参数、路径、到期时间、备注；判定规则（949110 等）、控制类规则和 UI 规则不能再新增为排除，已有条目保留 |
| 回滚 | WAF 快照恢复模式和策略，用当前排除列表重新生成 overlay；排除快照单独回滚。快照名精确到纳秒，旧的秒级名称仍可用 |
| 发布 | 增加 readback、源站探测和失败补偿，阶段写入变更历史；成功版本保存为 `last_good` |
| 页面 | 新增 Events、Analysis、Rules、Policy；原 Logs 页改名 Raw Audit Log，只用于查看原始记录；Overview 的事件统计改为来自本地事件库 |
| 页面上的修改 | 策略和排除改为"预览 → 应用"，应用时校验草稿 |
| API | 原有 5 个端点保留，排除的载荷新增可选字段，旧载荷仍可用；新增事件、规则、分析、策略、影响估算、变更历史、Loki 导入等端点 |
| 指标 | 新增 `/metrics`，默认关闭 |

## 审计日志

- 审计 parts 由 `CADDY_UI_AUDIT_LOG_PARTS` 控制，默认 `AHKZ`（不记录请求头和请求体）；排查请求头时可临时改为 `ABHKZ`。
- UI 负责轮转：超过 32 MiB 改名并重新应用各站点模式。原来用 logrotate 等外部轮转的，二者只能保留一个，见 [审计日志与轮转](audit-log.md#轮转)。
- 没有规则命中的审计记录（Coraza 会记录上游返回的 404、401、5xx 等响应）不再成为事件。

## 从 1.2.0 迁移

1. 备份 `caddy-ui-config`（overlay）和 `caddy-ui-backups`（快照）卷。
2. 按 [配置参考](configuration.md) 更新 `.env`：`CADDY_IMAGE`、`CADDYFILE_PATH`、`CADDY_UI_SITES`、`CADDY_UI_TOKEN`。
3. 修改 Caddyfile：`admin` 改为 Unix socket；每个受管站点在 `route` 中加入两个 import；删除旧的排除 import 和手写的 `coraza_waf` 块，把其中的自定义规则移到 `waf-custom/`。
4. 初始化并校验：

   ```sh
   docker compose run --rm runtime-init
   docker compose run --rm ui-config-init
   docker compose run --rm --no-deps --entrypoint /usr/local/bin/caddy caddy \
     validate --config /etc/caddy/Caddyfile --adapter caddyfile
   ```

5. `docker compose up -d --build`。
6. 在 UI 中对每个站点重新应用一次当前模式，生成新格式的 overlay；在 **Rollback & History** 中确认 load、readback（以及配置了探测地址时的 request）阶段成功。
7. 用一个必然命中的请求（例如 `/.env`）确认 **Events** 中出现事件，且 CRS 版本与 **Rules** 页标题一致。

## 本地与云端独立脱敏（2026-10-06）

用新变量 REDACTION_LOCAL / REDACTION_CLOUD 替换旧 MATCHED_VALUES。推荐本地 standard、云端 strict。升级 Alloy 配置，使其只读 `/ui-data/cloud/events/events-*.jsonl`；旧版本直接读 `/ui-data/events`，不得继续用于本地丰富事件。新 UI 首次启动会把已有本地记录按云端策略迁移到新队列，导回记录跳过；中断可重试。此后新记录双写成功才推进读取位置。迁移失败会停用读取并显示错误，纠正磁盘/权限后重启。

新队列额外默认保留 14 天、上限 128 MiB。已经排队或上传的数据不会因修改策略自动清除。详见 [可配置脱敏](redaction.md)。
