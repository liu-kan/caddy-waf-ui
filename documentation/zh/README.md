# caddy-waf-ui 中文文档

caddy-waf-ui 是 [caddy-with-auth](https://github.com/liu-kan/caddy-with-auth) 的 WAF 管理边车：后端镜像原样复用，UI 通过挂载的 overlay 文件和 Caddy Admin API 管理 Coraza WAF。WAF 事件可以经 Grafana Alloy 存到 Grafana Cloud Loki，查看、解释、回溯和调整都在本地 UI 完成。

UI 的页面地址都是 `/?tab=<页面>`。登录与 API 共用一个令牌（`CADDY_UI_TOKEN`）：浏览器用登录后的会话 Cookie，脚本用 `Authorization: Bearer <令牌>`。

## 文档目录

**安装与运行**

- [快速开始](quick-start.md)：用仓库自带的 Compose 示例跑起来。
- [接入现有部署](deployment.md)：把边车并入已有的 caddy-with-auth 部署。
- [配置参考](configuration.md)：全部环境变量、默认值和作用。
- [后端镜像](backend-image.md)：对镜像的要求、哪些改动走挂载、需要固化进镜像时怎么做、CRS 版本与规则字典。
- [Grafana Cloud 与 Alloy](grafana-cloud.md)：上传哪些数据、令牌分权、免费层预算、本地查询云端历史。
- [可配置脱敏](redaction.md)：本地和云端三级策略、hide/keep 名单、历史数据边界。
- [安全与隐私](security.md)：信任边界、令牌、脱敏规则、本地原始日志。
- [升级说明](upgrade-notes.md)：相对上游和早期版本的行为变化。

**查看与分析**

- [概览](overview.md)：站点状态与最近 24 小时的 WAF 情况。
- [WAF 事件](events.md)：事件列表、为什么被拦、本地匹配内容、人工判定。
- [规则字典](rules.md)：规则编号的含义，例如 `930130,949110`。
- [回溯分析](analysis.md)：误报候选、疑似攻击来源、新出现的规则、趋势。
- [审计日志与轮转](audit-log.md)：原始审计日志、读取游标、轮转与归档、磁盘预算。
- [指标](metrics.md)：`/metrics` 与可选的指标上报。

**调整策略**

- [站点与 WAF 模式](sites.md)：On / DetectionOnly / Off，以及三种模式下的发布验证。
- [WAF 策略](policy.md)：paranoia 等级、异常分阈值、调优模式、请求限制、禁用规则组。
- [规则排除](exclusions.md)：按规则 + 路径 + 参数的最小范围例外、到期时间。
- [IP 规则](ip-rules.md)：按访客 IP 的拒绝/允许列表。
- [IP 群组](ip-groups.md)：从 sing-box 规则集（.srs/JSON）或 CIDR 列表导入、定期更新的具名名单，以及按群组的拦截、封禁、试运行、引擎和阈值策略；国家白名单的性能与格式选择。
- [变更历史与回滚](changes-and-rollback.md)：发布阶段、补偿回退、快照与 last_good。

英文版说明见仓库根目录的 [README.md](../../README.md)、[LOCAL-CLOUD.md](../../LOCAL-CLOUD.md)、[INTEGRATION.md](../../INTEGRATION.md) 和 [ARCHITECTURE.md](../../ARCHITECTURE.md)。
