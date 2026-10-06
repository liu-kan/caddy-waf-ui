# 指标

UI 在 `/metrics` 提供 Prometheus 文本格式的指标。默认关闭：`CADDY_UI_METRICS_TOKEN` 为空时返回 404。设置后需要 `Authorization: Bearer <CADDY_UI_METRICS_TOKEN>`；这个令牌只能读指标，与登录令牌分开。`/metrics` 与 API 共用每个来源每分钟 120 次的限流。

## 指标列表

| 指标 | 类型 | 标签 | 含义 |
| --- | --- | --- | --- |
| `waf_events_total` | counter | `site`、`action` | 新入库的 WAF 事件，`action` 为 `blocked`、`would_block`、`detected` |
| `waf_rule_hits_total` | counter | `site`、`rule_id`、`action` | 事件中各规则的命中（每个事件每条规则计一次，不含判定规则） |
| `waf_reload_total` | counter | `result` | 发给 Caddy 的配置变更，`success` 或 `failed` |
| `waf_ingest_errors_total` | counter | `kind` | 审计日志读取问题：`read`、`parse`、`store` |
| `waf_ingest_lag_bytes` | gauge | | 审计日志中尚未读取的字节数 |
| `waf_ingest_last_poll_timestamp_seconds` | gauge | | 最近一次读取的 Unix 时间 |
| `waf_events_in_memory` | gauge | | 内存中缓存的事件数 |
| `waf_policy_info` | gauge（值为 1） | `site`、`mode`、`blocking_pl`、`detection_pl`、`tuning` | 每个受管站点当前的模式与策略 |

计数器在 UI 重启后从 0 开始，用 `rate()`/`increase()` 查询。

## 上报到 Grafana Cloud

指标上报是可选的，与日志分开配置。

1. 在 Grafana Cloud 创建一个只有 `metrics:write` 的令牌，记下 Prometheus remote write 地址和实例 ID。
2. 生成一份包含指标采集的 Alloy 配置：

   ```sh
   cat alloy/config.alloy alloy/metrics.alloy.example > alloy/config-metrics.alloy
   ```

3. 在 `.env` 中设置：

   ```dotenv
   ALLOY_CONFIG_PATH=./alloy/config-metrics.alloy
   CADDY_UI_METRICS_TOKEN=          # openssl rand -hex 32
   GRAFANA_CLOUD_PROMETHEUS_URL=https://prometheus-prod-xx.grafana.net/api/prom/push
   GRAFANA_CLOUD_PROMETHEUS_USER=   # 实例 ID
   GRAFANA_CLOUD_METRICS_WRITE_TOKEN=
   ```

4. `docker compose --profile cloud up -d`。

Alloy 每 30 秒采集一次 `caddy-waf-ui:8080/metrics`。示例配置丢弃 `waf_rule_hits_total`：它的序列数是"站点 × 出现过的规则 × 动作"，容易占满免费层的 1 万个活跃序列。规则维度的统计用 **Analysis** 页或 Loki 中的事件即可。

## 建议的告警

| 条件 | 说明 |
| --- | --- |
| `waf_ingest_lag_bytes` 持续增长 | 读取停滞，常见原因是事件磁盘达到上限，见 [审计日志与轮转](audit-log.md#磁盘预算) |
| `time() - waf_ingest_last_poll_timestamp_seconds > 300` | 读取循环没有运行 |
| `increase(waf_ingest_errors_total{kind="store"}[15m]) > 0` | 事件无法写入 |
| `increase(waf_reload_total{result="failed"}[1h]) > 0` | 有配置变更失败，到 **Rollback & History** 查看阶段和错误 |
| `waf_policy_info{mode="Off"}` | 有站点关闭了 WAF |
