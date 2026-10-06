# 概览

**Overview**（`/?tab=overview`，登录后的默认页面）汇总所有受管站点的状态和最近 24 小时的 WAF 情况。

## 页面内容

| 区块 | 内容 |
| --- | --- |
| Admin API 回读 | 本次启动以来最近一次发布的回读结果。失败时列出缺失的站点：此时线上配置与 overlay 不一致，发布已自动回退，到 **Rollback & History** 查看详情。启动后还没有发布过时不显示 |
| Managed Domains | 受管站点数，以及 On、DetectionOnly 各有几个 |
| Active CRS Exclusions | 所有站点的排除条目总数 |
| IP Rule Engine | 拒绝和允许的 IP 条目数 |
| WAF Events (24h) | 最近 24 小时的事件数，其中拦截和将拦截各多少 |
| WAF events — last 24 hours | 拦截、将拦截、低于阈值的数量，来源数，疑似攻击者和误报候选数；命中最多的 8 条规则（编号 × 事件数），点击查看规则解释。**Analyze →** 打开 24 小时的 [回溯分析](analysis.md) |
| Managed Per-Site WAF Domains | 每个站点的模式和最后更新时间。三个按钮可直接切换模式（切到 Off 需确认）；**WAF Conf** 打开 [站点与 WAF 模式](sites.md)，**Rules** 打开该站点的 [规则排除](exclusions.md) |
| Recent WAF events | 最近 24 小时最新的 5 条事件，点击请求打开事件详情，点击规则编号查看解释。**All events →** 打开 [WAF 事件](events.md)，**Raw audit log →** 打开原始审计日志 |

站点名旁出现 **degraded** 表示 overlay 文件头中的模式无法识别，见 [站点与 WAF 模式](sites.md#受管站点)。

## 日常检查

1. 回读状态没有失败提示；
2. 有没有意外处于 Off 或 DetectionOnly 的站点；
3. 24 小时事件中，拦截数是否突增，命中最多的规则是否陌生；
4. 误报候选数不为 0 时，到 **Analysis** 处理。

没有事件时，先看 **Events** 或 **Analysis** 页顶部的状态行：审计日志是否在读取、是否有读取错误。
