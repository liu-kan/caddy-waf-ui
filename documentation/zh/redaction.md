# 可配置脱敏

本地保留和云端发送分别配置；事件详情和管道状态会显示级别。推荐本地保留排查所需的匹配片段，云端只存规则、路径和分数：

```dotenv
CADDY_UI_REDACTION_LOCAL=standard
CADDY_UI_REDACTION_CLOUD=strict
CADDY_UI_REDACTION_HIDE=customer_email,internal_note
CADDY_UI_REDACTION_KEEP=pass_rate,x-correlation-id
CADDY_UI_CLOUD_DISK_MAX_MB=128
```

修改 `.env` 后重新创建 UI：

```sh
docker compose --profile cloud up -d --build caddy-waf-ui alloy
```

Compose 没有配置时两端均为 strict；`.env.example` 明确推荐本地 standard、云端 strict。非法级别会阻止启动，不会静默关闭脱敏。

| 级别 | 保留内容 | 凭据处理 |
| --- | --- | --- |
| `strict` | 规则编号、变量名、路径、查询参数名、分数和策略 | 匹配值隐藏；查询值和请求头不保留 |
| `standard` | 额外保留可分类的匹配值、普通查询值和诊断请求头 | 隐藏识别出的密码、token、Authorization、Cookie 等；未知变量和无法分类的日志片段仍隐藏 |
| `full` | 保留已经采集到的值和请求头，仍受摘录长度限制 | **凭据也会保留**，仅按显式 hide 名单隐藏 |

full 不会自动开启请求体/响应体采集，也不会补回未记录的请求头。默认 `AHKZ` 不含请求头；需要采集时另外选择 `CADDY_UI_AUDIT_LOG_PARTS=ABHKZ`。原始审计文件仍可能含敏感内容，这些配置不会改写它。

standard 按名称识别凭据，不是对任意自由文本的全面秘密检测器。`max_tokens`、`author` 等普通字段不会因子串误判。URI、已解析的 JSON（包括转义键、对象和数组）及表单中的敏感值会处理；某个复合值被隐藏时，它的匹配片段也会隐藏，避免片段再次泄漏凭据。建议根据应用实际字段补充 hide 名单。

## 精细覆盖

- `CADDY_UI_REDACTION_HIDE`：逗号或空格分隔，忽略大小写。匹配完整名称、最后一个点分段或名称中的一个词。所有级别都执行，优先于 keep。
- `CADDY_UI_REDACTION_KEEP`：匹配完整名称或最后一个点分段，覆盖 standard 的内置凭据判断，也可增加诊断请求头或放行某个 Cookie 匹配值。**不能突破 strict 和 hide**。
- 两个名单各最多 64 项，每项 128 字节；不支持通配符和正则。名单作用于本地及云端。
- 例：`hide=password keep=password` 仍隐藏密码；`keep=pass_rate` 可保留业务字段；`keep=authorization` 会明确允许 standard 保留该请求头。

云端不能比本地保留更多内容：本地 standard、云端 full 的有效云端级别是 standard。已经脱掉的内容无法通过调高级别恢复。

## 文件与查看

本地事件写入 `/ui-data/events/events-*.jsonl`；云端策略处理过的副本写入 `/ui-data/cloud/events/events-*.jsonl`。**Alloy 只读后者**，不读本地丰富事件或导回的 `imported-*.jsonl`。首次升级会把已有本地事件按云端策略迁移到导出队列，导回的云端事件不会再次发送。

本地和导出队列分别默认上限 128 MiB、保留 14 天；导出队列只缓存一条完整事件。两次写入都成功后才推进原始读取游标。导出失败会显示错误并等待重试，重试按已有本地记录处理，不会从原始文件重新扩大其信息量。

事件页、API、Raw Audit Log 和 **Show matched values** 都服从当前本地级别。按需原始查询不会绕过 strict；一次最多扫描 64 MiB、单条最多 8 MiB、最长五秒，且同时只跑一个扫描。页面和 API 返回 `Cache-Control: no-store`。

更改级别影响新事件和当前查看，不会改写以前的原始/本地/排队文件，也不能删除已经上传的历史。已有排队记录仍保留当初的级别；从 full 改 strict 不会追溯抹除这些数据。降低之前较宽松的策略时，需要另外处理已有数据及云端保留。

旧 `CADDY_UI_MATCHED_VALUES` 已弃用。裸二进制未设新本地级别时，旧 true 对应 standard，false/未设对应 strict；Compose 使用新变量，应替换旧 `.env` 配置。详情里的匹配值最长 200 字节、匹配片段 160 字节、查询值 1,024 字节、请求头最多 40 个且每个值 256 字节，full 也不是完整请求归档。
