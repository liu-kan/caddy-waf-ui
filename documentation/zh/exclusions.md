# 规则排除

**Exclusions**（`/?tab=exclusions&domain=<站点>`）为确认的误报添加例外：让某条规则（或某个标签下的所有规则）不再检查一部分请求，其他规则照常检查。添加前先预览 diff 和影响。

排除列表保存在 `exclusions-<slug>.conf`（UI 的规范列表，Caddy 不直接 import），每次变化都会重新生成该站点的 WAF overlay。

## 排除范围

| 参数 | 路径 | 效果 | 生成的指令 |
| --- | --- | --- | --- |
| — | — | 全站移除该规则 | `SecRuleRemoveById 942100`（CRS 之后） |
| `q` | — | 全站，该规则不再检查 `ARGS:q`，其他参数照常检查 | `SecRuleUpdateTargetById 942100 "!ARGS:q"` |
| — | `/api/posts/` | 只对匹配路径的请求移除该规则 | 规则 900000x：`REQUEST_FILENAME` 匹配时 `ctl:ruleRemoveById`（CRS 之前） |
| `content` | `/api/posts/` | 只对匹配路径的请求、只跳过该参数（最窄） | 规则 900000x：`ctl:ruleRemoveTargetById=942100;ARGS:content` |

优先用最窄的组合。全站移除一条规则等于让整个站点失去这项检测。

### 字段

| 字段 | 说明 |
| --- | --- |
| Exclude by | 规则编号，或标签（如 `attack-xss`、`attack-sqli`），按标签时作用于带该标签的全部规则 |
| Parameter | 事件中显示的 ARGS 名称，包括查询参数、表单字段和 JSON 字段（如 `json.messages.0.content`）；也可以写 `/正则/` 匹配一组名称，例如 `/^json\.messages\.\d+\.content$/`。只能排除参数，不能排除请求头和 Cookie |
| Path | 以 `/` 开头，按解码后的路径匹配，不含查询串 |
| Path match | `Prefix`（默认，路径以此开头）或 `Exact`（完全相同） |
| Expires at | 可选，UTC 时间。到期后由 Coraza 在每个请求中比对 `TIME_EPOCH` 自动失效，不需要定时重载；条目仍保留在列表中，需手动删除 |
| Note | 随排除保存的说明，最多 200 字 |
| Reason | 写入变更历史的原因，必填 |

带路径或到期时间的排除生成请求级规则，编号从 9000001 开始，每个站点最多 999 条。

### 不能排除的规则

| 规则 | 原因 |
| --- | --- |
| 949110、949111、959100、959101 | 判定规则。排除它们等于关闭拦截，应排除加分的检测规则 |
| 控制流程和相关性规则（如 901xxx 初始化、980xxx） | 它们不检查请求内容，排除会破坏 CRS 的初始化或计分流程 |
| 9000000–9009999 | UI 自己生成的规则 |

列表中已有的旧条目即使不符合上述限制也会保留，不会让站点无法管理。

## 添加排除

推荐从事件出发：在 [事件详情](events.md#误报时怎么处理) 或 [回溯分析](analysis.md#从候选到排除) 中点 **Review →**，表单会按最窄范围预填。

1. 检查或修改表单，选择 **Impact history**，点 **Preview diff and impact**。
2. 查看估算：该排除在近 14 天事件中会放行多少事件、涉及多少来源、其中多少是疑似攻击者。疑似攻击者占比高时缩小范围。
3. 查看 diff，确认生成的指令符合预期；diff 为空表示已有等效的排除。
4. 填写原因，点 **Add exclusion**。

草稿规则与 [策略](policy.md#预览与应用) 相同：30 分钟有效，表单改动或基线文件变化后需要重新预览。

右侧栏列出该站点近 7 天的误报候选（**Use** 直接预填）、命中最多的规则，以及 `exclusions-<slug>.conf` 的当前内容。

## 删除排除

在 **Active exclusions** 中点 **Remove**，确认后立即发布（不经过预览），记入变更历史。如果列表在页面打开后已被其他操作修改，删除会被拒绝，刷新后重试。

## 常见误报

| 规则 | 常见场景 | 建议 |
| --- | --- | --- |
| 942100 等 942xxx | 富文本、代码片段、聊天内容中出现 SQL 片段 | 对该接口路径 + 内容字段做最窄排除 |
| 941xxx | 提交 HTML 的编辑器、Markdown | 同上 |
| 932xxx | 提交命令行、脚本内容（例如 AI 对话、运维工具） | 同上 |
| 920420 | 上传接口使用 `application/octet-stream` 等不在默认列表中的 Content-Type | 在 [策略](policy.md#请求限制) 中把该类型加入允许列表，不要排除整条规则 |
| 920450 | 客户端发送 `Expect: 100-continue`（curl、部分 SDK 上传大文件时） | 按上传路径排除 920450 |
| 911100 | REST 接口使用 PUT、PATCH、DELETE | 在策略中加入允许的方法 |

## 回滚

排除列表和 WAF overlay 分别保存快照。回滚排除快照会恢复当时的列表并重新生成 overlay；回滚 WAF 快照不会改变当前的排除列表。见 [变更历史与回滚](changes-and-rollback.md)。

## REST API

| 端点 | 作用 |
| --- | --- |
| `PUT /api/sites/{domain}/exclusions` | 用请求中的列表**替换**整个排除列表并发布：`{"exclusions":[…],"reason":"…"}` |
| `GET /api/sites/{domain}/policy` | 返回中的 `exclusions` 是当前列表 |
| `POST /api/sites/{domain}/impact` | 估算追加若干排除后的影响和 diff，不应用 |

排除字段：`type`（`id` 或 `tag`）、`value`、`param`、`path`、`path_match`（`prefix`/`exact`）、`expires`（RFC 3339）、`note`。

```sh
curl -s -X POST -H "Authorization: Bearer $CADDY_UI_TOKEN" -H "Content-Type: application/json" \
  -d '{"exclusions":[{"type":"id","value":"942100","param":"content","path":"/api/posts","path_match":"exact"}]}' \
  http://127.0.0.1:8080/api/sites/chat.example.com/impact
```
