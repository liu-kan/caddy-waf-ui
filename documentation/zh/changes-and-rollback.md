# 变更历史与回滚

**Rollback & History**（`/?tab=rollback&domain=<站点>`）列出站点的配置快照和变更历史，可以把任一快照恢复为当前配置。

## 变更历史

所有修改配置的操作都会写入 `/ui-data/changes/changes.jsonl`，页面显示该站点最近 100 条，最新的在前：

| 列 | 内容 |
| --- | --- |
| Change | 动作与摘要，各发布阶段的结果（悬停查看详情），展开 **Diff** 查看生成文件的变化（超过 16 KiB 截断） |
| Reason | 表单或 API 中填写的原因 |
| By | `CADDY_UI_ACTOR_HEADER` 指定的请求头中的用户名；未配置时为请求来源 IP |
| Result | success 或 failed（悬停查看错误） |
| Revision | 本次生成的 WAF overlay revision，可与事件详情中的 revision 对照 |

| 动作 | 来源 |
| --- | --- |
| `mode` | 切换模式；审计日志轮转时以 `audit-maintenance` 身份重新应用当前模式 |
| `policy`、`exclusions` | 策略、排除变化（表单应用的草稿摘要为 "applied reviewed … draft"） |
| `iprules` | IP 规则变化 |
| `rollback` | 恢复快照 |
| `feedback` | 事件的人工判定，不改配置 |
| `ipgroup` | IP 群组名单更新后，重新发布使用该群组的站点（每个站点一条）；群组本身的增删改、待定更新的批准与丢弃也以 `ipgroup` 记录，但不属于某个站点，只在 `GET /api/changes` 不带 `site` 时出现 |

失败的尝试同样记录，带失败阶段和错误信息。启用 Grafana Cloud 时，这些记录以 `kind="change"` 上传，但只包含站点、动作、结果、revision、SHA256 和阶段结果，不含操作人、原因、错误和 diff，可用于 Grafana 注释。

## 发布阶段与补偿

| 阶段 | 含义 |
| --- | --- |
| validate | 输入校验通过 |
| load | Admin API `/load` 接受了新配置 |
| readback | 回读确认站点存在、revision 已生效 |
| request | 源站探测确认新 revision 和模式在处理请求；未配置探测地址时为 skipped |
| compensate | 探测失败后恢复文件并重新加载旧配置的结果 |

任一阶段失败时，UI 恢复修改前的文件；如果新配置已经被 Caddy 加载，再用恢复后的文件重新加载一次。补偿本身失败时，错误会明确返回并记录，需要人工处理（见下文"人工恢复"）。

同一 UI 进程内的修改串行执行；每个 overlay 卷只运行一个 UI 实例。

## 快照

每次修改前，UI 把即将被替换的文件保存到 `/backups/<slug>/<UTC 时间>.<类型>.conf`。修改排除时，除排除列表外还会保存 WAF overlay。每个站点每种类型保留 `CADDY_UI_BACKUP_KEEP`（默认 10）份。

| 类型 | 恢复后的结果 |
| --- | --- |
| `waf` | 恢复快照中的**模式和策略**；overlay 用当前的基线设置和**当前的**排除列表重新生成 |
| `exclusions` | 恢复当时的排除列表，并重新生成 overlay |
| `ip-rules` | 恢复当时的 IP 规则文件 |

WAF 快照和排除快照相互独立：回滚 WAF 快照不会撤销之后添加的排除，要撤销排除请恢复排除快照。早期版本生成的、不含策略行的 WAF 快照恢复时使用默认 CRS 策略。

恢复操作本身也走完整的发布流程，并在恢复前为当前文件再存一份快照，所以回滚可以再回滚。

## last_good

每次发布全部阶段成功后，UI 把生成的 overlay 保存为 `/ui-data/releases/<slug>/last_good.conf`，并在 `last_good.json` 中记录 revision、SHA256、时间和各阶段结果。它是最近一次经过验证的版本，用于事后核对或人工恢复。

## 人工恢复

自动补偿失败（例如 Caddy 在恢复过程中不可用）时：

1. 在 **Rollback & History** 中查看失败记录的阶段和错误；
2. Caddy 恢复后，恢复该站点最近的 `waf` 快照，或重新应用一次当前模式；
3. 仍失败时，用 `caddy validate` 检查 Caddyfile（见 [后端镜像](backend-image.md#全部改动都走挂载)），必要时把最近验证通过的版本复制回受管目录，再在 UI 中重新应用一次模式：

   ```sh
   docker compose exec caddy-waf-ui \
     cp /ui-data/releases/chat_example_com/last_good.conf /ui-managed/waf-chat_example_com.conf
   ```

需要彻底重建某个站点时，先备份它的三个 overlay 文件，只移走该站点的 `waf-<slug>.conf`，再运行 `docker compose run --rm ui-config-init`。不要为了重置站点删除整个卷：卷里还有证书和快照历史。

## REST API

| 端点 | 作用 |
| --- | --- |
| `GET /api/changes` | 变更历史，参数 `site`、`limit`（默认 100）。返回 `{"changes":[…]}` |
| `GET /api/sites/{domain}/backups` | 站点的快照列表 |
| `POST /api/sites/{domain}/rollback` | 恢复快照：`{"backup":"<快照文件名>","reason":"…"}` |

```sh
curl -s -H "Authorization: Bearer $CADDY_UI_TOKEN" \
  "http://127.0.0.1:8080/api/changes?site=chat.example.com&limit=20"
```
