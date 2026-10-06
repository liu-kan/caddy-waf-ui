# 站点与 WAF 模式

**Domains & WAF**（`/?tab=sites&domain=<站点>`）切换单个站点的 Coraza 引擎模式，并显示 UI 为它生成的 `waf-<slug>.conf`。**Overview** 页的站点表也有同样的三个模式按钮。

## 受管站点

UI 扫描 overlay 目录中的 `waf-*.conf`，读取文件头的 `# domain: … | mode: … | updated: …` 识别站点。新站点通过 `CADDY_UI_SITES` 和 `ui-config-init` 初始化（默认 DetectionOnly），并在 Caddyfile 中加入两个 import，见 [接入现有部署](deployment.md)。

文件头中的模式无法识别时，站点显示 **degraded** 标记：页面上的模式可能与 Caddy 实际加载的不一致，重新应用一次模式即可修复。

## 三种模式

| 模式 | 规则执行 | 命中后 | 审计记录 |
| --- | --- | --- | --- |
| On | 执行 | 达到阈值或命中直接拦截规则时拦截：一般返回 403，请求体解析失败返回 400 | 拦截的请求，事件为 BLOCKED |
| DetectionOnly | 执行 | 不拦截，放行给上游 | 将被拦截的请求，事件为 WOULD BLOCK |
| Off | 不执行 | — | 无 |

新站点建议先用 DetectionOnly 运行一段时间（最好同时开启 [调优模式](policy.md#调优模式)），在 **Analysis** 中处理完误报再切到 On。切到 Off 前页面会要求确认。

改模式只改 `SecRuleEngine`，站点的策略和排除保持不变。

## 发布过程

每次修改模式、策略或排除，UI 都按同一流程发布，并把每个阶段记入变更历史：

| 阶段 | 内容 | 失败时 |
| --- | --- | --- |
| validate | 校验输入 | 不做任何修改 |
| （快照） | 保存当前文件到 `/backups/<slug>/` | 不做任何修改 |
| load | 生成新 overlay（带新的 revision），把 Caddyfile 全文发给 Admin API `/load` | 恢复文件 |
| readback | 从 Admin API 回读配置，确认站点存在且 revision 已生效 | 恢复文件，并用恢复后的文件再次 `/load` |
| request | 向源站发一个探测请求，确认新 revision 和模式确实在处理请求 | 恢复文件并重新加载（compensate 阶段） |

所有阶段成功后，生成的 overlay 和各阶段结果保存为 `/ui-data/releases/<slug>/last_good.conf` 与 `last_good.json`，作为最近一次验证通过的版本。

revision 写在 `coraza_waf` 的指令内部。coraza-caddy 按指令文本复用 WAF 实例，revision 变化会强制它新建实例；所以即使只是 `waf-custom` 中的文件内容变了，重新应用一次当前模式也能让新内容生效。

## 源站验证

`CADDY_UI_PROBE_URLS` 为每个站点指定一个探测地址：

```dotenv
CADDY_UI_PROBE_URLS={"chat.example.com":"https://caddy/__waf_health","localhost":"http://caddy"}
```

| 项目 | 行为 |
| --- | --- |
| 请求 | `GET`，Host 为站点名，带 `X-Caddy-WAF-Probe: <revision>`，5 秒超时 |
| HTTPS | 校验证书，SNI 为站点名；不跟随重定向 |
| On | 期望 HTTP 418（overlay 中的规则 9001200 只拦截带当前 revision 的探测请求），并在审计日志中找到带同一 revision 和 `On` 引擎的记录 |
| DetectionOnly | 探测请求照常转发给上游；期望审计日志中有带同一 revision 和 `DetectionOnly` 引擎的记录 |
| Off | 只确认源站可达（非 5xx），revision 由 readback 阶段确认 |
| 失败 | 源站 5xx、连接失败、On 模式状态码不是 418、5 秒内没在审计日志中找到记录 |

注意：

- 地址由运维配置，与请求无关；只接受 `http`/`https`，不能带用户名密码、查询串或片段。
- 探测地址必须从 UI 容器可达。Compose 中 UI 与 Caddy 通过内部网络 `waf-probe` 互通，所以示例使用 `http://caddy`。
- DetectionOnly 下探测请求会到达上游应用，选择没有副作用的路径，例如健康检查。
- 没有为某站点配置地址时，request 阶段记为 skipped，只做 readback 校验。
- 探测记录不计入 WAF 事件。

## REST API

| 端点 | 作用 |
| --- | --- |
| `PUT /api/sites/{domain}/mode` | 切换模式：`{"mode":"On","reason":"…"}`，`mode` 为 `On`、`DetectionOnly`、`Off` |
| `GET /api/sites/{domain}/policy` | 返回当前的 `mode`、`policy`、`revision`、`exclusions` 和是否受管（`managed`） |

```sh
curl -s -X PUT -H "Authorization: Bearer $CADDY_UI_TOKEN" -H "Content-Type: application/json" \
  -d '{"mode":"On","reason":"two weeks in DetectionOnly, false positives handled"}' \
  http://127.0.0.1:8080/api/sites/chat.example.com/mode
```

成功返回 `{"status":"success"}`；站点名不合法或模式无效返回 400；发布失败返回 500，详情在变更历史中。
