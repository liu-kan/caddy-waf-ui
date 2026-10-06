# IP 规则

**IP Rules**（`/?tab=iprules&domain=<站点>`）按客户端地址拒绝或只允许访问某个站点。规则写入 `ip-rules-<slug>.conf`，在站点 `route` 中位于 WAF 之前，因此被拒绝的请求不会进入 Coraza。

## 两种列表

| 列表 | 生成的配置 | 效果 |
| --- | --- | --- |
| Denylist | `client_ip` 匹配器 + `abort` | 列表中的地址：直接断开连接，不返回任何响应 |
| Allowlist | `not client_ip` 匹配器 + `abort` | **只要列表非空，列表以外的所有地址都被断开** |

Allowlist 是白名单，不是"免检名单"：它不会让列表中的地址绕过 WAF，而是把其他地址全部挡在外面。只想放行少数地址时（例如内部管理站点）才使用。

条目可以是单个 IP 或 CIDR，IPv4 单个地址按 `/32`、IPv6 按 `/128` 保存；无法解析的条目会被拒绝。

## 客户端地址

`client_ip` 由 Caddy 根据 `trusted_proxies` 决定：

- 请求来自受信代理（例如 caddy-with-auth 中配置的 Cloudflare 地址段）时，取代理传来的真实客户端地址；
- 否则取直连对端地址。UI 不会信任任意的转发头。

在 Cloudflare 后面部署却没有配置受信代理时，所有请求的 `client_ip` 都是 Cloudflare 的地址，按访客 IP 的规则不会生效。保留 caddy-with-auth 原有的受信代理配置即可。

WAF 事件中的客户端 IP 来自 Coraza，与这里使用的是同一地址。

## 添加与删除

页面表单每次追加一个条目（DENY 或 ALLOW），立即发布并记入变更历史；IP 规则变化不涉及 WAF overlay，发布阶段为 validate、load、readback。

页面上不能删除单个条目。需要删除时：

- 用 API 提交修改后的完整列表；或
- 在 **Rollback & History** 中恢复之前的 `ip-rules` 快照。

## 与 IP 群组的区别

| | IP 规则 | [IP 群组](ip-groups.md) |
| --- | --- | --- |
| 执行位置 | Caddy，WAF 之前 | Coraza WAF 内，CRS 之前 |
| 效果 | 断开连接，不记录事件 | 403 拦截、试运行（都产生事件）、切换引擎、调整阈值（在被审计的请求中可见） |
| 名单 | 手工维护的少量地址 | 导入的名单（sing-box 规则集或 CIDR 列表），可定期自动更新 |
| 修改方式 | 立即发布 | 随站点策略预览、估算影响、应用和回滚 |

少量需要直接断开的地址用 IP 规则；按地区、网络或合作方等成批地址做策略用 IP 群组。

## 与分析结合

**Analysis** 页列出疑似攻击者，但不会自动封禁。决定封禁前，在事件列表中按该 IP 查看最近 14 天的记录，并确认它不是出口共享地址（公司 NAT、移动网络、代理服务）。长期封禁大段地址更适合放在 Cloudflare 等上游。

## REST API

| 端点 | 作用 |
| --- | --- |
| `PUT /api/sites/{domain}/iprules` | 用请求中的两个列表**替换**当前规则：`{"allowlist":[],"denylist":["198.51.100.7","203.0.113.0/24"]}`。原因可放在 `X-Change-Reason` 请求头中 |

```sh
curl -s -X PUT -H "Authorization: Bearer $CADDY_UI_TOKEN" -H "Content-Type: application/json" \
  -H "X-Change-Reason: scanner confirmed on event YqBrJkwPrpHwOYMd" \
  -d '{"allowlist":[],"denylist":["198.51.100.7"]}' \
  http://127.0.0.1:8080/api/sites/chat.example.com/iprules
```
