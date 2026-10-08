# 接入现有部署

已经按原生 Alloy 手册部署了 `/opt/librechat-a/observability` 的用户，请优先使用 [完整迁移手册](observability-migration.md)。它保留已有 `alloy.service` 与指标采集，逐项说明旧文件去留，并提供可合并的配套配置。

把 caddy-waf-ui 作为边车并入已有的 caddy-with-auth 部署。原有的 Caddy 服务、镜像、证书卷（`/data`、`/config`）、DNS 凭据、caddy-security 认证、Cloudflare 可信代理和应用网络全部保留；不要再起第二个监听 80/443 的 Caddy。

## 改 Caddyfile：每个受管站点加两个 import

在站点块的 `route` 里加入 IP 规则和 WAF 两个 import，顺序是 IP 规则 → WAF → 原有的认证与路由：

```caddyfile
chat.example.com {
	route {
		import /etc/caddy/ui-managed/ip-rules-chat_example_com.conf
		import /etc/caddy/ui-managed/waf-chat_example_com.conf
		# 原有的 authenticate / authorize / 路由保持原顺序和匹配器
		reverse_proxy api:3080
	}
}
```

- 站点名必须是普通主机名（字母、数字、`-`、`.`），不支持通配符和端口。文件名中的 `.` 和 `-` 换成 `_`，例如 `chat.example.com` 对应 `waf-chat_example_com.conf`。
- 必须放在 `route` 里。只靠全局 `order coraza_waf first` 不能保证 IP 拒绝排在 WAF 之前。
- 站点已有 `route`/`handle` 时，把 import 放进对应的 route，不改动其匹配器和认证边界。
- 同一请求路径上不要叠两个 WAF。原来手写的 `coraza_waf` 块，先把其中的自定义规则移到 `waf-custom/before.conf` 或 `after.conf`，再删除它。

## 初始化

在 `.env` 中设置：

| 变量 | 取值 |
| --- | --- |
| `CADDYFILE_PATH` | 你的 Caddyfile 在宿主机上的路径 |
| `CADDY_UI_SITES` | 受管站点，逗号或空格分隔，例如 `chat.example.com,api.example.com` |
| `CADDY_IMAGE` | 你正在使用的 caddy-with-auth 标签或 digest；带 IP 匹配插件的镜像见 [使用 coraza-ipset 镜像部署](ipset-image-deployment.md) |

```sh
docker compose run --rm runtime-init
docker compose run --rm ui-config-init
docker compose run --rm --no-deps --entrypoint /usr/local/bin/caddy caddy \
  validate --config /etc/caddy/Caddyfile --adapter caddyfile
```

`ui-config-init` 只补齐缺失的文件，从不覆盖已有的 WAF 配置、排除列表或 IP 列表；只含注释的旧占位文件会被替换为可用的 DetectionOnly 配置。Caddyfile 里 import 了某个站点的 overlay 而该站点没在 `CADDY_UI_SITES` 里时，初始化会失败并提示。

Compose 中的服务名为 `caddy`；并入已有栈时换成实际的服务名，不依赖固定的容器名。

## 卷与 UID

Caddy（DHI 运行时）和 UI 都以 UID/GID 65532 运行。

| 挂载 | Caddy | UI | Alloy（可选） |
| --- | --- | --- | --- |
| Caddyfile | `/etc/caddy/Caddyfile:ro` | 同路径只读，用于 `/load` | 不挂载 |
| 受管 overlay | `/etc/caddy/ui-managed:ro` | `/ui-managed:rw` | 不挂载 |
| 自定义规则 | `/etc/caddy/waf-custom:ro` | `/etc/caddy/waf-custom:ro`（解释自定义规则编号；草稿预览后文件有变化则拒绝应用） | 不挂载 |
| 备份 | 不挂载 | `/backups:rw` | 不挂载 |
| UI 数据（事件、云端导出队列、变更日志、草稿、游标、IP 群组状态） | 不挂载 | `/ui-data:rw` | `/ui-data:ro`（只读取 `cloud/events/`、`changes/`） |
| IP 群组来源文件（可选） | 不挂载 | `/ipgroups:ro`（Compose 中为宿主机 `./ipgroups`） | 不挂载 |
| 审计与访问日志目录 | `/data/logs:rw` | `/data/logs:rw`（改名轮转） | `/caddy-logs:ro` |
| 证书数据 `/data`、配置 `/config` | 读写 | 不挂载 | 不挂载 |
| Admin socket | `/run/caddy-admin:rw` | `/run/caddy-admin:ro` | 不挂载 |

- `runtime-init` 只调整各卷根目录，以及 UI 自有的 overlay、备份、数据和 Alloy 位置目录（目录 0750、文件 0640），不递归改动证书数据和应用日志。
- 原来用 bind mount 的部署，先备份 overlay 和快照，再给 UID 65532 授予 UI 目录和审计日志目录的读写权限。
- 保留原有审计日志路径：换成新的空卷会丢失历史日志。
- 不要为了方便把所有日志放宽到 0644。

## Admin API

默认 Caddyfile 使用 `admin unix//run/caddy-admin/admin.sock`，UI 用 `CADDY_ADMIN_URL=unix:///run/caddy-admin/admin.sock` 连接。socket 所在目录属主 65532、权限 0700，只有 Caddy 和 UI 挂载，不存在 TCP 管理端口。

能连上这个 socket 的进程就能替换全部 Caddy 配置；UI 以只读方式挂载并不会降低这一权限。只给可信的边车挂载它。也支持 HTTP/HTTPS 形式的 Admin URL，此时要自行保证网络隔离，且不要发布 2019 端口；URL 里不允许嵌入凭据。

## 网络

| 网络 | 成员 | 用途 |
| --- | --- | --- |
| `caddy-edge` | Caddy、应用 | 业务流量 |
| `waf-probe`（internal） | Caddy、UI | 发布后的源站请求验证 |
| `ui-access` | UI、Alloy | 发布 UI 的回环端口；Alloy 访问 Grafana Cloud |

UI 只在 `127.0.0.1:8080` 发布。需要远程访问时用 Tailscale 或带 TLS 的反向代理，见 [安全与隐私](security.md)。

## 验证接入

1. 打开 **Domains & WAF**，确认站点出现且模式正确。
2. 对站点发一个必然命中的请求（例如 `/.env`），在 **Events** 看到事件。
3. 改一次模式，在 **Rollback & History** 的变更记录里确认 validate / load / readback 都成功；配置了 `CADDY_UI_PROBE_URLS` 时 request 阶段也应成功。
