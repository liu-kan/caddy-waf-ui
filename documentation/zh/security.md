# 安全与隐私

## 信任边界

| 凭据或接口 | 拥有者 | 能做什么 |
| --- | --- | --- |
| `CADDY_UI_TOKEN` | 运维人员 | 登录 UI、调用 API：修改所有受管站点的 WAF 模式、策略、排除和 IP 规则 |
| Caddy Admin socket | Caddy、UI | 替换 Caddy 的全部配置。UI 以只读方式挂载 socket 目录，但仍可连接 |
| `GRAFANA_CLOUD_LOGS_READ_TOKEN` | UI | 读取 Loki 中的日志 |
| `GRAFANA_CLOUD_LOGS_WRITE_TOKEN` | Alloy | 向 Loki 写日志 |
| `CADDY_UI_METRICS_TOKEN` | Alloy | 读取 `/metrics` |

UI 的令牌等同于 WAF 管理员权限，Admin socket 等同于 Caddy 管理员权限。只给可信的边车挂载 socket；Alloy 不挂载 socket，也不挂载 Docker socket。

## 登录与会话

- 用 `openssl rand -hex 32` 生成 `CADDY_UI_TOKEN`，放在 `.env`（0600，不入 Git）或密钥管理系统中。
- 浏览器登录后得到会话 Cookie：`HttpOnly`、`Secure`、`SameSite=Strict`，有效期 12 小时。页面上的修改操作都带 CSRF 令牌。
- 会话是无状态的。**Sign out** 只清除本机 Cookie，不能吊销已签发的会话；怀疑泄露时更换 `CADDY_UI_TOKEN` 并重建容器。
- `/api/*` 只接受 `Authorization: Bearer <CADDY_UI_TOKEN>`，不接受 Cookie。
- 令牌比较使用常数时间比较。

限流（进程内存中计数）：

| 入口 | 限制 |
| --- | --- |
| `POST /login` | 每个来源每分钟 5 次，全局每分钟 60 次 |
| `/api/*`、`/metrics` | 每个来源每分钟 120 次，突发 30 次 |

UI 前面有反向代理时，所有请求的来源都是代理地址，会共用同一额度。

## 网络暴露

Compose 只把 UI 发布到宿主机的 `127.0.0.1:8080`。`Secure` Cookie 只在 HTTPS 或回环地址上生效，用明文 HTTP 从其他机器访问时无法登录，API 令牌也会明文传输。远程访问可选：

| 方式 | 做法 |
| --- | --- |
| Tailscale | `CADDY_UI_BIND=<tailscale IP>:8080`，只在 tailnet 内可达 |
| 带认证的反向代理 | 在 caddy-with-auth 中加一个站点，先用 caddy-security 认证，再 `reverse_proxy` 到 UI；不要把 UI 端口直接暴露到公网 |

`CADDY_UI_ACTOR_HEADER` 只用于在变更历史中记录操作人，不参与授权。只在 UI 前面的认证代理会覆盖该请求头时设置，否则任何人都能伪造操作人。

## 脱敏规则

| 数据 | 本地 | 上传 Grafana Cloud |
| --- | --- | --- |
| 原始审计日志（含 URI；改用 `ABHKZ` 时还含请求头、Cookie、Authorization） | 是，0640，仅 UID/GID 65532 可读 | 否 |
| 事件中的客户端 IP、Host、方法、路径（解码后，最长 512 字符） | 是 | 是 |
| 查询参数 | 只保留参数名（最多 20 个） | 只有参数名 |
| 命中的规则编号、消息、变量名（如 `ARGS:q`） | 是 | 是 |
| 匹配片段和值 | 默认 `[redacted]` | 默认 `[redacted]` |
| 本地匹配内容（事件详情中按需读取） | 只在请求时从原始日志读取，不落盘 | 否 |
| 变更历史中的操作人、原因、错误、diff | 是 | 否 |
| 草稿、快照、误报判定 | 是 | 否 |

现在使用本地和云端独立的 strict/standard/full 策略及 hide/keep 名单，详见 [可配置脱敏](redaction.md)。表中的“默认”指 strict。standard 隐藏识别出的凭据；显式 full 会保留已采集的凭据，除非 hide 命中。Show matched values 和旧日志页面都服从当前本地策略。

原始文件不被这些配置改写；路径、参数名和自由文本仍需要按应用语义评估。改变级别不会删除以前排队或已经上传的数据。

## 文件与容器

- Caddy 和 UI 都以 UID/GID 65532 运行，UI 容器根文件系统只读、丢弃全部 capability、`no-new-privileges`。
- overlay 和新审计文件为 0640，目录 0750，不会改成所有人可读。
- UI 只挂载审计日志目录（读写，用于轮转），不挂载含证书的 `/data`。
- `runtime-init` 只调整各卷根目录和 UI 自有目录的属主，不递归修改证书和应用日志。

## 自动化的边界

- 误报候选、疑似攻击者都只是建议，不会自动生成排除或 IP 规则；人工判定也不会。
- 页面上的策略和排除必须先预览，应用的就是预览过的那份配置（SHA256 校验，30 分钟有效）。
- API 直接应用，面向自动化，同样有校验、快照、变更历史和失败补偿。
- 源站探测地址只来自 `CADDY_UI_PROBE_URLS`，不由请求决定；只发 GET，不跟随重定向，校验 TLS 证书。
- Loki 地址、令牌和选择器都是运维配置，用户无法指定任意查询地址。

## 可调节脱敏

请以 [可配置脱敏](redaction.md) 为准：strict 隐藏值，standard 隐藏识别出的凭据，显式 full 可以保留凭据，仅受 hide 名单约束。本地原始查看也遵守当前本地级别，不会绕过 strict。原始文件本身不被改写；Alloy 只读取独立云端队列。
