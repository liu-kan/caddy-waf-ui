# 快速开始

仓库自带一个可直接运行的 Compose 示例：`liukan/caddy-with-auth` 作为入口和 WAF，`containous/whoami` 作为示例上游，UI 只在本机回环地址监听。示例站点是 `localhost`。

## 启动

```sh
cp .env.example .env
chmod 600 .env
openssl rand -hex 32   # 把输出填入 .env 的 CADDY_UI_TOKEN
docker compose config --quiet
docker compose up -d --build
```

浏览器打开 `http://127.0.0.1:8080`，用 `CADDY_UI_TOKEN` 登录。

启动顺序：

| 服务 | 作用 |
| --- | --- |
| `runtime-init` | 一次性，以 root 运行，只带 CHOWN/FOWNER/DAC_OVERRIDE。把各卷根目录交给 UID/GID 65532，Admin socket 目录设为 0700 |
| `ui-config-init` | 一次性。为 `CADDY_UI_SITES` 里的站点生成 DetectionOnly 的 WAF overlay、空排除列表和空 IP 规则；已有内容不覆盖。检查 Caddyfile 中的 import 都有对应文件 |
| `caddy` | 后端镜像原样运行（无 shell，不做 shell 健康检查）。Admin API 只监听共享卷里的 Unix socket |
| `caddy-waf-ui` | 管理 UI；读审计日志、维护本地事件库、通过 socket 重载 Caddy |
| `alloy` | 仅 `cloud` profile 启用，见 [Grafana Cloud 与 Alloy](grafana-cloud.md) |

## 试一下

```sh
curl -s -o /dev/null -w "%{http_code}\n" http://localhost/.env
```

示例站点默认是 DetectionOnly，所以返回 200，但会产生一条 "WOULD BLOCK" 事件。在 UI 的 **Events** 页能看到它；打开后可以看到 930130（受限文件访问）加 5 分、949110（入站异常分超过阈值）做出拦截判定。

到 **Domains & WAF** 把模式改成 On，再请求一次就会得到 403。

## 示例里值得保留的约定

- 站点块里两个 import 放在 `route` 内，顺序为 IP 规则 → WAF → 反向代理。
- `.env` 里的 `CADDY_UI_PROBE_URLS={"localhost":"http://caddy"}` 让 UI 每次发布后对源站做一次请求验证，见 [站点与 WAF 模式](sites.md)。
- 示例 Caddyfile 额外写了 `access.json` 和 `error.json`，只用于云端统计请求总量和运行错误；不需要上传时可以去掉。

接入已有的 caddy-with-auth 部署见 [接入现有部署](deployment.md)。
