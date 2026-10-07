# 使用 coraza-ipset 镜像部署

`liukan/caddy-with-auth:coraza-plugins-ipset` 是带 [coraza-ipset 插件](backend-image.md#ip-匹配插件coraza-ipset) 的 caddy-with-auth 镜像。它与 `latest` 的唯一区别是 IP 名单的匹配方式：`@ipMatchFromFile` 改为二分查找，IP 群组规则的耗时不再随名单变大而增加。Caddyfile、overlay、UI 和全部规则都不用改。

本文按顺序给出：确认镜像 → 全新部署或切换已有部署 → 配置国家白名单 → 验证 → 回退。命令都在 caddy-waf-ui 仓库根目录执行。

## 镜像内容

2026-10-07 发布的版本：

| 组件 | 版本 |
| --- | --- |
| Caddy | 2.11.7 |
| coraza-caddy | 2.6.1 |
| Coraza | 3.8.1 |
| CRS（coraza-coreruleset） | 4.25.0，与 UI 内置的规则字典一致 |
| coraza-ipset | caddy-with-auth 提交 4acf03e |

支持 linux/amd64 和 linux/arm64，以 UID/GID 65532 运行。同一个 tag 可能被重新发布，生产环境建议固定 digest（第 1 步）。

## 第 1 步：拉取并确认镜像

```sh
docker pull liukan/caddy-with-auth:coraza-plugins-ipset
CADDY_IMAGE=liukan/caddy-with-auth:coraza-plugins-ipset make crs-version
```

输出中应有这两行：

```text
dep	github.com/corazawaf/coraza-coreruleset/v4	v4.25.0	…
dep	github.com/liu-kan/caddy-with-auth/plugins/coraza-ipset	…
```

- 没有 `coraza-ipset` 行：拉到的不是插件镜像。
- coraza-coreruleset 不是 4.25.0：先按 [后端镜像](backend-image.md#升级-coraza-或-crs-时) 更新规则字典。

取得 digest：

```sh
docker image inspect --format '{{index .RepoDigests 0}}' liukan/caddy-with-auth:coraza-plugins-ipset
```

输出形如 `liukan/caddy-with-auth@sha256:…`，下文 `CADDY_IMAGE` 可以直接填这个值。

## 第 2 步（全新部署）：准备并启动

已有 caddy-waf-ui 部署的，跳到 [第 2 步（已有部署）](#第-2-步已有部署切换镜像)。

1. 获取代码：

   ```sh
   git clone https://github.com/liu-kan/caddy-waf-ui.git
   cd caddy-waf-ui
   ```

2. 创建 `.env`，并生成登录令牌：

   ```sh
   cp .env.example .env
   chmod 600 .env
   openssl rand -hex 32
   ```

3. 编辑 `.env`：

   | 变量 | 取值 |
   | --- | --- |
   | `CADDY_UI_TOKEN` | 上一条命令的输出 |
   | `CADDY_IMAGE` | `liukan/caddy-with-auth:coraza-plugins-ipset`，或第 1 步取得的 digest |
   | `CADDYFILE_PATH` | 试用时保留 `./Caddyfile.example`；生产环境换成你的 Caddyfile，见第 4 项 |
   | `CADDY_UI_SITES` | 受管站点，逗号分隔，例如 `chat.example.com` |
   | `CADDY_UI_PROBE_URLS` | 发布后的源站验证地址。HTTPS 站点写 `{"chat.example.com":"https://caddy/<无副作用的路径>"}`，详见 [站点与 WAF 模式](sites.md) |
   | `CADDY_UI_IPGROUP_MAX_PREFIXES` | 准备导入 US 这类大名单（26 万个前缀）时调高，例如 `300000`；CN、JP 用默认值即可 |
   | `CADDY_UI_IPGROUP_PROXY` | UI 容器不能直接访问 `raw.githubusercontent.com` 时填写，例如 `http://10.0.0.2:7890` |

4. 生产环境的 Caddyfile。每个受管站点在 `route` 里加两个 import，顺序为 IP 规则 → WAF → 原有路由，写法见 [接入现有部署](deployment.md#改-caddyfile每个受管站点加两个-import)。

   站点在 Cloudflare 后面时，必须配置受信代理。否则 Caddy 看到的客户端地址是 Cloudflare 的，国家白名单会封掉全部访客。在全局选项中加入：

   ```caddyfile
   {
   	admin unix//run/caddy-admin/admin.sock
   	order coraza_waf first
   	servers {
   		trusted_proxies combine {
   			import /etc/caddy/cloudflare-ranges.caddy
   			cloudflare {
   				interval 12h
   				timeout 15s
   			}
   		}
   		client_ip_headers CF-Connecting-IP
   		trusted_proxies_strict
   	}
   }
   ```

   `cloudflare-ranges.caddy` 用 caddy-with-auth 的 [gen-cloudflare-ranges.sh](https://github.com/liu-kan/caddy-with-auth/tree/main/examples/cloudflare-real-ip-fail2ban) 生成，再挂进 Caddy 容器（见第 5 项）。UI 不需要这个文件：Caddyfile 中的 import 由 Caddy 在它自己的容器里解析。

5. 需要额外挂载文件，或 80、443、8080 端口已被占用时，在仓库根目录创建 `docker-compose.override.yml`，`docker compose` 会自动合并它。按需保留下面的条目：

   ```yaml
   services:
     caddy:
       volumes:
         - ./cloudflare-ranges.caddy:/etc/caddy/cloudflare-ranges.caddy:ro
       ports: !override
         - "8081:80"
     caddy-waf-ui:
       ports: !override
         - "127.0.0.1:18088:8080"
   ```

   `!override` 需要 Docker Compose 2.24 或更高版本。

6. 检查配置并启动（UI 镜像在本地构建）：

   ```sh
   docker compose config --quiet
   docker compose up -d --build
   docker compose ps
   ```

   `runtime-init`、`ui-config-init` 执行完退出是正常的，`caddy`、`caddy-waf-ui` 应为 running。

7. 确认运行中的 Caddy 带插件：

   ```sh
   docker compose exec -T caddy /usr/local/bin/caddy build-info | grep coraza-ipset
   ```

8. 登录 UI：浏览器打开 `http://127.0.0.1:8080`（第 5 项改过端口的，用改后的端口），用 `CADDY_UI_TOKEN` 登录。服务器上部署时，先在本机执行 `ssh -L 8080:127.0.0.1:8080 <服务器>`，再打开同一地址。

## 第 2 步（已有部署）：切换镜像

适用于已按 [接入现有部署](deployment.md) 运行 caddy-waf-ui 的环境。切换只重建 Caddy 容器；overlay、名单和 UI 数据都在卷里，不受影响。

1. 记下当前运行的镜像 digest，回退时填回 `CADDY_IMAGE`。即使原来的 tag（例如 `latest`）之后被重新发布，用 digest 也能回到同一个镜像：

   ```sh
   docker image inspect --format '{{index .RepoDigests 0}}' "$(docker inspect --format '{{.Image}}' "$(docker compose ps -q caddy)")"
   ```

2. 把 `.env` 中的 `CADDY_IMAGE` 改为 `liukan/caddy-with-auth:coraza-plugins-ipset`，或第 1 步取得的 digest。

3. 拉取镜像，只重建 Caddy。Caddy 重启期间站点会中断几秒，请安排在低峰期：

   ```sh
   docker compose pull caddy
   docker compose up -d --no-deps caddy
   ```

4. 确认插件生效：

   ```sh
   docker compose exec -T caddy /usr/local/bin/caddy build-info | grep coraza-ipset
   ```

5. 确认发布正常：在 **Domains & WAF** 对任一站点重新应用当前模式，然后在 **Rollback & History** 的最新记录里确认 validate、load、readback、request 都成功。没有配置 `CADDY_UI_PROBE_URLS` 时，request 阶段显示 skipped。

要使用 IP 群组，UI 必须是带 IP 群组功能的版本（**IP Groups** 页存在）。旧版本先升级：

```sh
git pull
docker compose up -d --build caddy-waf-ui
```

并入其他 Compose 栈的，还要按 [升级说明](upgrade-notes.md#ip-群组2026-10-06) 给 UI 加上 `/ipgroups` 挂载。

## 第 3 步：配置国家白名单

示例：只允许中国大陆和日本访问，其余地址直接封禁。

1. 导入名单。在 **IP Groups** 页用 **Add / Update** 添加两个群组，来源都选 URL，刷新间隔保留 24h：

   | 名称 | 地址 |
   | --- | --- |
   | `cn` | `https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/sing/geo/geoip/cn.srs` |
   | `jp` | `https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/sing/geo/geoip/jp.srs` |

   保存后立即下载，页面显示前缀数（2026-10 时 cn 约 9,600，jp 约 17,400）。群组上显示错误时：

   - 下载失败：设置 `CADDY_UI_IPGROUP_PROXY`，再执行 `docker compose up -d caddy-waf-ui`；
   - 前缀数超过上限：调高 `CADDY_UI_IPGROUP_MAX_PREFIXES`，同样重建 UI。

2. 放行不在国家名单里的内部来源，例如健康检查、监控和办公网出口。

   1. 在宿主机 `./ipgroups/internal.txt` 中每行写一个 IP 或 CIDR。
   2. 在 **IP Groups** 页添加群组：名称 `internal`，来源 File，文件名 `internal.txt`。

   用 Compose 示例在本机试用时，请求来自 Docker 网关的私网地址，也要写进这个文件，例如 `172.16.0.0/12` 和 `192.168.0.0/16`。

3. 先试运行：

   1. 在 **Policy** 页的 **IP group rules** 中编辑第一行：
      - Groups：同时选中 `cn`、`jp`、`internal`（按住 Ctrl，macOS 为 ⌘）；
      - Clients：`outside all`；
      - Action：`trial`。
   2. 填写原因，点 **Preview diff and impact**，再点 **Apply reviewed policy**。
   3. 运行一段时间后，在 **Events** 查看 "would be blocked" 事件，确认两点：
      - 事件中的客户端 IP 是真实访客地址，不是 Cloudflare 或 Docker 网关的地址；
      - 没有本不该拦的来源。

4. 改为封禁：把这一行的 Action 改为 `ban`，再预览、应用。

   ban 只在站点为 On 模式时拦截。新站点默认是 DetectionOnly，这时 ban 和 trial 一样，只把本会封禁的请求记成 "would block" 事件。确认无误后，在 **Domains & WAF** 把站点切到 On。

   生效后，被 ban 的请求不产生事件，只在访问日志中记为 403。

用 API 设置同一条规则：

```sh
curl -s -X PUT -H "Authorization: Bearer $CADDY_UI_TOKEN" -H "Content-Type: application/json" \
  -d '{"policy":{"blocking_pl":1,"inbound_threshold":5,"outbound_threshold":4,"ip_groups":[{"groups":["cn","jp","internal"],"negate":true,"action":"ban"}]},"reason":"allow CN and JP"}' \
  http://127.0.0.1:8080/api/sites/chat.example.com/policy
```

API 直接应用，不经过草稿和影响估算；`policy` 中的其他字段按需保留现值，见 [WAF 策略](policy.md#rest-api)。

## 第 4 步：验证

| 检查 | 方法 | 期望 |
| --- | --- | --- |
| 镜像带插件 | `docker compose exec -T caddy /usr/local/bin/caddy build-info \| grep coraza-ipset` | 有输出 |
| overlay 使用合并名单 | `docker compose exec -T caddy-waf-ui grep ipMatchFromFile /ui-managed/waf-chat_example_com.conf` | 引用 `ipgroups/_union.<哈希>.txt` |
| 群组归属 | **IP Groups** 页的 **Which groups hold**，输入一个访客地址 | 显示 `cn` 或 `jp` |
| 发布 | **Rollback & History** 的最新记录 | validate、load、readback、request 成功 |
| 站点模式 | **Domains & WAF** | On（DetectionOnly 下 ban 只记录不拦截） |
| 实际访问 | 分别从国内、日本的网络和其他国家的网络（例如海外服务器）访问站点 | 前者正常，后者 403 |

每个被封的请求在 Caddy 错误日志中留一行 `WAF rule violation detected`，这一行由镜像中的 coraza-caddy 写入，属于正常现象。

## 回退

1. 把 `.env` 中的 `CADDY_IMAGE` 改回切换前记下的 digest。
2. 只重建 Caddy：

   ```sh
   docker compose up -d --no-deps caddy
   ```

overlay 不用改，规则照常生效，只是变回逐条比较。为大名单调高过 `CADDY_UI_IPGROUP_MAX_PREFIXES` 的，回退后这些名单的开销会明显增加，见 [性能与名单规模](ip-groups.md#性能与名单规模)。

## 常见问题

| 现象 | 原因与处理 |
| --- | --- |
| 所有访客都被封 | 受信代理没配好，客户端地址是 Cloudflare 的。查看 Caddy 访问日志中的 `request.client_ip`；切到 ban 之前先用 trial 确认 |
| 健康检查或内部工具被封 | 把它们的来源地址加入 `internal` 群组 |
| 本机试用时自己被封 | Compose 示例里本机请求来自 Docker 网关的私网地址，把它加入 `internal` |
| 切到 ban 后仍能访问 | 站点还是 DetectionOnly，ban 只记录；在 **Domains & WAF** 切到 On |
| 群组更新显示待批准 | 新名单的前缀数不到原来的一半，被暂存。确认无误后点 **Approve**，见 [IP 群组](ip-groups.md#名单来源) |
| `build-info` 中没有 `coraza-ipset` | 运行的不是插件镜像。用 `docker compose config --images` 检查配置中的镜像，生产环境固定 digest |
