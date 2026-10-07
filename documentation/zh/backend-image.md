# 后端镜像

后端使用 [liukan/caddy-with-auth](https://github.com/liu-kan/caddy-with-auth)，原样运行，不需要重新构建。UI 需要的所有配置都通过挂载文件提供；只有想做"不可变镜像"部署、升级了镜像里的 Coraza/CRS，或需要 [IP 匹配插件](#ip-匹配插件coraza-ipset) 时，才需要按本文处理。

## 对镜像的要求

| 要求 | 用途 | 检查方法 |
| --- | --- | --- |
| Caddy 模块 `http.handlers.waf`（`github.com/corazawaf/coraza-caddy/v2`） | 执行 UI 生成的 `coraza_waf` overlay | `caddy list-modules \| grep http.handlers.waf` |
| 标准 Admin API（`/load`、`/config/`） | 发布配置、回读 revision | 默认具备 |
| 支持 `log_append` 指令 | 示例 Caddyfile 用它把请求路径写进访问日志；不上传访问日志时可去掉该行 | `caddy validate` 通过 |
| 以 UID/GID 65532 运行 | 与 UI 共享 overlay、审计目录和 Admin socket 的权限 | DHI 运行时默认如此 |
| 可选：coraza-ipset 插件 | IP 群组规则用二分查找匹配，名单再大也不变慢 | `caddy build-info \| grep coraza-ipset` |

已验证的版本组合（`liukan/caddy-with-auth:latest`，镜像 ID `3a4bf970ed0c`）：Caddy 2.11.6、coraza-caddy/v2 2.6.1、Coraza 3.8.0、coraza-coreruleset 4.25.0（即 CRS 4.25.0）。查看当前镜像：

```sh
make crs-version                      # 默认读取 CADDY_IMAGE，未设置时为 liukan/caddy-with-auth:latest
CADDY_IMAGE=caddy-with-auth:pinned make crs-version
```

输出 Caddy、coraza-caddy、Coraza 和 coraza-coreruleset 的版本；镜像带 coraza-ipset 插件时也会列出它。

## 全部改动都走挂载

| 内容 | 挂载到 Caddy | 说明 |
| --- | --- | --- |
| Caddyfile | `/etc/caddy/Caddyfile:ro` | `admin {$CADDY_ADMIN_LISTEN:unix//run/caddy-admin/admin.sock}`、各站点的两个 import、可选的 access/error 日志输出 |
| 受管 overlay | `/etc/caddy/ui-managed:ro`（命名卷） | UI 生成，Caddy 只读 |
| 自定义规则 | `/etc/caddy/waf-custom:ro` | `before.conf`（CRS 之前）、`after.conf`（CRS 之后），运维自有 |
| 审计与访问日志 | `/data/logs`（命名卷） | Coraza 审计日志、可选的 `access.json`/`error.json` |
| Admin socket | `/run/caddy-admin`（命名卷，0700） | 只给 Caddy 和 UI |
| 环境变量 | `CADDY_ADMIN_LISTEN=unix//run/caddy-admin/admin.sock` | Caddyfile 中引用 |

DHI 运行时没有 shell，Compose 关闭了镜像里基于 shell 的健康检查。校验配置用镜像自带的 caddy：

```sh
docker compose run --rm --no-deps --entrypoint /usr/local/bin/caddy caddy \
  validate --config /etc/caddy/Caddyfile --adapter caddyfile
```

## 需要固化进镜像时

想把 Caddyfile 和自定义规则打进镜像（例如部署平台不方便挂载文件），在你自己的仓库或部署目录里加一个派生镜像，不改 caddy-with-auth 本身：

```dockerfile
FROM liukan/caddy-with-auth:latest
COPY --chown=65532:65532 --chmod=0640 Caddyfile /etc/caddy/Caddyfile
COPY --chown=65532:65532 --chmod=0640 waf-custom/ /etc/caddy/waf-custom/
```

注意三点：

1. **UI 必须拿到同一份 Caddyfile。** UI 重载时把自己读到的 Caddyfile 全文发给 `/load`。镜像里的文件和 UI 挂载的文件不一致时，第一次通过 UI 发布就会把线上配置换成 UI 那一份。两边用同一个文件来源，并在构建派生镜像时同步更新。
2. **overlay 目录不能打进镜像。** `/etc/caddy/ui-managed` 必须是 UI 可写、Caddy 可读的共享卷。
3. **改了 `waf-custom` 后要在 UI 里重新应用一次该站点的模式**，生成新的 revision，Coraza 才会重新加载这些 include。

## IP 匹配插件（coraza-ipset）

caddy-with-auth 仓库中的 `plugins/coraza-ipset` 是一个 Coraza 插件。编进镜像后，它替换 Coraza 自带的 `@ipMatchFromFile`（及别名 `@ipMatchF`）：名单存成合并后的有序区间，用二分查找匹配。

- IP 群组规则不用改，匹配结果与 Coraza 原实现逐条一致。
- 每个请求的耗时与名单大小无关。
- 同一份名单在整个进程里只解析、存储一次。

性能对比见 [IP 群组](ip-groups.md#性能与名单规模)。

| 项目 | 说明 |
| --- | --- |
| 已发布镜像 | `liukan/caddy-with-auth:coraza-plugins-ipset`，部署与切换步骤见 [使用 coraza-ipset 镜像部署](ipset-image-deployment.md) |
| 构建 | caddy-with-auth 的 Dockerfile 用 `xcaddy build --with github.com/liu-kan/caddy-with-auth/plugins/coraza-ipset=/build/plugins/coraza-ipset` 编入。编译前先用本次构建选用的 Coraza 版本运行插件测试：与 Coraza 原算法对照边界用例、随机名单和模糊输入 |
| 确认 | `make crs-version` 的输出包含 `coraza-ipset`。CI 还会用临时容器检查 build info 和实际请求（`tests/test_coraza_ipset.py`） |
| 回退 | 不带插件的镜像照常加载同样的 overlay，只是变回逐条比较。UI 不需要任何改动 |
| 升级 Coraza | Coraza 修改了实现 `ipMatch` 的源码时，插件测试会让镜像构建失败，防止插件与新版行为悄悄出现差异。对照改动更新插件，再更新 `ipset_test.go` 中记录的源码哈希 |

## 升级 Coraza 或 CRS 时

caddy-with-auth 的 Dockerfile 默认用 `CORAZA_CADDY_VERSION=latest` 和 `CORAZA_VERSION=latest`。CRS 版本由 coraza-caddy 的依赖决定：coraza-caddy 2.6.1 依赖 coraza-coreruleset 4.25.0。重建镜像可能带来新的 CRS 版本。此时规则编号的含义、PL 和分值可能变化，UI 会在事件页提示"事件报告的 CRS 版本与字典不一致"。

需要可重复的版本时，在 caddy-with-auth 仓库里用构建参数锁定，不必改它的 Dockerfile（基础镜像来自 `dhi.io`，需要先登录）：

```sh
docker login dhi.io
docker build \
  --build-arg CADDY_VERSION=2.11.6 \
  --build-arg CORAZA_CADDY_VERSION=v2.6.1 \
  --build-arg CORAZA_VERSION=v3.8.0 \
  --target final -t caddy-with-auth:pinned .
```

CRS 版本跟随 `CORAZA_CADDY_VERSION`。想脱离 coraza-caddy 单独锁定 CRS，需要在其 Dockerfile 的 `xcaddy build` 中增加 `--with github.com/corazawaf/coraza-coreruleset/v4@v4.25.0`：这是对镜像构建的修改，先评估再做。

镜像的 CRS 版本变化后，同步更新 UI 的规则字典：

```sh
make crs-version                          # 读出新镜像里的 coraza-coreruleset 版本
make crs-dict CRS_VERSION=4.26.0          # 重新生成 internal/crs/data/crs-dictionary.json.gz
# 修改 internal/crs/dict_test.go 中期望的版本号，然后：
go test ./internal/crs/ && docker compose build caddy-waf-ui
```

`make crs-dict` 从 Go 模块缓存读取镜像实际使用的 coraza-coreruleset 规则文件（不会加入本项目的依赖），并从上游 coreruleset 同版本仓库补充规则注释和源码链接。对同一版本重复执行，生成结果完全一致。

不想重建 UI 时，也可以只刷新字典：把同版本的规则目录只读挂载进 UI，并设置 `CADDY_UI_CRS_RULES_DIR`。这样只影响 UI 里的规则解释，不改变 WAF 行为。中文说明来自 UI 内置的 `notes-zh.json`，新版本里新增的规则会显示类别说明。

## 升级后的检查

1. `caddy list-modules` 中有 `http.handlers.waf`。
2. 用新镜像跑一遍示例栈（见 [快速开始](quick-start.md)），请求 `/.env`，确认事件中的 CRS 版本与 **Rules** 页标题一致。
3. 改一次模式，在变更记录里确认 load、readback、request 三个阶段成功。
4. 可选：用与镜像相同模块版本编译的原生 Caddy 运行仓库自带的真实请求测试：

```sh
CADDY_TEST_BINARY=/绝对路径/caddy go test ./tests/integration -run TestRealCaddyWAFUpdatesAndStreaming -v
```
