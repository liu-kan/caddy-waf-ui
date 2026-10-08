# 已部署 observability 的接入配置

先阅读 [完整中文迁移手册](../../documentation/zh/observability-migration.md)。本目录适用于已有 Docker Caddy/Coraza、LibreChat 和宿主机原生 `alloy.service` 的部署。

| 文件 | 使用方式 |
| --- | --- |
| `compose.waf-ui.yaml` | 复制到 `/opt/librechat-a/observability/waf-ui/`，作为现有 Compose 项目的最后一个 `-f` 文件；保留原来的 override、项目名、Caddy 镜像和应用网络 |
| `ui.env.example` | 首次复制为同目录 `ui.env`，0600，填写真实站点、UI 管理令牌和可选的 logs:read 令牌；不放 Alloy 写入令牌 |
| `waf-before.conf.example` | 请求体基线、磁盘临时目录、运行时例外；合并到原 `observability/caddy/waf-before.conf`，不覆盖业务例外 |
| `waf-after.conf.example` | 审计状态过滤和静态例外；合并到原 after 文件，主要审计设置和模式交给 UI |
| `waf-ui.alloy` | 替换旧 raw-audit source/process 后，追加到 `/etc/alloy/config.alloy`；复用 `loki.write.librechat_cloud`，保留指标、drop-in 和 `/var/lib/alloy/data` |
| `VERIFICATION.md` | 配套配置的本地隔离验证记录及未验证范围 |

这个 Compose 片段不能独立运行，不包含新 Alloy 服务，也不启动第二个 80/443 入口。服务器 UI 默认只在 `127.0.0.1:18088` 发布，用 SSH 隧道访问。

初次使用 `CADDY_UI_AUDIT_ROTATE_MB=0` 保留旧 logrotate，验收后再按手册交给 UI。独立云端队列是 `data/cloud/events/`；不要把 Alloy 改指向丰富的本地 `data/events/` 或 raw 文件。
