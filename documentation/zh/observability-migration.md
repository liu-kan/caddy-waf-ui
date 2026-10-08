# 已部署 observability 的 LibreChat：接入本地 WAF UI 完整手册

适用对象：已经按“查找 Coraza 与 Caddy 集成方案”的手册，把 `coraza-grafana-cloud-v2` 文件放到 `/opt/librechat-a/observability`，并运行 **现有 Docker Caddy/Coraza + 宿主机原生 Alloy/systemd + Grafana Cloud Loki** 的用户。

本手册以 2026-10-07 的本仓库实现为依据。目标是继续使用原有 `caddy-with-auth` 入口和 LibreChat 网络，在本机查看 WAF 事件、解释 `930130,949110` 等编号、回溯误报、调整策略，并继续把脱敏事件交给原有 Alloy 存到 Grafana Cloud。本文不是服务器已部署成功的证明，最后的验收需要在你的服务器上完成。

## 1. 迁移后的结构与旧文件去留

```text
访客 → Cloudflare（如有）→ 原有 Caddy/Coraza → 原有 LibreChat/RAG/模型服务
                                  │
                                  └→ logs/caddy/coraza-audit.json（本地原始审计）
                                             │
                                        caddy-waf-ui
                                             ├→ 本地事件、规则解释、分析、策略和快照
                                             └→ data/cloud/events/（独立云端脱敏副本）
                                                         │
                                               原有宿主机 alloy.service
                                                         │
                                                Grafana Cloud Loki
                                                         ↑
                                         本地 UI 用 logs:read 令牌查询历史
```

只增加一个长期运行的 UI 容器。本地不用安装 Loki、Grafana、数据库、第二套 Alloy 或第二个占用 80/443 的 Caddy。

| 已有对象 | 处理 |
| --- | --- |
| LibreChat 的 Compose、`.env`、API/RAG/数据库/搜索配置 | 保留；只合并本文的 UI 片段 |
| Caddy 镜像、80/443、`/data`、`/config`、DNS 凭据、认证模块 | 保留；ipset 镜像是后续可选项 |
| 真实 IP、访问/登录/错误日志、Fail2ban | 保留；不改其路径和过滤器 |
| 原来手写的 `coraza_waf` 块 | 将自定义设置迁出后，用受管 `import` 替换；同一请求只能经过一个 WAF |
| `observability/caddy/waf-before.conf`、`waf-after.conf` | 继续使用，按第 5 节重新分配内容 |
| `/etc/alloy/config.alloy` 的指标、remote configuration 等组件 | 保留 |
| Alloy 安装脚本生成的 `env.conf`、启动参数、`/var/lib/alloy/data` | 保留，不清空状态目录 |
| 旧 `loki.source.file "librechat_coraza"` 和对应 raw-audit process | 验收本地 UI 后，替换成独立云端事件队列采集 |
| 旧 `loki.write "librechat_cloud"`、Logs 写入令牌文件 | 复用；有其他节点健康日志使用它时更要保留 |
| `/etc/logrotate.d/librechat-coraza` | 初次接入保留；UI 轮转先设 0，验收后交接 |
| `observability/node/` 的可选健康日志 | 已启用就保留；没有生产者就不要创建空文件假装启用 |

旧云端流是 `job="coraza"`、`schema="coraza-v1"`。新 UI 需要 `kind="event"` 的规范化格式，使用 `job="caddy-waf-ui"`。**把 UI 的 selector 改成旧 job 并不能转换旧格式。** 旧云端日志继续在 Grafana Explore 查看；新的事件可直接在本地 UI 查询云端。

## 2. 本文的路径和命令约定

本文服务器命令在 Ubuntu 的 **Bash 管理员维护会话**中执行（需要时先 `sudo -i`），以便读取 0600 的环境文件并管理 Docker/宿主机权限；Caddy、UI 和 Alloy 的运行进程仍使用各自的非 root 身份。主目录用 `/opt/librechat-a`，Caddy Compose 服务名用 `caddy`，站点用 `chat.example.com`。不同现场应统一替换，不能只替换域名的一部分。

配套文件位于本仓库 [examples/observability-migration](../../examples/observability-migration/)：

| 文件 | 用途 |
| --- | --- |
| `compose.waf-ui.yaml` | 合并到现有 LibreChat Compose 的片段，不是独立部署 |
| `ui.env.example` | UI 和初始化容器使用的环境配置 |
| `waf-before.conf.example`、`waf-after.conf.example` | 内容分配示例，不覆盖已有的有效例外 |
| `waf-ui.alloy` | 原生 Alloy 组件片段，只采集独立云端脱敏事件，复用旧 writer |

阅读顺序：第 3–8 节完成本地接入；第 9–10 节切换云端存储/查询；第 11 节交接轮转；第 12–15 节用于调优、排障和回滚。第 7 节重建入口前安排维护窗口。

迁移完成后的宿主机目录：

```text
/opt/caddy-waf-ui/                         本次修改后的源码，用于构建 UI
/opt/librechat-a/
  <原有 Compose 文件和 .env>
  <原有 Caddyfile>
  logs/caddy/
    access.json 或 access.jsonl             原有访问日志，继续留本地
    coraza-audit.json                       原有审计文件，路径保持不变
  observability/
    caddy/waf-before.conf
    caddy/waf-after.conf
    alloy/、ops/、node/                     原有文件继续保留作为参考/回退材料
    waf-ui/
      compose.waf-ui.yaml
      ui.env                               含 UI 管理令牌和可选 Loki 只读令牌，0600
      waf-ui.alloy                         要合并到 /etc/alloy/config.alloy 的片段
      managed/                             Caddy 只读、UI 读写的 overlay
      backups/                             UI 配置快照
      data/                                本地事件、云端副本、草稿、游标、汇总
      admin/                               只供 Caddy/UI 使用的 Admin socket
      ipgroups/                            可选 IP 群组的运维来源文件
      tmp/                                 Coraza 请求体临时文件，使用磁盘
```

需要对齐的三种视角：

| 内容 | 宿主机 | Caddy 容器 | UI 容器 |
| --- | --- | --- | --- |
| 审计目录 | `/opt/librechat-a/logs/caddy` | `/var/log/caddy` | `/var/log/caddy` |
| 自定义规则目录 | `/opt/librechat-a/observability/caddy` | `/etc/caddy/waf-custom` | `/etc/caddy/waf-custom` |
| overlay | `observability/waf-ui/managed` | `/etc/caddy/ui-managed` | `/ui-managed` |
| UI 数据 | `observability/waf-ui/data` | 不挂载 | `/ui-data` |
| Admin 目录 | `observability/waf-ui/admin` | `/run/caddy-admin` 读写 | 同路径只读 |
| 请求体临时目录 | `observability/waf-ui/tmp` | `/var/cache/coraza` | 不挂载 |

宿主机 Alloy 读取的是表中的**宿主机路径**，不是容器的 `/ui-data` 或 `/var/log/caddy`。

## 3. 先核对现场和备份

### 3.1 固定现有 Compose 文件集合

不要进入 caddy-waf-ui 仓库执行其自带的 `docker compose up`。那是演示栈，会启动另一个入口。

```bash
cd /opt/librechat-a
ls -1 *compose*.y*ml
```

按目前实际使用的文件顺序设置数组。例如已有主文件和 override：

```bash
BASE_FILES=(-f docker-compose.yml -f docker-compose.override.yml)
base_dc() { docker compose "${BASE_FILES[@]}" "$@"; }
waf_dc() {
  docker compose "${BASE_FILES[@]}" \
    -f observability/waf-ui/compose.waf-ui.yaml "$@"
}
```

如果只有主文件，就改为 `BASE_FILES=(-f docker-compose.yml)`；如果是 `compose.yaml` 或更多 `-f` 文件，填入实际集合。**显式加 `-f` 后，原先自动加载的 override 也必须列出。** 每次重新打开 SSH 会话都先恢复这段定义。

先确认这些命令指向已经运行的项目：

```bash
base_dc ps
CADDY_CID=$(base_dc ps -q caddy)
test -n "$CADDY_CID"
docker inspect "$CADDY_CID" --format '{{index .Config.Labels "com.docker.compose.project"}}'
docker inspect "$CADDY_CID" --format 'image={{.Config.Image}} user={{.Config.User}}'
docker inspect "$CADDY_CID" --format '{{range .Mounts}}{{printf "%s\t%s\t%s\n" .Type .Source .Destination}}{{end}}'
base_dc exec -T caddy /usr/local/bin/caddy build-info
base_dc exec -T caddy /usr/local/bin/caddy list-modules
```

确认 build-info 使用 `github.com/corazawaf/coraza-caddy/v2`，并核对运行中的 CRS 版本。当前 UI 内置字典为 CRS 4.25.0；后端不同时按 [后端镜像与规则字典](backend-image.md) 接入对应字典，不把版本不符的说明当作精确解释。

保留项目名：原来用 `-p` 或 `COMPOSE_PROJECT_NAME` 的，继续使用同一个值。`ps` 看不到原有 Caddy 时先纠正项目/文件集合，再继续。

记录真正的 Caddyfile Source：单文件挂载直接取 Source；目录挂载到 `/etc/caddy` 时取目录下的 `Caddyfile`。本文默认 UI 挂载 `./Caddyfile`，如果现场为 `./observability/caddy/Caddyfile`，稍后必须设置 `WAF_UI_CADDYFILE_PATH`。

确认 `/var/log/caddy` 确实来自 `./logs/caddy`。不同时，配套 Compose 中 UI 的日志 Source、所有宿主机检查命令都换成实际路径，不创建新的空目录代替历史日志。

```bash
/usr/bin/alloy --version
systemctl show alloy.service -p User -p Group -p ExecStart -p DropInPaths
systemctl status alloy.service --no-pager -l
sudo test -f /opt/librechat-a/logs/caddy/coraza-audit.json
sudo stat -c '%u:%g %a %n' /opt/librechat-a/logs/caddy/coraza-audit.json
```

主配置和 drop-in 可以含凭据，在服务器上审阅即可，不要把完整 `docker compose config`、Docker Env、Alloy Environment 或配置原文贴到公共聊天。

### 3.2 备份

```bash
migration_backup="/opt/librechat-a/waf-ui-migration-backups/$(date -u +%Y%m%dT%H%M%SZ)"
sudo install -d -m 0700 "$migration_backup"
sudo cp -a observability "$migration_backup/observability"
sudo cp -a /etc/alloy/config.alloy "$migration_backup/alloy.config.alloy"
sudo cp -a /etc/systemd/system/alloy.service.d "$migration_backup/alloy.service.d"
```

另把实际 Caddyfile、所有 `BASE_FILES` 中的 Compose 文件、现有 `.env` 和审计 logrotate 规则复制到同一备份目录。若某个可选文件不存在就跳过；别因为复制报错而误以为已经备份成功。对审计文件保存 ACL：

```bash
sudo getfacl -p logs/caddy logs/caddy/coraza-audit.json > /tmp/waf-ui-audit-acl.before
sudo install -m 0600 /tmp/waf-ui-audit-acl.before "$migration_backup/audit-acl.before"
rm /tmp/waf-ui-audit-acl.before
docker inspect "$CADDY_CID" --format '{{.Image}}' > /tmp/waf-ui-caddy-image.before
sudo install -m 0600 /tmp/waf-ui-caddy-image.before "$migration_backup/caddy-image-id.before"
rm /tmp/waf-ui-caddy-image.before
```

证书卷继续使用原来的卷。本次文件备份不等于数据库、证书卷的完整备份，按原有维护流程保存它们；不要运行 `down -v`。

## 4. 准备源码、配套文件和 UI 目录

使用**包含本次修改的源码**。开发机的未提交修改不会出现在 `git clone` 或 `git archive HEAD` 中；远端尚未同步时，直接同步已修改的工作目录。以下在开发机执行，替换 SSH 目标：

```bash
rsync -az \
  --exclude='/.git/' --exclude='/.env*' --exclude='/.codegraph/' \
  --exclude='/.venv/' --exclude='/tools/' --exclude='/logs/' \
  --exclude='/backups/' --exclude='/ipgroups/' --exclude='/caddy-waf-ui' \
  --exclude='/cosign.key' \
  /Users/liuk/src/caddy-waf-ui/ ops@SERVER:/opt/caddy-waf-ui/
```

用有权写入目标目录的 SSH 账号，或先同步到个人目录再由管理员安装。正式配置和生产 IP 来源不要放进构建目录。

回到服务器，首次接入：

```bash
cd /opt/librechat-a
sudo install -d -m 0750 observability/waf-ui
sudo install -m 0644 /opt/caddy-waf-ui/examples/observability-migration/compose.waf-ui.yaml observability/waf-ui/compose.waf-ui.yaml
sudo install -m 0644 /opt/caddy-waf-ui/examples/observability-migration/waf-ui.alloy observability/waf-ui/waf-ui.alloy
sudo install -m 0600 /opt/caddy-waf-ui/examples/observability-migration/ui.env.example observability/waf-ui/ui.env
sudo install -d -o 65532 -g 65532 -m 0750 \
  observability/waf-ui/managed observability/waf-ui/backups \
  observability/waf-ui/data observability/waf-ui/ipgroups observability/waf-ui/tmp
sudo install -d -o 65532 -g 65532 -m 0700 observability/waf-ui/admin
```

已经存在的 `ui.env` 先备份、编辑，不再次用 example 覆盖；已有 UI 数据目录也不做重置。

配套片段保留 Caddy 的镜像、证书、环境变量和原有挂载，只增加 overlay、自定义规则、socket 和请求体临时目录。它明确让 Caddy/UI 使用 UID/GID 65532。**如果旧 Caddy 是 root 或其他 UID，先检查专用证书卷、配置卷和日志是否允许 65532 读写**；需要迁移属主时，应备份后只对确认属于 Caddy 的对象处理，不递归修改整个 `/opt/librechat-a` 或 LibreChat 数据库目录。完成权限迁移前不要切换运行身份。

日志目录必须允许 Caddy/UI 创建文件、改名和读取：

```bash
sudo chown 65532:65532 logs/caddy
sudo chmod 0750 logs/caddy
sudo chown 65532:65532 logs/caddy/coraza-audit.json
sudo chmod 0640 logs/caddy/coraza-audit.json
```

这只处理目录本身和审计文件，不递归改访问/登录日志。旧 Caddy 仍在运行时，先确认它具有所需访问权限，再改属主；非 root 的其他旧 UID 必须在维护窗口切换。已有给 Alloy 的 raw-audit ACL 暂时保留，第 9 节再撤回。

在现有项目 `.env` 中添加 Compose 展开变量，保留其它行：

```dotenv
WAF_UI_SOURCE_DIR=/opt/caddy-waf-ui
WAF_UI_CADDYFILE_PATH=./Caddyfile
```

第二项必须指向第 3 节核对出的真实文件。不要给 Caddy 换一份空的示例 Caddyfile。所有片段的相对路径以**第一个 Compose 文件所在的主项目目录**为基准，见 [Docker 合并规则](https://docs.docker.com/compose/how-tos/multiple-compose-files/merge/)。

## 5. 迁移原有 waf-before.conf / waf-after.conf

不要把 SecLang 指令直接 `import` 到 Caddyfile。它们由受管 WAF 内部的 `Include` 读取。

### 5.1 before：请求体基线和运行时例外

编辑 `observability/caddy/waf-before.conf`，把旧 after 中的请求体设置移过来，保留原有已经审阅的 `ctl` 例外：

```apache
SecRequestBodyAccess On
SecRequestBodyLimit 134217728
SecRequestBodyNoFilesLimit 2097152
SecRequestBodyInMemoryLimit 262144
SecRequestBodyLimitAction Reject
SecTmpDir /var/cache/coraza

# Existing reviewed runtime ctl exclusions belong below.
```

128 MiB 是总请求体上限，2 MiB 是非文件部分上限，256 KiB 是内存阈值，彼此不是同一个限制。上传仍受 LibreChat、上游和可用临时空间限制。这里将原来的 `/tmp` 改成单独的磁盘目录；配套 Compose 同时给 Caddy 设置 `TMPDIR=/var/cache/coraza`，供 Coraza 启动时的文件系统检查使用。这避免参考 Compose 中 64 MiB tmpfs 无法承担大请求且消耗内存；为并发请求预留磁盘并监控空间，不能靠提高一个限值保证大文件上传成功。

顺序为基础配置 → CRS setup → before → UI Policy → CRS → after → UI 最终设置。因此：

- `SecRequestBodyLimit` 放 before，UI 的 **Request body limit** 才能覆盖它；
- UI 字段留空/0 时使用 before 的 128 MiB 基线。页面固定的“13107200”提示在自定义基线下不能代表实际值；
- 不在 after 再放同一请求体限值，否则它会反过来覆盖 UI；
- `SecRuleUpdateTargetById` 等需要规则已加载的静态排除仍放 after；路径限定的 `ctl` 放 before，或迁移为 UI 的规则排除。

旧临时探针 `1000001/1000002` 先移除或注释。需要沿用 `1000001` 做手动验收时，用第 8 节含 `ctl:auditEngine=On` 的版本，不重复定义 ID。别保留长期公开的合成拒绝探针。

### 5.2 after：审计状态过滤和静态例外

编辑 `observability/caddy/waf-after.conf`：

```apache
SecAuditLogType Serial
SecAuditLogRelevantStatus "^(5[0-9]{2}|4[1-9][0-9]|40[0-35-9])$"
SecDebugLogLevel 1

# Existing reviewed SecRuleUpdateTargetById exclusions belong below.
```

这保留所有 5xx、所有 4xx 除 404 的状态过滤。它控制的是 **RelevantOnly 的状态筛选**，不是“所有命中都记录”；调优模式和特定探针仍能强制当前请求写审计。

从旧文件移除这些由 UI 最后生成的设置：

| 旧设置 | 新的归属 |
| --- | --- |
| `SecRuleEngine DetectionOnly` | Domains & WAF 的模式；初始化为 DetectionOnly |
| `SecResponseBodyAccess Off` | `ui.env` 的 `CADDY_UI_RESPONSE_BODY_ACCESS=Off` |
| `SecAuditEngine RelevantOnly`、`SecAuditLogFormat JSON` | UI 固定生成 |
| `SecAuditLog /var/log/caddy/coraza-audit.json` | `CADDY_UI_AUDIT_LOG`，同一路径继续使用 |
| `SecAuditLogParts AHKZ` | `CADDY_UI_AUDIT_LOG_PARTS=AHKZ` |
| `SecAuditLogFileMode 0600` | UI 生成 0640；目录 0750，不设成 0644 |

不删除业务需要的旧例外。UI 不会自动把外部文件里的静态例外导入表单，也不能从表单编辑这些例外；将其逐条迁入 UI 时，预览、应用并移除旧文件中的重复定义。

确保两个文件可供 65532 读取、父目录可遍历。若原来 0600/root，仅调整这两个文件及必要目录权限；含认证秘密的其他配置不要一起放宽。

```bash
sudo chgrp 65532 observability/caddy \
  observability/caddy/waf-before.conf observability/caddy/waf-after.conf
sudo chmod 0750 observability/caddy
sudo chmod 0640 observability/caddy/waf-before.conf observability/caddy/waf-after.conf
```

主 Caddyfile 同样需供 Caddy/UI 读取。旧 UID 不同时，在第 7 节维护窗口内处理实际的 Caddy 专用文件/卷权限：现有 access/login/error 文件即使目录可写，0600 且属于旧 UID 仍不能被新 UID 打开。逐个核对、迁移其属主或 ACL；不要只修好审计文件就认为整个 Caddy 已具备权限。

## 6. 配置 UI、初始化和修改 Caddyfile

### 6.1 UI 环境

```bash
openssl rand -hex 32
sudoedit observability/waf-ui/ui.env
```

将随机输出填到 `CADDY_UI_TOKEN`，不是 example 占位值。至少 32 个字符，保存后不要打印整个文件。

| 变量 | 本场景的设置 |
| --- | --- |
| `CADDY_UI_SITES` | `chat.example.com`，多个普通域名用逗号分隔；不支持通配符/端口 |
| `CADDY_UI_NODE` | `ip-172-31-2-69` 或你的真实、唯一节点名 |
| `CADDY_UI_AUDIT_LOG` | `/var/log/caddy/coraza-audit.json` |
| `CADDY_UI_WAF_BEFORE_FILE` / `_AFTER_FILE` | `/etc/caddy/waf-custom/waf-before.conf` / `waf-after.conf` |
| `CADDY_UI_RESPONSE_BODY_ACCESS` | `Off`，保留 SSE 行为 |
| `CADDY_UI_AUDIT_LOG_PARTS` | `AHKZ`，默认不采集请求头和正文 |
| `CADDY_UI_AUDIT_ROTATE_MB` | **先为 0**，避免与旧 logrotate 同时轮转 |
| `CADDY_UI_REDACTION_LOCAL` / `_CLOUD` | `standard` / `strict` |
| `CADDY_UI_PROBE_URLS` | `{"chat.example.com":"https://caddy/__waf_health"}`；使用可无副作用访问的路径 |
| `CADDY_UI_LOKI_SYNC_INTERVAL` | `0s`，按需查云端，避免小机器周期性全量回填 |
| 本地/云端磁盘上限 | 各 128 MiB；原始审计归档另算 |

此文件通过 Compose `env_file` 注入 UI 容器。原项目 `.env` 用来展开 Compose 变量；**它不等于自动给容器注入所有环境变量**。本例直接使用 `CADDY_UI_LOKI_*`，不需要把原生 Alloy 的写入 Token 复制过来。

探测走内部 `waf-probe` 网络，连接 Caddy 服务的 443，Host/SNI 使用受管域名且检查证书。已有证书/站点尚未就绪时，可暂留空，只完成 readback；证书就绪后启用并验收 request 阶段。不要用 Cloudflare 公网地址替代源站探测，也不要关闭 TLS 校验掩盖问题。

### 6.2 保持原有 Compose 接线

配套片段给 Caddy 增加 `waf-probe`，并显式保留 `default`，以免原本使用隐式 default 的 Caddy 失去 `api:3080`。已有自定义应用网络也必须出现在最终合并结果中。UI 只加入内部探测网和出站网，不加入数据库网络。

本例不改 Caddy 镜像。先不要切 ipset 镜像，以便单独验收 UI 接入。DHI 镜像没有 `sh`、`curl`、`ls`、`date`；Caddy 操作始终用 `/usr/local/bin/caddy`。如果旧 Caddy 有依赖这些工具的 healthcheck，换成可用的健康方案或明确禁用；检查其它服务是否依赖其 `service_healthy`。

### 6.3 初始化受管文件

```bash
waf_dc config --quiet
waf_dc build caddy-waf-ui
waf_dc run --rm --no-deps waf-ui-config-init
```

此时可以还没修改 Caddyfile。初始化只写缺失/占位 overlay，不重启 Caddy，不覆盖有效 WAF 策略、例外或 IP 列表。查看结果：

```bash
sudo ls -l observability/waf-ui/managed
sudo sed -n '1,90p' observability/waf-ui/managed/waf-chat_example_com.conf
```

应有 `waf-chat_example_com.conf`、`exclusions-chat_example_com.conf`、`ip-rules-chat_example_com.conf`。域名中的点和连字符换为下划线，其他域名分别生成。不要让两个不同域名使用碰撞的同一 slug。

### 6.4 修改真实 Caddyfile

在已有**全局块**增加/修改 Admin 行，不再增加第二个全局块；保留邮件、DNS、security、真实 IP、运行日志等原设置：

```caddyfile
{
    admin unix//run/caddy-admin/admin.sock
    order coraza_waf first
    # Existing global settings stay here.
}
```

迁移每个受管站点原有 route。下面只是该 route 的变更示例，**不用于覆盖原有认证、匹配器、日志、代理传输配置或 handle_errors**：

```caddyfile
chat.example.com {
    # Existing site logging, matchers and error handlers stay in place.
    route {
        request_header X-Request-ID {http.request.uuid}
        log_append <tx_id {http.request.uuid}
        log_append <path {http.request.uri.path}
        log_append <upstream "{$LIBRECHAT_UPSTREAM:api:3080}"
        header X-Request-ID {http.request.uuid}

        # Late logging records Coraza's ID even when the WAF rejects a request.
        log_append waf_tx_id {http.transaction_id}
        import /etc/caddy/ui-managed/ip-rules-chat_example_com.conf
        import /etc/caddy/ui-managed/waf-chat_example_com.conf

        # Existing authenticate / authorize / handlers stay in their order.
        reverse_proxy "{$LIBRECHAT_UPSTREAM:api:3080}" {
            flush_interval -1
            header_up X-Forwarded-For {http.vars.client_ip}
            header_up X-Real-IP {http.vars.client_ip}
            header_up -CF-Connecting-IP
            header_up -Forwarded
            header_down X-Request-ID {http.request.uuid}
            transport http {
                dial_timeout 10s
                response_header_timeout 120s
            }
        }
    }
}
```

实际多机上游继续使用原值，不换成 `api:3080`。`LIBRECHAT_UPSTREAM` 不能显式为空；保留 Caddy 容器中的原有 environment 注入。

IP import 必须在 WAF import 之前，二者都要经过原来需要检查的请求路径。使用 `handle`/route 匹配器的部署，把它们放在对应作用域，不意外扩大或绕过认证。

删除被替换的手写 `coraza_waf` 块、重复的 baseline/CRS Includes 和手动 revision 标记；自定义内容已经在第 5 节保留。`exclusions-*.conf` 是 UI 的数据源，由生成器组合进 WAF，**不用再单独 import 它**。

**请求 ID 的迁移边界：** 当前生成器不输出旧 `tx_id_req_header X-Request-ID`。应用继续收到入口生成的 UUID；Coraza 使用自己的事务 ID。新增的 `log_append waf_tx_id {http.transaction_id}` 把两者放在同一条本地访问日志中，作为回溯桥梁。此行放在 WAF 之前且不能写成 `<waf_tx_id`，因为它需要在下游执行后取到 ID。[Caddy 的 late/early 语义](https://caddyserver.com/docs/caddyfile/directives/log_append)、[coraza-caddy 的事务 ID 占位符](https://github.com/corazawaf/coraza-caddy/blob/v2.6.1/coraza.go)。WAF Off、IP 规则在 WAF 前拒绝等情况下可能没有 WAF ID，不据此判断采集失败。

单文件 bind mount 在编辑器原子替换后可能仍指向旧 inode。本文下一步重新创建 Caddy/UI，所以重新读取新文件；今后修改此类主文件时也要确认运行容器看到的是新内容。目录挂载的自定义规则则可见新文件，仍需重新应用 WAF 模式。

## 7. 校验后在维护窗口上线

先做一次不接管端口的校验：

```bash
waf_dc config --quiet
waf_dc run --rm --no-deps waf-ui-config-init
waf_dc run --rm --no-deps --entrypoint /usr/local/bin/caddy caddy \
  validate --config /etc/caddy/Caddyfile --adapter caddyfile
```

初始化现在也会核对 Caddyfile 的 managed import 是否都有对应站点。`validate` 通过后，再检查合并结果的 Caddy 镜像/证书卷/环境/应用网络保持正确。只在服务器本机检查，不传播含密码的完整输出。

新增挂载、网络、运行身份和 Admin 地址需要重建 Caddy，不能仅 reload。维护窗口执行，已有 SSE 会断开，应让用户停止生成后再操作：

```bash
waf_dc up -d --no-deps --force-recreate caddy
waf_dc up -d --no-deps caddy-waf-ui
waf_dc ps caddy caddy-waf-ui
waf_dc logs --tail=50 caddy-waf-ui
curl -fsS http://127.0.0.1:18088/health
```

只启动这两个服务，不启动示例应用，不重建数据库。默认 UI 内存上限 256 MiB、CPU 0.5，`GOMEMLIMIT=160MiB` 是 GC 目标而非总内存硬上限；实际负载用 `docker stats` 检查。

从自己电脑用 SSH 隧道访问服务器：

```bash
ssh -N -L 18088:127.0.0.1:18088 ops@SERVER
```

浏览器打开 `http://127.0.0.1:18088`，用 `CADDY_UI_TOKEN` 登录。避免把 18088/2019 开到公网。要长期反代，采用 HTTPS 和已有运维认证，不将 UI 管理接口作为普通 LibreChat 用户页面。

Admin socket 能替换 Caddy 的全部配置。UI 的 socket 目录只读挂载并不削弱这一权限；不挂给 Alloy、应用或不可信边车。

## 8. 先验收本地链路，再切换上云链路

### 8.1 站点与发布

1. **Domains & WAF** 中看到 `chat.example.com`，初始为 DetectionOnly。
2. 点击 **Apply Mode** 重新应用当前 DetectionOnly。
3. **Rollback & History** 中 load、readback 成功；配置了 probe URL 时 request 也成功，未配置则是 skipped。
4. 发布探测规则 9001200 被故意排除在普通事件列表外，所以“request 成功但 Events 没有探针”正常。

### 8.2 手动事件探针

有 Cloudflare/WAF/CDN 前置时，公网 `/.env` 可能先被前置设备拦截；用后面的本地 raw 记录证明它是否到了 Caddy。不要只凭浏览器状态码下结论。

用原来熟悉的合成探针也可以。在 before 中临时加入一条（确认没有重复 ID）：

```apache
SecRule REQUEST_URI "@streq /__waf_probe__" "id:1000001,phase:1,pass,log,auditlog,ctl:auditEngine=On,msg:'WAF_PIPELINE_PROBE',tag:'pipeline-test'"
```

在 UI 重新应用当前模式；重启 UI 让自定义规则字典读取新 `msg`，不需要重建 Caddy：

```bash
waf_dc restart caddy-waf-ui
curl -sS --max-time 20 -D - -o /dev/null \
  -H 'Cache-Control: no-cache' https://chat.example.com/__waf_probe__
sudo tail -n 100 logs/caddy/coraza-audit.json |
  jq -c 'select(any(.messages[]?; (.data.id|tostring) == "1000001")) |
  {tx:.transaction.id,time:.transaction.timestamp,mode:.transaction.producer.rule_engine,
   interrupted:.transaction.is_interrupted,rule_ids:[.messages[]?.data.id]}'
```

`@streq` 要求 URI 完全相等，不追加查询串。`ctl:auditEngine=On` 只强制该请求写审计，否则返回 200 的 pass 探针会被 RelevantOnly 过滤。这不会开启全站审计。

在 **Events** 查到 1000001，说明 raw → 本地 UI 成功。再发 `/.env` 或 `/.git/config`，能到源站时通常命中 930130 和 949110；DetectionOnly 放行，On 才实际拒绝。测试时不得向生产业务发送会有副作用的请求。

无规则命中、未中断的普通 4xx/5xx 审计记录不会变成 WAF 事件。原来的“日志存在但 rule_ids 为空”不能当作 WAF 事件丢失。

### 8.3 规则解释和回溯

- **Rules** 搜索 `930130,949110`，也可直接粘贴 `"rule_ids_csv":"930130,949110"`。
- 930130 是受限文件访问检测，例如 `.env`、`.git/`；949110 是入站评分达到阈值的判定。处理误报时定位加分规则和命中变量，不排除 949110。
- **Events** 的编号能跳到规则说明，详情有规则、变量、分数、模式和配置 revision；按站点、路径、IP、时间筛选。
- 需要本地匹配片段时点 **Show matched values**，服从当前本地脱敏级别。AHKZ 没采集的请求头/正文不会凭空恢复。
- 云端事件没有原始正文；超过原始文件保留窗后，也无法再恢复本地匹配片段。

访问日志保留两个 ID 时，可以用 UI 事件中的 Coraza ID 查回应用 UUID。按实际文件名替换 `access.json`：

```bash
waf_tx_id='<从 UI 事件复制的 Coraza 事务 ID>'
sudo jq -c --arg id "$waf_tx_id" \
  'select(.waf_tx_id == $id) |
   {ts,tx_id,waf_tx_id,path,status,ip:.request.client_ip}' logs/caddy/access.json
```

再用这一行的 `tx_id` 到已有应用/健康摘要日志查对应请求。没有修改应用日志生产者的部署，不能承诺应用一定记录了这个 UUID。

### 8.4 首次读取与历史预算

UI 没有旧读取游标时会从现有 raw 文件开始读，保留窗内的有用历史可成为本地事件，并按当前云端策略生成新队列。旧日志中的站点/revision 可能不完整，不能伪造为新策略下的事件。

首次回填会占用本地/云端磁盘预算，也可能把旧 `job="coraza"` 中的同一事务以新格式再上传一次。Grafana Cloud 可能拒收过旧的时间戳；保留期 14 天并不等于允许补写任意 14 天前的数据。观察 queue、Alloy 的 too-old/out-of-order 错误和 Cloud 用量。

若希望只从切换时刻采集，**在 Caddy 已停止的维护窗口**把现有 raw 文件保存为备份目录中的独立旧文件，再在原路径创建 65532:65532/0640 的新文件，然后启动 Caddy/UI。不要趁 Caddy 运行时直接截断或移走它，也不要把旧备份命名为 UI 的 `.rotated-*` 格式。这样旧历史仍在备份和原 Grafana 流中，但不会自动出现在新 UI；这是明确选择，不是无损导入。

## 9. 让原有宿主机 Alloy 改读云端事件队列

### 9.1 只替换旧 WAF source/process，复用 writer

在 `/etc/alloy/config.alloy` 中找到旧的：

```text
loki.source.file "librechat_coraza"
loki.process "librechat_coraza_safe"
loki.write "librechat_cloud"
```

先确认你的现场名称一致。删除/停用前两个 raw-audit source/process，**保留第三个 writer**。如果另有可选 node health 链引用它，更不能删除 writer。随后把 `observability/waf-ui/waf-ui.alloy` 的内容追加一次。

示例实际读取：

```text
/opt/librechat-a/observability/waf-ui/data/cloud/events/events-*.jsonl
```

它不读取 `data/events/`、`imported-*`、原始审计、草稿或配置 diff。本手册先不上报全量访问/运行日志，保留原来“访问记录留本地”的方案，减少资源和 Cloud 用量。

模板引用旧 `loki.write.librechat_cloud.receiver`，继续使用 `/etc/alloy/librechat-waf.env` 中的 `GRAFANA_LOKI_URL`、`GRAFANA_LOKI_USERNAME` 和 `/etc/alloy/secrets/librechat-loki-token`。原 `90-librechat-waf.conf` 保留，不改安装脚本的 `env.conf`，不复制写入 Token 到 UI。 如果旧 Access Policy 的 label policy 只允许 `job="coraza"`，还要允许新 `job="caddy-waf-ui"`；否则正确 Token 也可能拒绝新流。保持实际 Stack 和 logs:write 范围，不扩大为管理权限。`password_file` 属于 Alloy 支持的认证方式，见 [loki.write 文档](https://grafana.com/docs/alloy/latest/reference/components/loki/loki.write/)。

仅把片段放在旁边的 `waf-ui.alloy` 文件不会自动加载；现有服务启动的是 `/etc/alloy/config.alloy`，必须合并到主配置。不要为此改启动方式、状态路径或重新执行官网安装脚本。

### 9.2 给 Alloy 仅授予 cloud/events 的读权限

先用第 3 节确认服务用户。以下假设为 `alloy`；实际不同就替换。安装 `acl` 工具（已安装则跳过）：

```bash
sudo apt-get install acl
sudo setfacl -m u:alloy:--x /opt /opt/librechat-a \
  /opt/librechat-a/observability /opt/librechat-a/observability/waf-ui \
  /opt/librechat-a/observability/waf-ui/data \
  /opt/librechat-a/observability/waf-ui/data/cloud
```

UI 已启动后应有 `cloud/events` 目录。给现有目录/文件和将来的每日文件授权：

```bash
sudo setfacl -m u:alloy:r-x \
  /opt/librechat-a/observability/waf-ui/data/cloud/events
sudo setfacl -m d:u:alloy:r-x \
  /opt/librechat-a/observability/waf-ui/data/cloud/events
sudo find /opt/librechat-a/observability/waf-ui/data/cloud/events \
  -maxdepth 1 -type f -name 'events-*.jsonl' -exec setfacl -m u:alloy:r-- {} +
sudo -u alloy find /opt/librechat-a/observability/waf-ui/data/cloud/events \
  -maxdepth 1 -type f -name 'events-*.jsonl' -readable
```

父目录只授予遍历，不递归开放整个 data。检查实际文件的 ACL mask，权限需经受住 UI 创建次日文件；default ACL 用于新文件，不替代已有文件 ACL。Alloy 不需加入 65532 组、不需成为 Docker 组成员，也不需以 root 运行。

使用前一节的新事件检查至少一个文件可读，并确认丰富本地事件文件和 raw 审计不在新的采集配置中。旧 raw-audit ACL 在迁移验收前留作回退；切换成功后撤销旧手册添加的用户授权：

```bash
sudo setfacl -x u:alloy /opt/librechat-a/logs/caddy/coraza-audit.json
sudo setfacl -x u:alloy /opt/librechat-a/logs/caddy
```

只在确认这些 ACL 是旧 WAF 采集专用时执行；还被其他采集任务使用的权限先审阅。不撤销 /opt 和主项目目录的必要遍历 ACL。

### 9.3 校验与应用

```bash
sudoedit /etc/alloy/config.alloy
sudo /usr/bin/alloy validate /etc/alloy/config.alloy
sudo systemctl reload alloy.service
systemctl status alloy.service --no-pager -l
sudo journalctl -u alloy.service --since '-10 min' --no-pager -o short-iso
```

本次只改组件配置，用 reload；改了 EnvironmentFile/启动参数时才 daemon-reload 并 restart，见 [官方 Linux 配置说明](https://grafana.com/docs/alloy/latest/configure/linux/)。保留 `/var/lib/alloy/data`，不删位置文件来“修复”日志。

`validate` 不证明文件可读或云端已收到。模板首次读队列为 `tail_from_end=false`，包括发现文件之前已写入的脱敏事件；保留位置信息以避免任意重放。[文件采集行为](https://grafana.com/docs/alloy/latest/reference/components/loki/loki.source.file/)。

Grafana Explore 选择最近 15 分钟、停止 Live，先查宽查询：

```logql
{job="caddy-waf-ui",kind="event"}
```

重新发一次 1000001 探针，再查：

```logql
{job="caddy-waf-ui",kind="event"} | json | rule_ids_csv =~ "(^|.*,)1000001(,.*|$)"
```

新格式会给编号串添加边界逗号，可能是 `,930130,949110,`；UI 接受这种形式。不要只搜索已经停止投递的旧 `{job="coraza"}` 判断新链路失败。

新 source 自己持有读取位置，但 UI 队列不是 Cloud 已确认的可靠消息队列。Alloy 的重试、断网、进程崩溃与保留窗都影响交付；看到本地 cloud 文件不等于 Loki 已接收。验收必须看到真实云端新事件。

## 10. 配置本地 UI 的 Loki 历史查询

在 Grafana Cloud 为这个 Stack 另建仅有 **logs:read** 的 Access Policy Token；原 Alloy 写令牌继续只有 **logs:write**。两者不混用，作用域限制到实际 Stack。见 [Grafana Cloud Access Policy](https://grafana.com/docs/grafana-cloud/platform/security-and-account-management/security-and-access/authentication-and-permissions/access-policies/)。

编辑 `observability/waf-ui/ui.env`：

```dotenv
CADDY_UI_LOKI_URL=https://logs-你的区域.grafana.net
CADDY_UI_LOKI_USER=你的Logs租户数字ID
CADDY_UI_LOKI_TOKEN=仅logs-read权限的实际Token
CADDY_UI_LOKI_SELECTOR={job="caddy-waf-ui",kind="event"}
CADDY_UI_LOKI_SYNC_INTERVAL=0s
CADDY_UI_GRAFANA_URL=https://你的Stack.grafana.net
CADDY_UI_GRAFANA_LOKI_DATASOURCE=实际Loki数据源UID
```

上述中文都是占位提示，填写控制台真实连接值。`CADDY_UI_LOKI_URL` 是根 URL，**不带 `/loki/api/v1/push`**；Alloy 旧 `GRAFANA_LOKI_URL` 仍是完整 push URL。租户 ID 不是 Grafana 登录名，数据源 UID 也不是显示名称。

```bash
waf_dc up -d --no-deps --force-recreate caddy-waf-ui
```

修改 env 文件后必须重建容器，`restart` 不会读取新的值。**Events → Source → Grafana Cloud Loki** 查询新事件；事件详情、规则说明仍在本地 UI 中展示。扩大范围时注意页面的 incomplete-history/分页提示，不把第一页当作完整历史。

需要更丰富的请求细节仍依赖本机 raw 文件；从 Cloud 导回的脱敏记录不会补回原先没有保存的秘密或正文，也不会再次写进上云队列。

## 11. 轮转交接与磁盘预算

初次验收期间 `CADDY_UI_AUDIT_ROTATE_MB=0`，原宿主机 `copytruncate` 规则继续工作。确认本地读取、发布、源站验证和云端新事件都正常后，建议交给 UI 改名轮转，保留本地匹配片段。

先备份/检查 `/etc/logrotate.d/librechat-coraza`。它只管理这个审计文件时，把整份规则移到第 3 节的备份目录；有其它日志时，只移除审计 stanza，保留其余规则。别把 `.disabled` 文件继续留在 logrotate 配置目录中依赖忽略规则，也不要禁用整个 logrotate.timer。

然后改 `ui.env`：

```dotenv
CADDY_UI_AUDIT_ROTATE_MB=32
CADDY_UI_AUDIT_ARCHIVE_HOURS=48
```

```bash
waf_dc up -d --no-deps --force-recreate caddy-waf-ui
```

UI 每 30 秒检查原始日志大小，达到阈值后改名、重新应用站点模式，让 Coraza 打开新文件；旧实例/长连接可能继续向归档写入。归档至少保留 48 小时，已读完且超过保留窗后清理。**同一审计文件只能选一种轮转方式**。访问/登录/错误日志仍由原 Caddy 或原有机制维护。

| 对象 | 本例预算/行为 |
| --- | --- |
| UI 运行内存 | 256 MiB 上限，缓存 1000 条完整事件，较早事件按磁盘查询 |
| 本地规范化事件 | 14 天、128 MiB；达到上限可能暂停摄取 |
| 独立云端副本 | 14 天、128 MiB；不是“上传确认后立即清空”的队列 |
| 原始审计和归档 | 每次约 32 MiB 轮转；需按至少两天真实流量另留磁盘 |
| 请求体临时空间 | 独立磁盘目录；按并发上传预算，不计入事件上限 |
| 快照、草稿、变更、汇总、Alloy 位置/指标 WAL | 另占空间，不能只按两个 128 MiB 估算 |

```bash
docker stats --no-stream
sudo du -sh logs/caddy observability/waf-ui/data observability/waf-ui/backups observability/waf-ui/tmp
df -h /opt/librechat-a
```

既有 Alloy 的总负载包含旧指标采集；不要直接套用演示 Alloy 容器的 256 MiB 上限压缩原生服务。先观察实际内存/CPU，再调整现有集成。

2026-10-07 核对的 [Grafana Cloud 价格页](https://grafana.com/pricing/)列出 Free Logs 每月 50 GB 写入、14 天保留。所有已有共享日志也计入用量，控制台当前套餐/限制为准。只上传 WAF 事件，避免长期开启低分调优和全量访问日志；首次回填和攻击峰值也要计入预算。

## 12. 脱敏可调、策略调优和可选 ipset

### 12.1 脱敏

默认建议本地 `standard`、云端 `strict`。在 `ui.env` 调整：

```dotenv
CADDY_UI_REDACTION_LOCAL=standard
CADDY_UI_REDACTION_CLOUD=strict
CADDY_UI_REDACTION_HIDE=customer_email,internal_note
CADDY_UI_REDACTION_KEEP=
```

| 级别 | 内容 |
| --- | --- |
| strict | 保留规则、路径、参数名、分数等；隐藏匹配值、查询值和请求头 |
| standard | 保留可分类的诊断内容，隐藏识别出的密码、Token、Authorization、Cookie 等 |
| full | 保留已经采集的内容，**包括凭据**，除非 hide 命中；不自动开启正文采集 |

hide 优先于 keep；Cloud 有效级别不会比本地更宽。standard 按字段名识别，不是任意聊天文本的通用秘密识别器。改变级别后重建 UI；如果修改 `CADDY_UI_AUDIT_LOG_PARTS`，还要对每个站点重新应用当前模式。

`AHKZ` 不是原始日志匿名化；消息和匹配片段仍可能敏感。可选 `ABHKZ` 额外采集请求头，UI 查看/云端副本仍按各自策略处理。raw 文件永远不直接上云。更改级别不会清除之前排队、落盘或已经上传的历史，降低级别时要另行处理这些历史，详见 [可配置脱敏](redaction.md)。

### 12.2 调优与启用阻断

1. 保持 DetectionOnly，先验证登录、上传/RAG、Agent、SSE 首字/逐步输出/停止/断线、WebSocket，以及 OAuth/MCP 回调。
2. 短期开启 **Policy → Tuning mode**，收集响应 200 的低分命中；注意审计和 Cloud 用量。
3. 在事件详情和 Analysis 看命中变量及真实业务场景。正常聊天包含代码、SQL、HTML，不能直接视为攻击。
4. 用 **Exclusions** 做“检测规则 + 实际路径 + 参数”的最小范围例外，必要时设到期。不要排除 949110 或全局放行 `/api/`。
5. **Preview diff and impact → Apply reviewed policy/exclusions**，确认阶段成功；估算不能完整重放正文，也不能替代实际业务测试。
6. 业务回归通过后，再在 Domains & WAF 切 On。发现问题先回 DetectionOnly，再定位例外；由 Rollback & History 恢复合适的策略/排除快照。

修改 before/after 内容后，重新应用每个受影响站点的当前模式，生成新 revision，避免外部 Include 的 WAF 缓存。自定义规则说明在 UI 启动时读文件，更新说明另需重启 UI。不要手改受管 overlay，它会被下一次发布覆盖。

### 12.3 可选 ipset 镜像

本地 UI 接入验收后，有大量 IP 群组匹配需求再按 [ipset 镜像部署](ipset-image-deployment.md) 单独切换现有 Caddy 镜像；保持同一个服务和证书卷，固定 digest，保留旧 image/digest 便于回退。

Cloudflare 真实 IP 必须已经验证。先用 IP Groups/Policy 的 `trial` 看谁会被拒绝，再考虑 block/ban；ban 在 On 模式生效且不产生 WAF 审计事件，403 需要从访问日志观察。不要把 GeoIP 国家限制和实际身份认证混为一谈，也不要为“健康检查能进来”而广泛信任所有私网来源。

## 13. 排障顺序

| 现象 | 先检查 |
| --- | --- |
| UI 无站点 | 是否挂载真实 Caddyfile、原站点在 Admin 回读中是否存在、managed import 和初始化站点是否匹配 |
| permission denied | UID/GID、目录遍历、文件读取/日志目录改名权限；不 chmod 777，不给 UI 整个证书卷 |
| load 失败 | Admin socket 路径/属主、真实 Caddyfile 及其在 Caddy 中的 imports；`caddy validate` 的具体错误 |
| request 验证失败 | UI 到 Caddy 的内部网络、443/证书/SNI、无副作用路径、是否有另一层 WAF或IP规则先拒绝 |
| Events 空，raw 有记录 | 是否有命中/中断；普通无命中的 4xx/5xx 被跳过；是否选错站点/时间/来源 |
| 1000001 无审计 | 精确 URI、`ctl:auditEngine=On`、是否重新应用当前模式；前置 Cloudflare 是否拦截 |
| Cloud 空，本地 cloud 文件有事件 | Alloy 主配置是否真正合并、ACL、writer、logs:write、正确租户/push URL、拒收旧时间戳；用新 job 查询 |
| Loki 历史 unsupported events | selector 指向旧 coraza-v1 或 raw 文件；改回新 kind=event 流，不扩大 selector 混入其它日志 |
| 云端有事件但 UI 历史空 | logs:read、根 URL、租户 ID、时间范围和 selector；读写 Token 分别验证 |
| 上传 413/临时文件失败 | UI 与 before/after 的实际优先级、非文件 2 MiB 上限、应用限制、临时磁盘；不只调总请求上限 |
| 配置改了未生效 | env 更改需要重建；规则更改需要重新应用模式；单文件挂载可能旧 inode；不要只 `restart` |
| 事件读取 lag 持续增加 | 本地/云端磁盘预算、实际磁盘空间、摄取状态行和 UI 错误日志 |
| 日志突然频繁重开 | 是否仍有外部 logrotate，同时启用了 UI 轮转 |

短的分层检查命令：

```bash
waf_dc ps caddy caddy-waf-ui
waf_dc logs --tail=80 caddy-waf-ui
sudo tail -n 5 logs/caddy/coraza-audit.json |
  jq -c '{tx:.transaction.id,mode:.transaction.producer.rule_engine,ids:[.messages[]?.data.id]}'
sudo find observability/waf-ui/data/cloud/events -maxdepth 1 -type f -name 'events-*.jsonl' -printf '%f %s bytes\n'
sudo journalctl -u alloy.service --since '-10 min' --no-pager -o short-iso
```

`alloy.service active`、Prometheus WAL checkpoint、usage report、`journalctl -- No entries --` 都不能证明 Loki 接收成功。必须从 raw → UI local → cloud queue → Alloy → Cloud 新事件逐层验证。

## 14. 回滚

### 14.1 仅回退策略

UI 的 Rollback & History 可以恢复站点 WAF 模式/策略、排除或 IP 规则快照。恢复 WAF 快照使用当前 before/after 基线与当前排除列表，**不会把外部文件和整份 Caddyfile一起恢复**；排除变化要恢复排除快照。需要还原运维文件时用第 3 节备份，再重新应用模式。

### 14.2 完整撤回本次 UI 接入

1. 停止 UI，阻止维护轮转和后续策略写入：

   ```bash
   waf_dc stop caddy-waf-ui
   ```

2. 从迁移前备份恢复实际 Caddyfile、before/after、原 Compose 文件和 `.env`；恢复旧审计轮转规则。保留新的 UI 数据、快照和日志，不删除。
3. 用**旧 `base_dc` 文件集合和原项目名**验证恢复后的 Caddy 配置；原来改变过 UID/镜像/卷权限时一起核对，别恢复配置却忘了证书访问权限。

   ```bash
   base_dc run --rm --no-deps --entrypoint /usr/local/bin/caddy caddy \
     validate --config /etc/caddy/Caddyfile --adapter caddyfile
   base_dc up -d --no-deps --force-recreate caddy
   ```

4. 恢复旧 raw-audit source/process 和原生 Alloy 主配置中的相关部分，撤掉本次 UI source/process，但继续保留现在有效的指标配置。恢复旧审计文件/父目录的 Alloy ACL；必要时参照备份中的 ACL 逐项处理，别覆盖上线后新增的其他授权。

   ```bash
   sudo /usr/bin/alloy validate /etc/alloy/config.alloy
   sudo systemctl reload alloy.service
   ```

5. 用旧 `{job="coraza"}` 和 1000001 探针再次验收；检查 LibreChat 实际业务。新 Grafana 流和 UI 数据可继续保留用于事后排查。

只停止/恢复指定服务，不运行整个项目 `down`，不运行 `down -v`，不清空 `/var/lib/alloy/data`，不删除原始审计或证书卷。

## 15. 完成条件

- [ ] 仍是原有 Caddy 服务承接 80/443，API/RAG/数据库/认证/真实 IP 和证书正常。
- [ ] 初始 DetectionOnly，原 128 MiB 总请求体/2 MiB 非文件基线已保留，SSE 响应体检查为 Off。
- [ ] UI 能重新应用模式并完成 readback；配置探测时 request 也成功。
- [ ] 新探针在本地 raw 和 Events 都出现，Rules 能解释 930130/949110。
- [ ] 访问日志中的 waf_tx_id 可关联 UI 事件；应用 UUID 与它的区别已经验证。
- [ ] Alloy 只采集独立 cloud/events，原有指标、writer、systemd drop-in 和状态目录保持正常。
- [ ] Grafana Cloud 收到新 job 的真实事件，UI 用只读令牌能查到同一事件。
- [ ] 审计轮转只有一个执行者，原始归档/临时上传空间/事件预算都受监控。
- [ ] 本地与云端脱敏级别明确，生产凭据未进入源码/构建上下文/公开输出。
- [ ] 已完成 LibreChat 登录、SSE、上传/RAG、WebSocket、OAuth/MCP 等实际业务回归，并保存可用回退材料。
