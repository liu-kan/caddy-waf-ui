# 本地验证记录

日期：2026-10-07（America/Los_Angeles；对应运行日志为 2026-10-08 UTC）。

使用当前 caddy-waf-ui 工作目录构建专用 `caddy-waf-ui:manual-verify-20261007` 镜像；后端使用本机已有 `liukan/caddy-with-auth:coraza-plugins-ipset`，Alloy 使用 `grafana/alloy:v1.20.0`。全部运行在独立 `waf-manual-20261007` Compose 项目和临时测试卷中，凭据与请求内容均为合成值。

| 检查 | 结果 |
| --- | --- |
| 全部手册 Bash 代码块的 `bash -n` | 通过 |
| Compose 合并：Caddy 镜像、证书/配置卷、default 应用网络保留，另加 probe 网 | 通过 |
| UI 仅回环发布，不挂证书卷和 Docker socket | 通过 |
| UID 65532 初始化 overlay、Caddy 真正 `validate` | 通过 |
| 只读根文件系统 + 磁盘 SecTmpDir/TMPDIR | 通过；测试发现并补齐 TMPDIR |
| DetectionOnly 和 On 发布的 validate/load/readback/request 阶段 | 通过 |
| pass 探针 1000001、受限文件访问命中和 On 返回 403 | 通过 |
| 访问日志的入口 UUID 与 Coraza waf_tx_id 联查，包含被 WAF 拦截的请求 | 通过 |
| 本地 standard 与云端 strict 队列 | 通过；普通查询诊断值留本地，合成凭据/查询值不在云端副本中 |
| 配套原生 Alloy 组件语法、复用旧 writer/password_file、新队列发现与读取 | 通过 |
| Loki 协议模拟接收器解码真实 Alloy push | 通过；收到新 job/kind 的事件且未收到合成敏感值 |
| 本地 UI 查询规范化 Loki 历史 | 通过（模拟 Loki） |
| 930130/949110 查询和 930130 中文说明 | 通过 |
| UI 将 before 的 128 MiB 基线覆盖为 1 MiB，发送约 1.2 MB JSON | 返回 413，符合预期 |
| Linux default ACL：新建 0640 云端文件可供 Alloy 用户读取 | 通过 |
| 同一 Alloy 用户不能读取本地丰富事件/raw 文件，也不能写云端队列 | 通过 |

测试没有修改现有应用项目或其数据库、证书、Alloy 服务。验证结束后只清理独立测试项目和测试卷。

尚未验证：真实 VPS 的完整 Compose/认证/Cloudflare/证书配置、真实 systemd reload、Grafana Cloud 租户的实际授权与投递、生产 LibreChat 的 SSE/WebSocket/上传/RAG/OAuth/MCP，以及生产磁盘和并发负载。这些按主手册的现场验收步骤完成；模拟 Loki 成功不能替代真实 Cloud 验收。
