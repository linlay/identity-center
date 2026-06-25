identity-center — Program Bundle

本部署包用于宿主机程序部署，不依赖 Docker。
前端静态资源位于 `frontend/dist`，供外部宿主 nginx 或等价网关托管。

部署步骤
========

1. 复制 .env.example 为 .env，填入真实配置值。
2. 运行 `./deploy.sh`，初始化或更新 .env 配置。
3. macOS / Linux 运行 `./start.sh`；Windows 运行 `./start.ps1`。
4. 宿主 nginx 或部署系统负责把 `/admin/`、`/admin/api`、`/api/openid`、`/api/oauth2` 路由到正确入口；旧 `/openid`、`/oauth2` 仅作兼容。
5. 停止 backend 时，macOS / Linux 运行 `./stop.sh`；Windows 运行 `./stop.ps1`。

宿主接入约定
============

- 宿主 Node HTTP server 读取 `manifest.json` 注册前端与 API 路由。
- 前端 UI 公共入口固定为 `/admin/`
- API 公开前缀以 `manifest.json` 的 `api.adminBaseUrl`、`api.openidBaseUrl`、`api.oauth2BaseUrl` 为准

目录说明
========

.env.example                  — 根部署环境变量模板
manifest.json                 — bundle 清单文件
README.txt                    — 本文件
当前平台对应的 start / stop / deploy 入口
backend/                      — backend 程序
frontend/                     — 静态资源
scripts/                      — 当前平台辅助脚本与公共脚本
data/                         — 运行期自动创建的 SQLite 与密钥目录
run/                          — 运行期自动创建的 backend pid 与日志目录

辅助脚本
========

scripts/setup-public-key.{sh|ps1}           — 导出 JWK 公私钥与 publicKey.pem
scripts/issue-bridge-access-token.{sh|ps1}  — 生成供 bridge 调用的 app access token
scripts/issue-bridge-runner-token.{sh|ps1}  — 生成供内部 bridge 调 runner 使用的带 exp app access token
backend/identity-center(.exe) <command>  — 直接执行上述辅助能力，不依赖外部 openssl / sqlite3 命令

bridge token 设备标识
====================

- `issue-bridge-access-token` 与 `issue-bridge-runner-token` 支持 `--device-id <uuid>` / PowerShell `-DeviceId <uuid>`。
- 未显式传参时会读取环境变量 `DESKTOP_DEVICE_ID`；两者都不存在时，服务按原逻辑自生成或复用设备记录。
- 返回 JWT 的 `device_id` 与传入的 Desktop 安装级 UUID 保持一致。

注意事项
========

- backend 默认读取 `./data/auth.db`，数据库 schema 已内嵌到二进制。
- bundle 不再包含 frontend 进程；`frontend/dist` 由外部宿主 nginx 或等价网关托管。
- 根目录只携带当前平台入口；Windows bundle 不再附带 `.sh`，macOS / Linux bundle 不再附带 `.ps1`。
- `data/` 与 `run/` 在首次运行时自动创建，不预置在压缩包里。
- `scripts/` 下辅助脚本直接委托给 backend 二进制；不再依赖系统 `openssl`、`sqlite3` 或额外 SQLite DLL。
