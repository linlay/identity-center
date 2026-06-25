identity-center — Image Bundle

本文件只说明 image bundle 解压后的最小操作。该 bundle 用于离线导入镜像并运行 compose。

部署步骤
========

1. 复制 .env.example 为 .env，填入真实配置值。
2. 运行 ./load-image.sh 导入镜像；或直接运行 ./start.sh 让它按需自动导入。
3. 浏览器访问 http://127.0.0.1:11950/admin/（实际端口取决于 .env 中的 FRONTEND_PORT）。
4. 运行 ./stop.sh 停止服务。

目录说明
========

.env.example                  — 环境变量模板
compose.release.yml           — 容器编排
load-image.sh                 — 导入离线镜像包
start.sh                      — 启动脚本（会按需调用 load-image.sh）
stop.sh                       — 停止脚本
setup-public-key.sh           — 导出 JWK 公私钥与 publicKey.pem
issue-bridge-access-token.sh  — 生成供 bridge 调用的 app access token
issue-bridge-runner-token.sh  — 生成供内部 bridge 调 runner 使用的带 exp app access token
README.txt                    — 本文件
data/                         — 运行时数据目录
images/                       — Docker 镜像压缩包

bridge token 设备标识
====================

- `issue-bridge-access-token.sh` 与 `issue-bridge-runner-token.sh` 支持 `--device-id <uuid>`。
- 未显式传参时会读取环境变量 `DESKTOP_DEVICE_ID`；两者都不存在时，服务按原逻辑自生成或复用设备记录。
- 返回 JWT 的 `device_id` 与传入的 Desktop 安装级 UUID 保持一致。

注意事项
========

- 需要 Docker Engine 20+ 和 docker compose v2。
- image bundle 默认只打包 Linux 当前架构镜像。
- frontend 容器为 nginx，负责 `/admin/` 静态资源与 `/admin/api`、`/api/*` 反向代理，并兼容旧 `/oauth2`、`/openid` 协议入口。
- 镜像使用 bundle 内部固定标签，.env 不需要维护镜像版本。
- `setup-public-key.sh`、`issue-bridge-access-token.sh`、`issue-bridge-runner-token.sh` 依赖 `openssl` 和 `sqlite3`。
