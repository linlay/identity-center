# CLAUDE.md

## 1. 项目概览

`zenmind-app-server` 是一套认证与管理服务，提供 OAuth2 / OIDC、管理后台、App 访问令牌和设备管理。

仓库采用双容器 fullstack 结构：

- `backend/`：Go API，容器内固定监听 `8080`
- `frontend/`：React 管理台与 nginx 前端容器资源，对外暴露 `/admin/`

### Program Mode

Program Bundle 当前只交付 backend 二进制与 `frontend/dist`。宿主机通过 `manifest.json` 注册前端与 API 路由，frontend 静态资源由宿主 nginx / Node HTTP server 托管。

## 2. 技术栈

- Backend：Go 1.23
- Frontend：React 18 + Vite
- HTTP 路由：`chi`
- 数据库：SQLite
- 配置：`.env`
- 部署：Docker / `docker compose`

## 3. 架构设计

- 浏览器访问 `/admin/`
- nginx 前端容器代理 `/admin/api/*`、`/api/*` 到 backend，并兼容旧 `/oauth2/*`、`/openid/*`
- backend 负责认证、授权、管理 API 和 SQLite 持久化
- 当前版本不再把外部可编辑配置文件作为默认部署能力
- 宿主机集成时，`manifest.json` 中的 `api` 字段用于宿主 Node HTTP server 注册 `/admin/api/`、`/api/openid/`、`/api/oauth2/` 路由

## 4. 目录结构

- `.env.example`：部署环境变量契约
- `compose.yml`：双容器本地编排
- `backend/`：Go 服务
- `frontend/`：管理台和 nginx 前端镜像资源
- `data/`：SQLite 持久化目录
- `scripts/release-program.sh`：Program 模式发布脚本
- `scripts/release-assets/program/`：Program 发布所需资源文件

## 5. 数据结构

核心模型仍位于：

- `backend/internal/model/types.go`
- `backend/internal/store/store.go`
- `backend/schema.sql`

## 6. API 定义

- Admin：`/admin/api/*`
- App Auth：`/api/auth/*`
- OAuth2：`/api/oauth2/*`
- OIDC：`/api/openid/*`
- `GET /admin/api/security/key-pair/export`：导出存储的 JWK 密钥对为 PEM 格式（需 admin 认证）

## 7. 开发要点

- `.env.example` 只维护部署必要字段
- backend 宿主机端口映射已从部署契约移除
- `BACKEND_PORT` 不再是有效部署变量；backend 容器内固定监听 `8080`
- `AUTH_ISSUER`、两个 bcrypt 仍是关键输入；前端入口固定为 `/admin/`
- 当前仓库仍兼容旧代码里的可编辑配置文件能力，但它不再是默认部署模型

## 8. 开发流程

1. `cp .env.example .env`
2. `docker compose up -d --build`
3. 后端改动后执行 `make backend-test`
4. 前端改动后执行 `make frontend-build`
5. `make release-program`：构建 Program 发布包。包含 backend 二进制、frontend dist、平台对应启停脚本和 .env.example

## 9. 已知约束与注意事项

- backend 仅容器网络访问
- frontend 是唯一默认对外入口
- 公开 issuer 必须与真实部署入口一致
- Program Bundle 由宿主机负责前端路由注册与静态资源托管，bundle 自身只负责 backend