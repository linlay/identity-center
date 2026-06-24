# identity-center

## 1. 项目简介

`identity-center` 是认证与管理服务，提供 OAuth2 / OIDC、管理后台、App 访问令牌和设备管理。

项目支持两种部署模式：Docker 容器编排（默认）和单二进制 Program Mode（用于桌面集成）。

Docker-first 部署契约：

- backend 固定只在容器网络内监听 `8080`
- frontend 对外暴露 `/admin/`
- release bundle 支持按版本离线部署
- 根目录 `.env.example` 只保留部署必要项
- 部署配置只保留当前服务自身的 `.env` 契约

## 2. 快速开始

```bash
cp .env.example .env
docker compose up -d --build
```

Release 现在统一整理为两条产线：

```bash
make release
make release-program
make release-image
```

说明：

- `make release` 等价于 `make release-program`。
- `make release-program` 默认产出两个 Program Bundle：
  - `darwin/arm64`
  - `windows/amd64`
- `make release-image` 默认产出当前宿主机架构对应的 Linux Image Bundle。
- Program Bundle 是宿主机程序部署包，包含后端二进制和 `frontend/dist`。
- Image Bundle 是容器镜像离线部署包，解压后导入镜像并通过 compose 启动。
- 所有 release 产物统一输出到 `dist/release/`。
- 正式版本默认读取根目录 `VERSION`，格式固定为 `vX.Y.Z`。
- 构建期默认使用 `https://goproxy.cn,direct` 和 `https://registry.npmmirror.com` 作为宿主机构建依赖源。
- 若构建机需要代理，请配置宿主机上的 `go` / `npm` 访问环境；代理只是可选辅助，不再是 release 默认成功路径的前提。
- Program Bundle 构建需要 Go 与 npm；Image Bundle 额外需要 Docker / buildx。
- 如需官方源、私有源或其它自定义源，仍可显式传入 `GOPROXY`、`NPM_REGISTRY` 覆盖默认值。

默认入口：

- 管理台：`http://127.0.0.1:11950/admin/`

如需通过外层总网关接入，请保持：

- 管理台前缀：`/admin/`
- API 前缀：`/admin/api`
- OAuth2 / OIDC：`/api/oauth2`、`/api/openid`

宿主机集成场景下，Node HTTP server 通过 `manifest.json` 注册路由时，约定：

- UI 公共入口固定为 `/admin/`
- 管理 API 以 `api.adminBaseUrl` 为准
- OIDC 以 `api.openidBaseUrl` 为准
- OAuth2 以 `api.oauth2BaseUrl` 为准

## 3. 配置说明

- 环境变量契约以根目录 `.env.example` 为准
- Image Bundle 产物中的 `.env.example` 会自动写入 `IDENTITY_CENTER_VERSION`，用于选择镜像标签
- 部署层只保留 `FRONTEND_PORT`；backend 不再暴露宿主机端口
- `BACKEND_PORT` 不再是有效部署变量；backend 容器内固定监听 `8080`
- `AUTH_ISSUER` 仍然必需，因为服务会用它生成 OIDC / OAuth2 metadata
- admin bcrypt 仍然必填，推荐在写入 `.env` 时保留单引号
- 数据默认挂载到 `./data`

## 4. 部署

- `compose.yml` 只负责双容器编排
- `make release` / `make release-program` 生成 Program Bundle 到 `dist/release/`
- `make release-image` 生成 Image Bundle 到 `dist/release/`
- backend 容器网络端口固定为 `8080`
- frontend 容器负责静态资源和反向代理
- 若由总网关接入，不要再单独公开 backend 端口
- 版本化打包说明见 `docs/versioned-release-bundle.md`

## 5. Release 用法

常用命令：

```bash
make release VERSION=v1.0.0
PROGRAM_TARGET_MATRIX=darwin/arm64,windows/amd64 make release-program VERSION=v1.0.0
PROGRAM_TARGETS=windows ARCH=amd64 make release-program VERSION=v1.0.0
make release-image VERSION=v1.0.0
```

产物命名示例：

```text
dist/release/identity-center-v1.0.0-darwin-arm64.tar.gz
dist/release/identity-center-v1.0.0-windows-amd64.zip
dist/release/identity-center-image-v1.0.0-linux-arm64.tar.gz
```

Bundle 解压后的最小内容：

- Program Bundle：`manifest.json`、`backend/identity-center(.exe)`、`frontend/dist`、当前平台根目录 `start/stop/deploy`、当前平台 `scripts/`、`.env.example`
- Image Bundle：`.env.example`、`README.txt`、`load-image.sh`、`start.sh`、`stop.sh`、`compose.release.yml`、`images/`、`data/`

Program Bundle 不再包含 frontend 进程；`frontend/dist` 由宿主 nginx 或等价前端网关托管，bundle 自身只负责 backend。`manifest.json` 中的 `frontend` / `api` 字段用于宿主 Node HTTP server 注册前端静态路由和 API 路由。Windows bundle 只包含 `.ps1` 入口，Darwin bundle 只包含 `.sh` 入口。

## 6. 运维

- 查看日志：`docker compose logs -f identity-center-backend identity-center-frontend`
- OIDC metadata：`curl -i http://127.0.0.1:11950/api/openid/.well-known/openid-configuration`
- bcrypt 生成接口：`POST /admin/api/bcrypt/generate`

## 7. 本地前端开发

- Vite 开发代理默认回落到 `http://localhost:8080`
- 如需改代理目标，只使用 `VITE_API_PROXY_TARGET`
- Vite 开发代理同时转发 `/admin/api`、`/api/*`，并兼容旧 `/oauth2`、`/openid`
- Docker 部署下仍只通过 frontend 网关访问 backend

## 7. 桌面集成（Program Mode）

```bash
make release-program
```

构建产物为 Program Bundle，无需 Docker 即可运行；bundle 内包含后端可执行文件和前端静态资源，frontend 路由由宿主系统处理。

关键环境变量：

| 变量 | 说明 |
|---|---|
| `SERVER_PORT` | backend 监听端口 |
| `AUTH_DB_PATH` | 认证数据库文件路径 |
