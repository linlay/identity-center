# Go 全栈子服务 Program Bundle 运行时规范

## 1. 设计原则

Program Bundle 是“已经完成前端构建和后端编译、可直接交付宿主加载和运行的独立子服务运行包”。

当前仓库的 Program Bundle 采用“backend + frontend static assets”模式：

- bundle 内交付 backend 二进制与 `frontend/dist`
- 不再交付、也不再依赖 Go 实现的 `frontend-gateway`
- 默认不交付 `frontend/nginx.conf`，前端路由由宿主系统负责
- 每个平台只交付该平台真正需要的入口与辅助脚本
- `data/`、`run/` 等运行期目录由脚本按需创建

Image Bundle 是另一类交付物，用于容器镜像离线分发。该模式下 frontend 容器回到 nginx 路线，由 nginx 提供静态资源和反向代理。

## 2. 最小可运行 Bundle 结构

Darwin / Linux：

```text
<bundle-root>/
  manifest.json
  .env.example
  start.sh
  stop.sh
  deploy.sh
  scripts/
    program-common.sh
    setup-public-key.sh
    issue-bridge-access-token.sh
    issue-bridge-runner-token.sh
  backend/
    identity-center
  frontend/
    dist/
      index.html
      assets/
```

Windows：

```text
<bundle-root>/
  manifest.json
  .env.example
  start.ps1
  stop.ps1
  deploy.ps1
  scripts/
    program-common.ps1
    setup-public-key.ps1
    issue-bridge-access-token.ps1
    issue-bridge-runner-token.ps1
  backend/
    identity-center.exe
  frontend/
    dist/
      index.html
      assets/
```

默认必需项：

- `manifest.json`
- `.env.example`
- 当前平台对应的 `start` / `stop` / `deploy` 入口
- 当前平台对应的 `scripts/`
- `backend/identity-center` 或 `backend/identity-center.exe`
- `frontend/dist/index.html`
- `frontend/dist/assets/`

可选项：

- `README.txt`
- `frontend/dist/favicon.ico`
- `frontend/dist` 下其他静态资源

## 3. 目录职责

- `manifest.json`：宿主识别和加载 bundle 的描述文件；宿主 Node HTTP server 依赖其中的 `frontend` / `api` 配置注册前端静态路由和 API 路由
- `.env.example`：根部署环境变量模板
- `start.*` / `stop.*` / `deploy.*`：当前平台标准入口，默认只管理 backend
- `scripts/`：当前平台辅助脚本与公共脚本；辅助脚本优先委托 backend 二进制执行 key/token 生成
- `backend/identity-center(.exe)`：后端主程序
- `frontend/dist/`：前端构建产物，由宿主 nginx、Node HTTP server 或等价前端网关托管
- `data/`：运行期数据目录，默认由脚本在首次运行时创建
- `run/`：运行期 backend pid / log 目录，默认由脚本在首次运行时创建

约束：

- Program Bundle 根目录名仍为 `identity-center/`
- bundle 默认不包含 `frontend/nginx.conf`
- bundle 默认不包含 `configs/runtime.env.example`
- bundle 默认不预置空的 `data/`、`run/`、`logs/`
- macOS / Linux bundle 不包含 `.ps1`
- Windows bundle 不包含 `.sh`

## 4. manifest.json 规范

最小示例：

```json
{
  "id": "identity-center",
  "name": "identity-center",
  "version": "v1.0.0",
  "platform": {
    "os": "darwin",
    "arch": "arm64"
  },
  "frontend": {
    "dist": "frontend/dist",
    "index": "index.html",
    "spa": true
  },
  "api": {
    "enabled": true,
    "adminBaseUrl": "/admin/api/",
    "openidBaseUrl": "/api/openid/",
    "oauth2BaseUrl": "/api/oauth2/"
  },
  "backend": {
    "entry": "backend/identity-center"
  },
  "scripts": {
    "start": "start.sh",
    "stop": "stop.sh",
    "deploy": "deploy.sh"
  }
}
```

Windows 示例：

```json
{
  "id": "identity-center",
  "name": "identity-center",
  "version": "v1.0.0",
  "platform": {
    "os": "windows",
    "arch": "amd64"
  },
  "frontend": {
    "dist": "frontend/dist",
    "index": "index.html",
    "spa": true
  },
  "api": {
    "enabled": true,
    "adminBaseUrl": "/admin/api/",
    "openidBaseUrl": "/api/openid/",
    "oauth2BaseUrl": "/api/oauth2/"
  },
  "backend": {
    "entry": "backend/identity-center.exe"
  },
  "scripts": {
    "start": "start.ps1",
    "stop": "stop.ps1",
    "deploy": "deploy.ps1"
  }
}
```

字段语义：

- `frontend.dist` / `frontend.index` / `frontend.spa`：宿主 Node HTTP server 用来注册前端静态目录、页面入口与 SPA fallback 规则
- `api.enabled`：宿主 Node HTTP server 用来决定是否为该 bundle 注册 API 路由能力
- `api.adminBaseUrl`：管理 API 的公开入口前缀
- `api.openidBaseUrl`：OIDC 公开入口前缀
- `api.oauth2BaseUrl`：OAuth2 公开入口前缀
- `backend.entry`：宿主或部署脚本用来定位 backend 可执行文件
- 前端 UI 公共入口固定为 `/admin/`

强制约束：

- manifest 中所有路径均相对于 bundle 根目录
- `frontend.dist` 指向编译后的静态资源目录
- `backend.entry` 指向编译后的二进制，而不是源码入口
- `scripts` 字段必须指向当前 bundle 中真实存在的入口文件
- 不再使用 `frontend.nginxConfig`

## 5. 前端与后端运行时要求

前端：

- 前端静态资源只保留在 `frontend/dist/`
- Program Bundle 本身不包含 frontend 进程
- `/admin/`、`/admin/api/`、`/api/openid/`、`/api/oauth2/` 的最终注册和转发由宿主系统负责
- 镜像部署模式下，这些路由由 nginx frontend 容器负责
- 前端仍需支持基于 `/admin/` 的运行
- 宿主机接入 Node HTTP server 时，API 路由应直接使用 manifest 中声明的公开前缀

后端：

- 后端只包含编译后的二进制，不包含源码结构
- 默认由 Program 启动脚本拉起，监听端口由启动参数、`SERVER_PORT` 或内置默认值控制
- 后端数据库路径默认是 `./data/auth.db`
- 数据库 schema 已内嵌在后端二进制中，不依赖外置 `schema.sql`
- 后端二进制提供 `setup-public-key`、`issue-bridge-access-token`、`issue-bridge-runner-token` 子命令，可直接生成 JWK PEM 文件和 bridge token，不依赖外部 `openssl` / `sqlite3` 命令
- `issue-bridge-access-token` 和 `issue-bridge-runner-token` 支持 `--device-id <uuid>`（PowerShell wrapper 为 `-DeviceId <uuid>`），未传参时读取 `DESKTOP_DEVICE_ID`，仍为空时按服务原逻辑自生成或复用设备记录

运行期目录：

- `data/` 与 `run/` 可以存在，但由启动脚本按需创建
- `logs/` 不应作为独立目录预置到 bundle

## 6. 命名建议

当前仓库采用以下交付命名：

- Program Bundle：`identity-center-vX.Y.Z-<os>-<arch>.<ext>`
- Image Bundle：`identity-center-image-vX.Y.Z-linux-<arch>.tar.gz`

示例：

- `identity-center-v1.0.0-darwin-arm64.tar.gz`
- `identity-center-v1.0.0-windows-amd64.zip`
- `identity-center-image-v1.0.0-linux-arm64.tar.gz`

命名规则：

- Program Bundle：服务名 + 版本 + 平台 + 架构
- Image Bundle：服务名 + `image` + 版本 + 平台 + 架构

## 7. 不应进入 Bundle 的内容

以下内容不应进入最终 Program Bundle：

- 前端源码
- Go 源码
- Go gateway 相关源码与二进制
- 测试文件
- `node_modules`
- 构建缓存
- Git 元数据
- 与运行时无关的文档
- `frontend/nginx.conf`
- `configs/runtime.env.example`
- 空的 `data/`、`run/`、`logs/`
- 非当前平台入口脚本
- 非当前平台辅助脚本
- 外置 `backend/schema.sql`
- bundle 自身的 `VERSION` 文件

## 8. 宿主如何消费 Bundle

宿主消费 Program Bundle 的高层步骤如下：

1. 读取 bundle 根目录下的 `manifest.json`
2. 根据 `frontend` 字段注册前端静态目录、入口页和 SPA fallback
3. 根据 `api.enabled` 决定是否为该 bundle 注册 API 路由能力，并读取 `api.adminBaseUrl`、`api.openidBaseUrl`、`api.oauth2BaseUrl`
4. 根据 `backend.entry` 找到 backend 可执行文件
5. 使用 `scripts.start` / `scripts.stop` / `scripts.deploy` 调用当前平台入口以管理 backend
6. 由宿主 Node HTTP server 或前置 nginx 按 `/admin/`、`/admin/api/`、`/api/openid/`、`/api/oauth2/` 规则注册前端与协议/API 路由
7. 旧 `/openid/`、`/oauth2/` 可作为兼容别名保留一个过渡版本

## 9. 最终 Checklist

- `manifest.json` 位于 bundle 根目录
- Program 外层文件名不包含 `program`
- Image 外层文件名使用 `image`，不使用 `image-bundle`
- 前端产物位于 `frontend/dist/`
- bundle 不包含 `frontend-gateway(.exe)`
- 后端主程序位于 `backend/identity-center(.exe)`
- bundle 根目录包含 `.env.example`
- bundle 根目录只包含当前平台的 `start` / `stop` / `deploy`
- `scripts/` 只包含当前平台 helper
- manifest 保留 `frontend` / `api` / `backend` 路由注册契约
- manifest 不包含 `frontend.nginxConfig`
- bundle 不预置空的 `data/`、`run/`
- bundle 不包含源码、测试、缓存和非运行期文件
