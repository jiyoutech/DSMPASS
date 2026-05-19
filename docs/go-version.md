# Go 主线说明

当前开源主线位于 `go/`，后端使用 Gin，数据层使用 SQLite 和 sqlc 风格的查询代码，前端构建产物由同一个后端进程提供静态服务。

## 技术栈

- Gin：HTTP 路由和 API。
- SQLite：本地运行数据库。
- sqlc 风格数据访问：schema 和 query 位于 `go/internal/db/`。
- Unix Socket：后端与 Helper 本机通信。
- HMAC 签名：保护后端到 Helper 的本机请求。
- React + Ant Design：管理后台。

## 目录结构

```text
go/
  cmd/backend/          后端入口
  cmd/helper/           Helper 入口
  internal/backend/     路由、前端静态服务、设置、同步、IDP 回调
  internal/config/      环境变量和运行配置
  internal/db/          schema、query 和 Go 数据访问代码
  internal/helperclient 后端到 Helper 的 Unix Socket 客户端
  internal/helperserver Helper 本机服务
  internal/identity/    身份映射和 DSM 名称分配
  internal/provider/    身份源 provider
  internal/syncsvc/     通讯录同步
  internal/signing/     HMAC 签名
  sqlc.yaml             sqlc 配置
```

## 本地运行后端

先构建前端：

```bash
cd frontend
npm ci
npm run build
```

运行后端测试：

```bash
cd ../go
GOCACHE="$PWD/.gocache" go test ./...
```

运行后端：

```bash
GOCACHE="$PWD/.gocache" go run ./cmd/backend
```

默认监听：

```text
0.0.0.0:25000
```

后端提供：

```text
/                    管理后台
/assets/*            前端静态资源
/api/admin/settings  系统设置
/api/admin/providers 身份源
/api/admin/helper/status
/api/admin/audit/logins
/api/admin/dsm-accounts
/api/admin/dsm-groups
/api/admin/group-members
/api/sync/:provider/dry-run
/api/sync/:provider/apply
/idp/<source>/launch
/idp/<source>/callback
/healthz
/readyz
```

## 本地运行 Helper

开发环境可以单独启动 Helper：

```bash
cd go
DSMPASS_HELPER_HMAC_SECRET=change-this-helper-secret \
GOCACHE="$PWD/.gocache" \
go run ./cmd/helper
```

后端使用 socket 模式连接 Helper：

```bash
DSMPASS_RELAY_MODE=socket \
DSMPASS_HELPER_HMAC_SECRET=change-this-helper-secret \
GOCACHE="$PWD/.gocache" \
go run ./cmd/backend
```

示例密钥只用于本地开发，不要用于生产环境。

## 数据库代码

schema 和查询文件：

```text
go/internal/db/schema.sql
go/internal/db/query.sql
```

修改查询后重新生成：

```bash
cd go
sqlc generate
```

仓库中保留了生成后的 Go 文件，方便没有安装 sqlc 的环境也能直接构建。

## 当前能力

已实现：

- Gin 后端服务。
- 后端进程提供管理后台静态资源。
- SQLite 持久化运行设置。
- 运行设置启动加载，保存后即时应用。
- 飞书 provider 注册、OAuth 回调和通讯录同步。
- 用户、群组、成员关系同步。
- 身份映射、DSM 账号、DSM 群组和成员关系管理。
- 管理后台使用的列表、开通和审计 API。
- 登录审计日志。
- Helper 健康检查和签名校验。
- 通过 Helper 执行 DSM 账号、群组和成员关系开通。

注意：

- 飞书接口和权限需要用真实飞书应用验证。
- 新增 provider 时先看 [`provider-development.md`](provider-development.md)。
- 生产部署优先使用 SPK，见 [`spk-feishu-setup.md`](spk-feishu-setup.md)。
