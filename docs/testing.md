# 测试说明

本文档说明本项目当前的测试入口、覆盖范围和发布前建议执行的命令。

## 测试入口

统一入口是：

```bash
scripts/test.sh all
```

也可以直接使用 Makefile：

```bash
make test
```

`make test` 会执行三类检查：

- Go 单元测试
- 前端类型检查和构建
- 文档公开检查

## 分项执行

只运行 Go 单元测试：

```bash
scripts/test.sh go
make go-test
```

只运行前端构建：

```bash
scripts/test.sh frontend
make build-frontend
```

只运行文档检查：

```bash
scripts/test.sh docs
make docs-test
```

## Go 单元测试

Go 测试命令：

```bash
cd go
GOCACHE="$PWD/.gocache" go test ./...
```

当前测试重点覆盖：

- 后端管理 API 和 IDP 回调行为
- Helper client/server 通信
- HMAC 签名校验
- DSM 用户名生成和身份映射
- 飞书 provider 的 URL、错误解析和字段校验

新增后端行为、Helper 安全逻辑、身份源解析或同步逻辑时，应补对应 Go 单元测试。

## 前端构建检查

前端检查命令：

```bash
cd frontend
npm run build
```

该命令会先执行 TypeScript 构建，再执行 Vite 构建。首次运行前需要安装依赖：

```bash
make frontend-install
```

新增页面、表单字段、API 类型或组件状态时，至少保证前端构建通过。

## 文档公开检查

文档检查命令：

```bash
scripts/test.sh docs
```

检查内容包括：

- 公开文档清单是否完整。
- 是否重新引用已删除的内部设计文档。
- 是否出现明显真实路径、私钥、token、内网地址或未脱敏配置。
- 是否把已中文化的公开文档标题改回英文旧标题。

文档公开范围见 [`publication-guidelines.md`](publication-guidelines.md)。

## 发布前检查

发布前建议执行：

```bash
make test
DSMPASS_VERSION=<version> make package-spk
```

然后按 [`release.md`](release.md) 完成 DSM 测试安装、升级、卸载和飞书登录验证。
