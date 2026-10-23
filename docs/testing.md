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

### 临时登录与 SMB 密码隔离

浏览器直登和服务端中继只临时替换目标用户的 `/etc/shadow` 密码字段，不再调用 `synouser --setpw`。账号创建和用户主动改密仍走 DSM 原有流程。

- 使用 DSM 自带的 `/usr/bin/openssl passwd -6 -stdin` 生成 SHA-512 crypt 哈希，密码通过标准输入传递。
- 先加密保存原 shadow 行、临时密码及预期临时行摘要，再进行条件检查和原子替换；保留密码期限字段、文件权限、所有者及扩展属性。
- 完成回调、TTL 到期和启动恢复使用同一套条件恢复逻辑；检测到外部改密时保留外部变更。
- 拒绝锁定账号和空密码账号；OpenSSL 缺失、输出异常或日志写入失败时终止登录，不回退到会修改 SMB 的改密命令。
- 临时窗口内 DSM/SSH 的原密码认证仍可能受影响。该方案隔离的是 SMB 凭据，并不提供所有认证服务无感切换的保证。
- 此改动不会自动修复旧版本已经造成的 SMB 密码不一致；受影响账号需要通过 DSM 重新设置密码。

在专用测试 NAS 上运行以下实机测试。测试需要 root、DSM、SMB Service，以及可用的 `openssl`、`smbclient` 和 `pdbedit`；会创建并清理临时账号，不访问用户共享文件。

```bash
cd go
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -tags dsm_integration \
  -o /tmp/dsmpass-helper.test ./internal/helperserver
# 将程序传到测试 NAS 的可执行临时目录后，以 root 执行：
# DSM 的 /tmp 通常挂载为 noexec，以下使用卷上的临时目录。
DSMPASS_DSM_INTEGRATION=1 /volume1/@tmp/dsmpass-helper.test \
  -test.run '^TestDSMRealShadowConcurrentRelayAndRecovery$' -test.v
```

ARM NAS 构建时将 `GOARCH` 改为 `arm64`。覆盖并发中继、浏览器临时密码登录、完成回调、启动恢复、TTL 恢复，以及登录期间用户主动改密；在登录前、中、后检查目标账号 SMB 凭据记录及全新 SMB 连接，并检查恢复后的 DSM 桌面会话；同时验证 shadow 内容、权限、所有者和扩展属性恢复一致。

### 同步模式回归

- 默认和 `mode=incremental` 保留已有密码；`mode=full` 才触发 DSM/SMB 永久改密。两个同步 POST 接口接收 JSON `{"mode":"incremental"}` 或 `{"mode":"full"}`，其他模式返回 400；均要求管理端认证。
- 后端和 Helper 都校验身份源、账号、用户名、有效映射、身份状态和托管标记；测试覆盖其他身份源、手动关联、停用、重复映射、系统保留账号和正在进行的临时登录。
- 全量失败必须记录错误，重试复用身份源初始密码，日志不包含明文密码。旧 Helper 不支持密码修复时，开始同步前即报错。
- 上述 DSM 实机集成测试还会在隔离账号上复现旧版密码不一致，调用全量同步使用的 Helper 改密操作，验证 DSM 和全新 SMB 连接均接受统一密码；之后再次临时登录仍保留该密码，另一账号不受改密影响。

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
