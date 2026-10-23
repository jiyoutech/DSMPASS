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

### 账户写入与恢复的并发约束

- Helper 单实例锁先于启动恢复取得，防止第二个实例恢复第一个实例仍在使用的临时密码。登录、创建、启用、禁用和永久改密统一按账户锁、项目全局写锁的顺序执行；锁等待超时后返回忙碌，不执行排队中的修改。
- 直接读改写真实 shadow 时，还取得群晖 `/run/synosdk/lock/lock_pw` 的排他 `flock`。调用原生账户命令时只持有项目锁，由子进程取得群晖锁，避免重复加锁死锁。浏览器等待和 DSM HTTP 认证不持有全局或系统锁。
- 不再核对 DSM 版本文件、账户库或命令的组件指纹，也不按 DSM 版本或 CPU 架构设置白名单。真实 shadow 写入要求运行于 Linux，且系统锁文件已存在、可打开、为单链接普通文件；缺失或异常时拒绝写入，不自行创建 DSM 锁，也不降级为只使用项目锁。健康检查的 `shadow_login_supported` 反映这些运行条件，锁争用在实际写入时处理。
- 锁文件可用不等同于证明所有 DSM 写入方遵守相同锁协议。目前实机验证仍仅覆盖 DSM 7.3-81180 amd64；其他版本及 ARM64 不再被指纹门禁拦截，但未经过实机验证。DSM 升级可能改变内部锁协议，运行条件检查无法自动发现这种变化。
- 该锁只保护遵守相同协议的账户工具。直接写 shadow 的第三方脚本、未验证的改密工具、单独修改 SMB 凭据库不在保护范围内；原子重命名不能替代锁协议。
- 新日志在修改前持久化账户 UID、临时密码字段摘要和加密恢复资料。请求 ID 不可重用；完成回调与恢复扫描在同一账户锁内重读状态，已完成请求不会覆盖后续登录。
- 恢复只更换密码字段，保留最新密码期限、禁用标记及其他字段。发现外部新密码时保留新密码；UID 不符、账户消失或锁定密码无法识别时保留日志并拒绝新的临时登录。
- 回调、TTL、启动恢复和每两秒的后台扫描共用恢复逻辑；失败按 2 秒起步、最多 60 秒的间隔退避重试。租约到期本身不会解除账户保护。原生永久改密结果不明时禁止临时登录，不回滚 shadow，也不自动重试永久改密；检查 DSM 后显式执行新的全量同步修复。
- 升级前应让旧 Helper 完成未结束的登录恢复，再停止旧进程并启动新版。旧版本不遵守新单实例锁，不支持新旧 Helper 同时运行。

并发单元测试覆盖字段级恢复、禁用、账户身份变化、迟到回调、重复请求、锁超时、进程被杀后的恢复、跨进程写入、后台恢复重试及永久改密的结果不明状态。系统锁测试另外覆盖缺失路径不被创建、只读锁文件的互斥与元数据保持，以及异常文件拒绝处理：

```bash
cd go
go test -race ./internal/helperserver ./internal/backend ./internal/helperclient
```

在专用测试 NAS 上运行以下实机测试。测试需要 root、DSM、SMB Service，以及可用的 `openssl`、`smbclient` 和 `pdbedit`；会创建并清理临时账号，不访问用户共享文件。

```bash
cd go
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -tags dsm_integration \
  -o /tmp/dsmpass-helper.test ./internal/helperserver
# 将程序传到测试 NAS 的可执行临时目录后，以 root 执行：
# DSM 的 /tmp 通常挂载为 noexec，以下使用卷上的临时目录。
DSMPASS_DSM_INTEGRATION=1 /volume1/@tmp/dsmpass-helper.test \
  -test.run '^TestDSMReal(ShadowConcurrentRelayAndRecovery|AccountLockCoordination)$' -test.v
```

覆盖并发中继、浏览器临时密码登录、完成回调、启动恢复、TTL 恢复，以及登录期间用户主动改密；在登录前、中、后检查目标账号 SMB 凭据记录及全新 SMB 连接，并检查恢复后的 DSM 桌面会话；同时验证 shadow 内容、权限、所有者和扩展属性恢复一致。账户锁测试另外验证原生创建、改密、禁用、启用、删除以及 `SYNO.Core.User.set` 在系统锁持有期间等待，释放后才执行，并验证禁用期间恢复不会重新启用账户。

`go/scripts/dsm/check-dsm-temp-login.sh` 现仅接收上述测试二进制路径并运行同一组测试，不再接受用户名，也不再自行执行 `synouser --setpw` 和 `sed` 恢复 shadow。

### 同步模式回归

- 默认和 `mode=incremental` 保留已有密码；`mode=full` 才触发 DSM/SMB 永久改密。两个同步 POST 接口接收 JSON `{"mode":"incremental"}` 或 `{"mode":"full"}`，其他模式返回 400；均要求管理端认证。
- 后端和 Helper 都校验身份源、账号、用户名、有效映射、身份状态；测试覆盖其他身份源、未同步账号、手动修正用户名的同步账号、停用、重复映射、系统保留账号和正在进行的临时登录。
- 全量失败必须记录错误，重试复用身份源初始密码，日志不包含明文密码。旧 Helper 不支持密码修复时，开始同步前即报错。
- 单个账户开通或改密失败后继续处理其他账户，任务最终仍报告失败并保留各账户结果。同一轮密码重置使用同一份初始密码。多个有效身份源共享同一 DSM 账户时拒绝自动重置，避免不同初始密码相互覆盖；普通登录和增量同步不受这一密码归属限制。
- 永久改密先记录执行中状态，命令失败或进程中断保留待确认状态；重复同一请求不会再次执行未知结果的命令。只有新的显式全量请求可重新尝试。原生命令返回成功记为命令完成，不等同于已验证客户端重新登录。
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
