# DSM Pass

DSM Pass 是一个面向 Synology DSM 的企业身份登录网关。它把外部身份源登录、目录同步和 DSM 本地账号体系连接起来，让用户可以通过企业身份源进入 DSM。

当前主实现是 **Go 后端 + Go DSM Helper + React 管理后台**。Python 旧实现没有迁移到这个开源化目录里，避免主线混乱。

> 项目目前处于 **pre-1.0 / alpha** 阶段。核心流程已经可用，但 DSM 登录中继、临时密码、Cookie 写入和 helper 权限边界都属于高风险系统集成能力。生产使用前请先在测试 NAS 上验证安装、升级、卸载、端口映射和恢复流程。

## 当前状态

项目处于 pre-1.0 阶段，已经具备核心流程，但发布生产版本前仍建议完整审计安全配置、部署权限和日志策略。

当前支持：

- 飞书 OAuth 登录
- 飞书通讯录用户、部门、成员同步
- DSM 用户、部门映射、成员关系开通
- 用户级禁止飞书登录
- 身份源级登录/同步独立开关
- 身份源级定时同步
- 登录审计和同步日志
- DSM 登录 Cookie 中继
- 首次启动后台账号初始化
- HTTPS 默认启动，自签证书自动生成
- DSM SPK 安装包，支持 x86_64 和 aarch64
- 管理后台端口在 SPK 安装时配置
- IDP 入口协议和端口可在后台配置
- IDP 路由独立热重启，管理后台不跟随重启

## 目录结构

```text
go/          Go 后端、DSM Helper、数据库、DSM 打包脚本
frontend/    React + Ant Design 管理后台
docs/        架构、部署和 provider 扩展文档
```

## 架构边界

后端不直接执行 DSM 特权操作。DSM 本地账号、群组、临时密码中继等高权限动作都由 Helper 执行。

```text
Browser
  -> Go 后端
    -> Unix Socket + HMAC
      -> DSM Helper
        -> synouser / synogroup / DSM Auth API / /etc/shadow
```

Helper 使用：

- Unix Socket 本地通信
- HMAC 请求签名
- 时间戳防重放
- 用户级锁和 shadow 全局锁
- 临时密码中继 journal
- 启动恢复未完成的 shadow 操作

## 安全默认值

开源化目录已经调整为更适合生产的默认值：

- 后台认证默认开启
- HTTPS 默认开启
- 登录诊断日志默认关闭
- `DSMPASS_HELPER_HMAC_SECRET` 必须显式配置，否则服务拒绝启动
- 诊断日志会脱敏密码、token、SID、cookie、签名和 shadow 行

生产环境不要开启明文排障日志。即使日志已经脱敏，也应当视为敏感运行数据。

## 快速开始

安装前端依赖并构建：

```bash
cd frontend
npm ci
npm run build
```

运行 Go 测试：

```bash
cd ../go
GOCACHE="$PWD/.gocache" go test ./...
```

或者在项目根目录运行：

```bash
make test
```

## DSM SPK 打包

```bash
DSMPASS_VERSION=0.8.6 make package-spk
```

输出文件：

```text
go/dist/dsm/DSMPASS-0.8.6-linux-amd64.spk
go/dist/dsm/DSMPASS-0.8.6-linux-arm64.spk
go/dist/dsm/SHA256SUMS
```

`linux-amd64` 用于 Intel/AMD Synology 机型，`linux-arm64` 用于 ARMv8/aarch64 机型。

安装 SPK 时可以在向导里配置管理后台端口。端口必须在 `1025-65535` 范围内且未被占用。管理后台默认 HTTPS；IDP 入口协议和端口在管理后台系统配置里单独设置。

从安装 SPK 到配置飞书登录和通讯录同步的完整步骤见 [`docs/spk-feishu-setup.md`](docs/spk-feishu-setup.md)。更多安装、升级和排障细节见 [`docs/dsm-spk-package.md`](docs/dsm-spk-package.md)。

### Helper 权限初始化

如果后台提示：

```text
Helper 无法执行 DSM 用户和群组命令
dial unix .../helper.sock: connect: no such file or directory
```

通常表示 Helper 没有成功启动，或没有拿到执行 DSM 用户、群组命令的权限。DSM Pass 的后端不直接以 root 运行；真正需要改 DSM 用户和群组时，由 Helper 通过本机 sudo 规则提权执行。

处理步骤：

1. 打开 DSM 的 SSH 服务。
2. 用 DSM 管理员账号 SSH 登录 NAS。
3. 切换到 root。
4. 执行 Helper sudo 规则安装脚本。
5. 回到管理后台点击「重启并检查 Helper」。
6. 检查 `helper.sock` 是否已经创建。

```bash
ssh 管理员账号@NAS_IP
sudo -i
/var/packages/DSMPASS/target/setup-helper-sudo.sh
# 回到管理后台点击「重启并检查 Helper」后，再检查 socket 是否生成
ls -l /var/packages/DSMPASS/var/run/helper.sock
```

`ls` 用来确认 Helper 的 Unix Socket 是否已经创建。正常结果应显示 `helper.sock`，并且权限列以 `s` 开头，例如：

```text
srw-rw---- 1 DSMPASS DSMPASS 0 ... /var/packages/DSMPASS/var/run/helper.sock
```

用户和用户组可能因 DSM 环境略有不同，重点看文件存在、第一列以 `s` 开头。如果显示 `No such file or directory`，说明 Helper 还没有成功启动，需要先在管理后台点击「重启并检查 Helper」并查看日志。

如果 `setup-helper-sudo.sh` 成功，会写入 `/etc/sudoers.d/DSMPASS-helper`，允许 DSMPASS 套件用户免密码执行 Helper 和 Helper 管理脚本。完成后重点确认提权脚本执行成功，并在管理后台点击「重启并检查 Helper」。

## DSM 二进制部署

如果不使用 SPK，可以构建 DSM tar 包：

```bash
make package-dsm
```

输出文件：

```text
go/dist/dsm/dsmpass-linux-amd64.tar.gz
go/dist/dsm/dsmpass-linux-arm64.tar.gz
```

## DSM 启动

解压后设置必要环境变量：

```bash
export DSMPASS_ACCESS_HOST=nas.example.com
export DSMPASS_HELPER_HMAC_SECRET="$(openssl rand -hex 32)"
./start-dsmpass.sh
```

访问后台：

```text
https://nas.example.com:25000/
```

首次打开会进入后台账号初始化和系统配置流程。

## 管理后台和 IDP 入口

管理后台和 IDP 入口是两个独立的对外面：

- 管理后台：用于配置身份源、同步规则和审计，端口在 SPK 安装向导或环境变量 `DSMPASS_GO_LISTEN` 中配置。
- IDP 入口：用户访问 `/idp/<source>/launch` 和 OAuth callback 的入口，协议和端口在后台系统配置中配置。

推荐生产部署方式是管理后台只在内网开放，IDP 入口按需要映射到公网或反向代理。修改 IDP 协议或 IDP 端口后，服务只热重启 IDP listener，不重启管理后台。

DSM 默认端口按 IDP/DSM 协议自动派生：

- HTTP -> DSM `5000`
- HTTPS -> DSM `5001`

## 关键配置

复制环境变量样例：

```bash
cp .env.example .env
```

重点变量：

- `DSMPASS_ACCESS_HOST`：用户访问后台/IDP 的 IP 或域名
- `DSMPASS_HELPER_HMAC_SECRET`：后端与 Helper 共用的强随机密钥
- `DSMPASS_GO_LISTEN`：管理后台监听地址，默认 `0.0.0.0:25000`
- `DSMPASS_TLS_ENABLED`：管理后台是否启用 HTTPS，SPK 默认启用
- `DSMPASS_DSM_REDIRECT_URL`：登录成功后跳转的 DSM 地址
- `DSMPASS_DSM_LOGIN_API`：DSM Auth API 地址
- `DSMPASS_LOGIN_DIAGNOSTICS`：诊断日志开关，生产保持 `false`

## 身份源扩展

前端不会硬编码身份源类型。新建身份源时，前端从后端接口获取 provider 类型：

```text
GET /api/admin/provider-types
```

新增 provider 时，应当在后端 provider registry 中声明能力，再补齐登录、目录读取和配置字段。

## 发布检查

发布前至少确认：

1. `make test` 通过
2. `make package-spk` 通过
3. 没有提交 `.env`、数据库、日志、TLS 私钥、token、SID、临时密码或 shadow 内容
4. 生产环境配置了强随机 `DSMPASS_HELPER_HMAC_SECRET`
5. 生产环境关闭 `DSMPASS_LOGIN_DIAGNOSTICS`
6. 浏览器访问协议、DSM 跳转地址和 Cookie Secure 设置一致
7. 在 DSM 测试机上验证首次安装、升级、卸载保留数据、卸载删除数据、IDP 端口切换和协议切换

## 许可证

MIT。见 `LICENSE`。
