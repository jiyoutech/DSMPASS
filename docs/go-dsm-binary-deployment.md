# DSM 二进制部署

当前安全修复版使用 SPK 初始化套件账号及受保护的 Helper。二进制 tar 包保留为构建和调试产物，不再支持旧版从任意目录直接以 root 启动 Helper 的部署方式。

## 构建产物

二进制包输出为：

```text
go/dist/dsm/dsmpass-linux-amd64.tar.gz
go/dist/dsm/dsmpass-linux-arm64.tar.gz
```

每个包包含：

```text
bin/dsmpass-backend
bin/dsmpass-helper
frontend/dist/
start-dsmpass.sh
VERSION
```

`amd64` 用于 Intel/AMD Synology 机型，`arm64` 用于 ARMv8/aarch64 机型。

## 构建

在项目根目录执行：

```bash
make package-dsm
```

如果需要指定版本：

```bash
DSMPASS_VERSION=0.8.7 make package-dsm
```

## 安装与启动边界

安装和升级请遵循 [SPK 权限与迁移说明](dsm-spk-package.md)。首次初始化必须由管理员使用可信安装包提供的安装器，创建固定的 `DSMPASS` 套件账号及 root 专用程序、配置和恢复目录。

受保护的 Helper 使用以下固定入口：

```text
/usr/local/libexec/dsmpass/dsmpass-helper
/usr/local/libexec/dsmpass/helper-control.sh
/etc/dsmpass/helper.json
/run/dsmpass/helper.sock
```

Helper 不再读取调用者的环境变量来选择程序路径、数据库、DSM 端点或恢复资料目录。普通套件用户只能调用固定控制操作；更新 root 程序必须通过 [发行签名校验](helper-upgrades.md)，不能用任意套件文件替换。

后端以 `DSMPASS` 普通账号运行。不要以 root 执行位于套件用户可写目录中的 `start-dsmpass.sh`，也不要恢复旧版 `SETENV` sudo 规则。独立 tar 部署尚未提供与此边界等价的自动安装流程；仅解压 tar 包或设置环境变量不能完成受保护 Helper 的初始化。

## 网页配置

后端和 Helper 启动后，打开：

```text
https://DSM-IP:25000/
```

首次进入会初始化后台账号，然后进入系统配置。配置项含义见 [`spk-feishu-setup.md`](spk-feishu-setup.md)。

系统设置里填写：

- IDP 协议
- 访问 IP / 域名
- IDP 入口端口
- DSM 登录模式
- DSM TLS 校验策略

身份源里创建飞书配置：

- 身份源名称
- 飞书 App ID
- 飞书 App Secret
- DSM 初始密码
- 登录开关
- 同步开关
- 定时同步间隔
- 缺失用户处理策略

## 注意事项

- tar 包不包含独立权限初始化、升级和卸载流程；当前部署流程以 SPK 为准。
- 后端环境配置不能覆盖 root Helper 的固定路径和受保护配置。
- 同步和账号开通会调用真实 DSM 能力，不是模拟模式。
- 生产环境不要公开管理后台，建议只在内网或可信反向代理后访问。
- 不要公开运行日志、数据库、`.env`、密钥或真实部署拓扑。
