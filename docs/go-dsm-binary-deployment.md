# DSM 二进制部署

推荐普通用户优先使用 SPK。只有在需要自定义启动方式、调试或集成到已有运维体系时，才使用二进制部署。

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

## 安装到 DSM

上传与 NAS 架构匹配的 tar 包，然后解压到自定义目录，例如：

```bash
sudo mkdir -p /volume1/docker/dsmpass
sudo tar -xzf dsmpass-linux-amd64.tar.gz -C /volume1/docker/dsmpass
sudo chmod +x /volume1/docker/dsmpass/start-dsmpass.sh
```

创建运行目录：

```bash
sudo mkdir -p /run/dsmpass/locks
sudo mkdir -p /var/lib/dsmpass
sudo chmod 700 /run/dsmpass /run/dsmpass/locks /var/lib/dsmpass
```

## 启动

先配置强随机 Helper 密钥：

```bash
export DSMPASS_HELPER_HMAC_SECRET="$(openssl rand -hex 32)"
```

从包目录启动：

```bash
cd /volume1/docker/dsmpass
sudo ./start-dsmpass.sh
```

脚本会设置程序路径和基础启动变量：

```env
DSMPASS_GO_LISTEN=0.0.0.0:25000
DSMPASS_DATABASE_URL=sqlite:///volume1/docker/dsmpass/dsmpass.db
DSMPASS_FRONTEND_DIST_DIR=/volume1/docker/dsmpass/frontend/dist
DSMPASS_HELPER_SOCKET=/run/dsmpass/helper.sock
```

如果端口或路径不同，可以在启动前覆盖：

```bash
sudo DSMPASS_GO_LISTEN=0.0.0.0:28080 ./start-dsmpass.sh
```

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

- 二进制部署不会自动接入 DSM 套件中心的安装、升级和卸载流程。
- 管理后台端口、数据库路径、前端目录、Helper Socket 等启动参数来自环境变量，网页后台不会修改这些启动参数。
- 同步和账号开通会调用真实 DSM 能力，不是模拟模式。
- 生产环境不要公开管理后台，建议只在内网或可信反向代理后访问。
- 不要公开运行日志、数据库、`.env`、密钥或真实部署拓扑。
