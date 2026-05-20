# DSM SPK 打包与安装

本项目可以构建兼容 DSM 7 的 SPK 套件，支持 x86_64 和 aarch64 Synology 机型。

## 打包

在项目根目录执行：

```bash
DSMPASS_VERSION=0.8.22 make package-spk
```

产物输出到：

```text
go/dist/dsm/DSMPASS-<version>-linux-amd64.spk
go/dist/dsm/DSMPASS-<version>-linux-arm64.spk
go/dist/dsm/SHA256SUMS
```

`linux-amd64` 用于 Intel/AMD Synology 机型，`linux-arm64` 用于 ARMv8/aarch64 机型。

## 套件内容

SPK 包含 DSM 要求的基础结构：

```text
INFO
package.tgz
scripts/start-stop-status
scripts/postinst
scripts/postupgrade
scripts/preupgrade
scripts/preuninst
scripts/postuninst
conf/privilege
LICENSE
PACKAGE_ICON.PNG
PACKAGE_ICON_256.PNG
```

`package.tgz` 里包含：

```text
bin/dsmpass-backend
bin/dsmpass-helper
frontend/dist/
start-dsmpass.sh
VERSION
```

套件启动后会运行后端进程和 Helper 进程。后端负责管理后台、API、同步和 IDP 回调；DSM 本地账号、群组和登录相关的高权限操作由 Helper 处理。

## 安装向导

SPK 安装向导会要求填写管理后台 HTTPS 端口。

规则：

- 管理后台端口必须在 `1025` 到 `65535` 之间。
- 端口不能被其他 DSM 服务占用。
- 管理后台端口安装后不在网页后台里修改。
- IDP 协议和 IDP 端口在首次进入网页后台时配置。
- 首次网页配置默认建议 IDP 端口为 `26000`，与默认管理后台端口 `25000` 分开。

管理后台默认使用 HTTPS。IDP 入口是独立 listener，使用 HTTP 还是 HTTPS 取决于系统设置里的 IDP 协议。

推荐部署方式：

```text
https://nas.example.com:25000/                 管理后台，仅内网开放
https://nas.example.com:26000/idp/<id>/launch  IDP 用户登录入口，可按需对外映射
```

修改 IDP 协议或 IDP 端口时，只会重启 IDP listener，管理后台 listener 不会跟着重启。

系统会根据以下字段生成 IDP 地址、DSM 地址和 DSM Auth API 地址：

- IDP 协议
- 访问 IP / 域名
- IDP 入口端口

这些派生地址会在网页初始化向导中只读展示，避免 IDP 协议和回调地址协议不一致。

## 运行数据

安装脚本会创建并保留：

```text
/var/packages/DSMPASS/var/dsmpass.env
/var/packages/DSMPASS/var/data/
/var/packages/DSMPASS/var/run/
```

`dsmpass.env` 首次安装时会生成 `DSMPASS_HELPER_HMAC_SECRET`。升级时复用现有文件，不重新生成密钥。

常见覆盖项：

```sh
DSMPASS_GO_LISTEN=0.0.0.0:25000
DSMPASS_ACCESS_HOST=127.0.0.1
DSMPASS_TLS_ENABLED=1
```

编辑环境文件后，可以在 DSM 套件中心重启套件，也可以执行：

```bash
sudo /var/packages/DSMPASS/scripts/start-stop-status restart
```

日志路径：

```text
/var/packages/DSMPASS/var/dsmpass.log
```

日志属于敏感运行数据。公开 issue 或文档前必须脱敏。

## 升级

升级会保留：

- 运行数据库
- 运行配置
- 身份源凭据
- 日志
- TLS 文件
- Helper HMAC 密钥

如果旧环境文件没有 `DSMPASS_TLS_ENABLED`，升级脚本会追加 `DSMPASS_TLS_ENABLED=1`。如果已显式设置为 `0`，升级会保留该选择。

## 卸载

卸载向导会询问是否保留套件数据。

计划重装或手动升级时，选择保留套件数据。

只有在确认要删除本地配置、同步数据、日志和 TLS 文件时，才选择删除套件数据。

Helper sudo 规则属于系统级提权配置。无论卸载时是否保留套件数据，卸载脚本都会尝试删除 `/etc/sudoers.d/DSMPASS-helper`。

卸载后建议 SSH 到 DSM 确认：

```bash
sudo -i
ls -l /etc/sudoers.d/DSMPASS-helper
```

如果仍然存在，手动删除：

```bash
sudo rm -f /etc/sudoers.d/DSMPASS-helper
```

## 排障

端口错误：

- 只使用 `1025` 到 `65535` 范围内的端口。
- 管理后台是 HTTPS 时，不要把同一个端口复用给 HTTP IDP listener。
- 保存时报 `port is already in use` 时，换一个 IDP 端口后重新保存。

协议未变化：

- 确认修改的是「IDP 协议」，不是管理后台协议。
- 确认身份源页面展示的 IDP 地址已经使用新的协议和端口。
- 查看 `/var/packages/DSMPASS/var/dsmpass.log`，确认 IDP listener 已按新配置启动。

DSM 跳转端口：

- HTTP 默认派生 DSM `5000`。
- HTTPS 默认派生 DSM `5001`。
- 如果已经配置自定义 DSM 端口，系统会保留自定义端口。

Helper 权限或 socket 错误：

后台提示 `Helper 无法执行 DSM 用户和群组命令` 时，需要通过 SSH 给 Helper 安装 sudo 规则。原因是后端不直接以 root 运行，而 DSM 用户、群组命令需要 root 权限。

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

执行成功后会生成 `/etc/sudoers.d/DSMPASS-helper`。回到管理后台点击「重启并检查 Helper」；继续失败时查看 `/var/packages/DSMPASS/var/dsmpass.log`。
