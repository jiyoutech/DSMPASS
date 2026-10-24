# DSM SPK 打包与安装

本项目可以构建兼容 DSM 7 的 SPK 套件，支持 x86_64 和 ARMv8 Synology 机型。

## 打包

在项目根目录执行：

```bash
DSMPASS_VERSION=0.8.27 make package-spk
```

默认允许创建多个身份源。需要发行仅允许一个身份源的 SPK 时，在打包命令中关闭该能力：

```bash
DSMPASS_VERSION=0.8.27 DSMPASS_ALLOW_MULTIPLE_IDENTITY_SOURCES=0 make package-spk
```

`DSMPASS_ALLOW_MULTIPLE_IDENTITY_SOURCES` 支持 `1`、`0`、`true`、`false`，默认值为 `1`。该值会固化进 SPK 后端二进制，安装后不能通过 `dsmpass.env` 修改。关闭后允许创建第一个身份源；已有身份源时再次创建会返回冲突。升级到关闭该能力的 SPK 不会删除或停用已有身份源，只会阻止继续新建。

产物输出到：

```text
go/dist/dsm/DSMPASS-<version>-linux-amd64.spk
go/dist/dsm/DSMPASS-<version>-linux-arm64.spk
go/dist/dsm/SHA256SUMS
```

`linux-amd64` 用于 Intel/AMD Synology 机型，SPK `INFO` 使用 `arch="x86_64"`；`linux-arm64` 用于 ARMv8/aarch64 机型，SPK `INFO` 使用群晖识别的 `arch="armv8"`。Go 二进制仍然以 `GOARCH=arm64` 编译，产物文件名也继续使用 `linux-arm64`。

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

特权 Helper 使用独立的 root 配置 `/etc/dsmpass/helper.json`，程序与控制入口位于 `/usr/local/libexec/dsmpass/`，日志和恢复资料位于 `/var/lib/dsmpass/`。这些路径及其父目录必须由 root 控制，不能由套件用户写入，也不接受符号链接。Helper 不执行套件 env 文件，不接受调用方指定程序路径，后台数据库也不能覆盖其特权配置。

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

无论是否保留数据，卸载前都会通过受保护控制器删除 Helper 程序、控制脚本、socket、PID 记录和 `/etc/sudoers.d/DSMPASS-helper`。这一步在套件账号仍然存在时执行，避免卸载后低权限脚本无法清理 root 文件。

选择保留数据时，同时保留 root 私有的 `/etc/dsmpass` 配置和 `/var/lib/dsmpass` 授权、日志及恢复资料；选择删除数据时，控制器在确认没有未完成恢复后自动清理这两个固定目录。`/run/dsmpass` 中少量空的进程锁文件保留到重启，防止排队控制进程绕过同一把锁，不包含密码或可执行程序。

升级和卸载前会停止 Helper 并完成待恢复密码。若恢复失败，操作取消并尝试重新启动 Helper，使恢复循环与其他账号服务继续运行，错误会明确提示处理恢复后重试。无法恢复的密码仍会阻止卸载，不会通过删除记录掩盖问题。路径权限异常、磁盘错误或重启失败仍需管理员检查日志；中途系统断电可能需要重新初始化受保护 Helper。

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

后台提示 Helper 尚未就绪时，先点击“重启并检查 Helper”，查看是否为版本不匹配、连接失败或原生命令不可执行。首次安装、从旧控制器迁移或安装自行编译的未签名包时，需要管理员执行以下初始化命令；后端本身不以 root 运行。

```bash
ssh 管理员账号@NAS_IP
sudo -i
/var/packages/DSMPASS/target/setup-helper-sudo.sh
# 回到管理后台点击「重启并检查 Helper」后，再检查 socket 是否生成
ls -l /run/dsmpass/helper.sock
```

`ls` 用来确认 Helper 的 Unix Socket 是否已经创建。正常结果应显示 `helper.sock`，并且权限列以 `s` 开头，例如：

```text
srw-rw---- 1 root DSMPASS 0 ... /run/dsmpass/helper.sock
```

用户和用户组可能因 DSM 环境略有不同，重点看文件存在、第一列以 `s` 开头。如果显示 `No such file or directory`，说明 Helper 还没有成功启动，需要先在管理后台点击「重启并检查 Helper」并查看日志。

执行成功后会安装 root 保护的程序、配置和 `/etc/sudoers.d/DSMPASS-helper`。sudo 只允许固定控制入口的 start、stop、restart、status，不允许保留调用方环境，也不允许直接运行套件目录中的 Helper。socket 还会校验连接方的本机 UID。继续失败时由 root 查看 `/var/lib/dsmpass/helper.log`。

有 `visudo` 时先验证候选规则；DSM 未提供 `visudo` 时，安装器原子写入固定规则，再使用系统 `sudo -l` 解析并检查指定控制命令的授权，不执行该命令。解析失败会恢复原规则或移除新规则，并报告失败；不会跳过规则检查。

首次迁移前先让旧 Helper 完成密码恢复并停止它，再从可信 SPK 安装执行初始化脚本。完成这一次管理员初始化后，带有效发行签名的套件会自动更新受保护 Helper，后续升级无需反复手工运行脚本。未签名源码包和显式降级仍需管理员安装，详见 [Helper 自动升级](helper-upgrades.md)。安装器检查受保护目录的实例锁与恢复日志，发现运行实例或未完成恢复时拒绝覆盖；首次迁移也需确认旧套件目录中的实例已停止且密码已恢复。

初始化会一次性自动批准已有有效同步映射对应的普通账号和自定义群组，不需要逐个执行授权命令；管理员和系统账号仍禁止。完成标记保存在 root 授权文件中，后续升级不会重新批准已撤销的账号。此操作不改密码；首次迁移会信任当前映射数据，详见[账号授权说明](helper-account-authorization.md)。如果数据库尚未初始化或读取失败，应先启动后台完成数据库初始化，再重试脚本。

Helper 默认从 DSM 的 root 所有配置 `/usr/syno/etc/www/DSM.json` 自动读取认证协议和端口，每次认证重新读取；在 DSM 登录门户修改端口后无需编辑 Helper 文件或重启。已有默认 `https://127.0.0.1:5001/webapi/entry.cgi` 自动采用此模式，新的配置写为 `dsm_login_api: "auto"`。健康检查返回实际认证地址及端口读取错误。

自动发现始终连接回环地址，不使用后台可写的访问地址、域名或环境变量。若 DSM 配置文件不存在、权限不安全或内容无效，会明确报错，不猜测端口。管理员已有的非默认回环 API 配置保留；确需覆盖时可以由 root 编辑 `/etc/dsmpass/helper.json`。Helper 签名密钥等特权设置仍只能由 root 修改。
