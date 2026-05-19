# DSM Pass

DSM Pass 是面向 Synology DSM 的企业身份登录网关。它把飞书 OAuth 登录、通讯录同步和 DSM 本地账号体系连接起来，让用户可以使用企业身份进入 DSM。

当前主线实现为 **Go 后端 + Go DSM Helper + React 管理后台**。

> 项目仍处于 **pre-1.0 / alpha** 阶段。核心流程已经可用，但 DSM 登录中继、临时密码、Cookie 写入和 Helper 提权都属于高风险系统集成能力。生产使用前，请先在测试 NAS 上完整验证安装、升级、卸载、端口映射、登录和恢复流程。

## 功能概览

| 能力 | 状态 |
| --- | --- |
| 飞书 OAuth 登录 DSM | 已支持 |
| 飞书通讯录用户、部门、成员同步 | 已支持 |
| DSM 用户、部门组和成员关系自动开通 | 已支持 |
| 用户级禁止登录 | 已支持 |
| 身份源级登录/同步开关 | 已支持 |
| 身份源级定时同步 | 已支持 |
| 登录审计和同步日志 | 已支持 |
| DSM SPK 安装包 | 已支持 x86_64 / aarch64 |
| 管理后台 HTTPS | 默认启用，自签证书自动生成 |
| IDP 入口协议和端口 | 后台可配置，支持热重启 |

## 快速安装

### 1. 下载 SPK

从 [GitHub Releases](https://github.com/Zhoany/DSMPASS/releases) 下载与 NAS 架构匹配的 SPK：

| NAS 架构 | 文件 |
| --- | --- |
| Intel / AMD | `DSMPASS-<version>-linux-amd64.spk` |
| ARMv8 / aarch64 | `DSMPASS-<version>-linux-arm64.spk` |

也可以本地打包：

```bash
DSMPASS_VERSION=0.8.15 make package-spk
```

输出文件：

```text
go/dist/dsm/DSMPASS-0.8.15-linux-amd64.spk
go/dist/dsm/DSMPASS-0.8.15-linux-arm64.spk
go/dist/dsm/SHA256SUMS
```

### 2. 安装到 DSM

1. 打开 DSM「套件中心」。
2. 在「设置」中允许手动安装第三方套件。
3. 点击「手动安装」，上传对应架构的 `.spk` 文件。
4. 在安装向导中填写管理后台端口，例如 `25000`。
5. 完成安装并启动套件。
6. 用浏览器访问管理后台：

```text
https://<NAS-IP-or-domain>:25000/
```

管理后台默认使用 HTTPS 和自签证书。测试环境可以在浏览器中继续访问；生产环境建议配置可信证书或放在可信反向代理后面。

### 3. 初始化后台

首次进入管理后台后，按页面流程完成：

| 步骤 | 配置 |
| --- | --- |
| 后台账号 | 初始化管理员账号和密码 |
| 访问主机 | 填写用户能访问的 NAS IP 或域名，例如 `nas.example.com` |
| IDP 协议 | 生产建议 `HTTPS` |
| IDP 入口端口 | 建议 `26000`，必须未被占用 |
| DSM 地址 | 确认自动识别结果正确 |
| DSM Auth API | 确认自动识别结果正确 |

推荐地址规划：

```text
https://nas.example.com:25000/                       DSM Pass 管理后台
https://nas.example.com:26000/idp/<source>/launch    用户飞书登录入口
https://nas.example.com:5001/                        DSM HTTPS
```

## 飞书配置

### 1. 创建应用

1. 在飞书开放平台创建「企业自建应用」。
2. 在「凭证与基础信息」中获取 `App ID` 和 `App Secret`。
3. 在 DSM Pass 新建「飞书」身份源，填入 `App ID`、`App Secret` 和 DSM 初始密码。
4. 保存后进入身份源详情页，记录页面显示的 `Launch` 和 `Callback` 地址。

### 2. 填写地址

回到飞书开放平台：

| 飞书配置项 | 填写内容 |
| --- | --- |
| 网页应用 / 桌面端主页 | DSM Pass 身份源详情页的 `Launch` 地址 |
| OAuth 重定向 URL / 回调地址 | DSM Pass 身份源详情页的 `Callback` 地址 |

如果后续修改 DSM Pass 的 IDP 协议、访问域名或 IDP 端口，需要同步更新飞书里的主页地址和回调地址，并重新发布应用。

### 3. 开通权限

DSM Pass 同步飞书通讯录时需要读取用户、部门、用户所属部门和部门成员关系。建议按下面配置：

| 类型 | 权限 | 用途 |
| --- | --- | --- |
| 必需 | `contact:contact.base:readonly` | 读取通讯录基础数据 |
| 必需 | `contact:user.base:readonly` | 读取用户姓名等基础信息 |
| 必需 | `contact:user.department:readonly` | 读取用户所属部门，保证多部门用户同步准确 |
| 必需 | `contact:department.base:readonly` | 读取部门名称等基础信息 |
| 必需 | `contact:department.organize:readonly` | 读取部门上下级组织架构 |
| 建议 | `contact:user.employee_id:readonly` | 读取用户 ID 相关字段，便于后续扩展和排查 |
| 按需 | `contact:user.email:readonly` | 需要同步邮箱字段时开启 |
| 按需 | `contact:user.phone:readonly` | 需要同步手机号字段时开启 |

`contact:user.department:readonly` 很关键。缺少它时，多部门用户可能无法和飞书权限保持一致。邮箱和手机号权限只影响字段是否返回，不影响基础登录和部门同步。

### 4. 设置范围并发布

飞书里有两个范围要分别设置：

| 范围 | 作用 | 配置建议 |
| --- | --- | --- |
| 通讯录权限范围 | 决定应用 API 能读取哪些部门和用户 | 覆盖需要同步到 DSM 的部门和用户 |
| 应用可用范围 / 用户范围 | 决定哪些用户能看到和使用飞书应用 | 覆盖需要通过 DSM Pass 登录 DSM 的用户 |

完成权限和范围配置后，创建版本并发布应用。部分通讯录权限需要企业管理员审核，审核通过后才会生效。

### 5. 同步验证

回到 DSM Pass 身份源详情页，点击「同步」。同步完成后检查：

| 页面 | 检查内容 |
| --- | --- |
| 用户 | 飞书用户是否映射为 DSM 用户 |
| 部门 | 飞书部门是否映射为 DSM 部门组 |
| 成员 | 部门成员关系是否已经生成 |

正常情况下，点击「同步」会自动通过 Helper 创建或更新 DSM 用户、DSM 部门组和成员关系。页面里的「开通」按钮只用于异常后的单条补偿，例如 Helper 未提权、上次同步中断或 DSM 同名对象冲突。

## 部门组命名

DSM 本地群组不支持飞书那种同名部门层级。DSM Pass 的处理规则是：

| 飞书部门情况 | DSM 部门组名 |
| --- | --- |
| 部门名不重名 | 使用原部门名，例如 `marketing` |
| 部门名重名 | 先生成临时路径名并标记为冲突，等待管理员确认 |

示例：

```text
matrix/sup1/sup2/sup5 -> matrix_sup1_sup2_sup5
matrix/sup1/sup3/sup5 -> matrix_sup1_sup3_sup5
```

同名部门不会自动开通。打开身份源详情时如果还有冲突，页面会弹出冲突处理窗口；管理员可以在同一个窗口里先参考飞书部门路径，把其中任意一个或多个改成最终 DSM 部门组名。冲突部门处理完成前，同步不会继续开通 DSM 用户和成员关系，避免权限落到错误部门。

## 同名用户处理

### DSM 已有同名用户

如果飞书只有一个用户映射到某个 DSM 用户名，而 DSM 本地已经有这个同名用户，DSM Pass 会直接建立飞书身份和 DSM 用户的映射，并把状态标记为「已关联」。这种情况不是冲突，不会要求管理员改名，也不会新建另一个 DSM 用户。

后续同步只要映射关系已经存在，也不会因为飞书新增同名用户而反复把已有映射改写成冲突。

### 飞书内重名用户

只有飞书通讯录里有多个用户清洗后会生成同一个 DSM 用户名时，DSM Pass 才会要求管理员处理。系统会先生成临时名，冲突处理窗口会把飞书内同名用户按姓名放在一起展示，并标记为「飞书内重名」。

管理员可以参考飞书姓名、邮箱、手机号、身份 ID 和所属部门，手动指定最终 DSM 用户名。可以保留其中一个原名，也可以两个都改名；保存后该记录会进入「待开通」，后续可重新同步或手动开通。

如果 DSM Pass 数据库里已经有另一个飞书身份占用了同一个 DSM 用户名，页面会标记为「已被其他身份占用」，管理员需要决定修改哪一条或两条都修改。

## Helper 权限初始化

DSM Pass 后端不直接以 root 运行。创建 DSM 用户、部门组、成员关系和登录中继等高权限操作由 Helper 执行。

如果后台提示：

```text
Helper 无法执行 DSM 用户和群组命令
dial unix .../helper.sock: connect: no such file or directory
```

按下面步骤处理：

1. 在 DSM 控制面板中开启 SSH 服务。
2. 使用 DSM 管理员账号 SSH 登录 NAS。
3. 切换到 root。
4. 执行 DSMPASS 自带的 Helper sudo 规则安装脚本。
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

脚本成功后会写入 `/etc/sudoers.d/DSMPASS-helper`，允许 DSMPASS 套件用户免密码执行 Helper 和 Helper 管理脚本。

卸载套件时会尝试删除这条 sudo 规则；保留套件数据只保留配置、数据库、日志和 TLS 文件。卸载后建议通过 SSH 确认：

```bash
sudo -i
ls -l /etc/sudoers.d/DSMPASS-helper
```

如果仍然存在，手动删除：

```bash
sudo rm -f /etc/sudoers.d/DSMPASS-helper
```

## 架构

```text
Browser
  -> Go 后端
    -> Unix Socket + HMAC
      -> DSM Helper
        -> synouser / synogroup / DSM Auth API / /etc/shadow
```

Helper 边界：

| 机制 | 作用 |
| --- | --- |
| Unix Socket | 仅本机通信 |
| HMAC 请求签名 | 防止未授权调用 Helper |
| 时间戳校验 | 降低重放风险 |
| 用户级锁和 shadow 全局锁 | 避免并发修改 DSM 账号状态 |
| 临时密码 journal | 登录中继异常时可恢复 |

## 安全默认值

| 项目 | 默认策略 |
| --- | --- |
| 后台认证 | 默认开启 |
| HTTPS | 默认开启 |
| 登录诊断日志 | 默认关闭 |
| Helper HMAC 密钥 | 必须显式配置，否则拒绝启动 |
| 日志脱敏 | 脱敏密码、token、SID、cookie、签名和 shadow 行 |

生产环境保持 `DSMPASS_LOGIN_DIAGNOSTICS=false`。即使日志已经脱敏，也应当视为敏感运行数据。

## 开发和测试

目录结构：

```text
go/          Go 后端、DSM Helper、数据库、DSM 打包脚本
frontend/    React + Ant Design 管理后台
docs/        架构、部署和 provider 扩展文档
```

安装前端依赖并构建：

```bash
cd frontend
npm ci
npm run build
```

运行测试：

```bash
make test
```

只运行 Go 测试：

```bash
cd go
GOCACHE="$PWD/.gocache" go test ./...
```

只检查公开文档：

```bash
scripts/test.sh docs
```

## 二进制部署

如果不使用 SPK，可以构建 DSM tar 包：

```bash
make package-dsm
```

输出文件：

```text
go/dist/dsm/dsmpass-linux-amd64.tar.gz
go/dist/dsm/dsmpass-linux-arm64.tar.gz
```

解压后至少需要配置：

```bash
export DSMPASS_ACCESS_HOST=nas.example.com
export DSMPASS_HELPER_HMAC_SECRET="$(openssl rand -hex 32)"
./start-dsmpass.sh
```

## 关键环境变量

| 变量 | 用途 |
| --- | --- |
| `DSMPASS_ACCESS_HOST` | 用户访问后台和 IDP 的 IP 或域名 |
| `DSMPASS_HELPER_HMAC_SECRET` | 后端与 Helper 共用的强随机密钥 |
| `DSMPASS_GO_LISTEN` | 管理后台监听地址，默认 `0.0.0.0:25000` |
| `DSMPASS_TLS_ENABLED` | 管理后台是否启用 HTTPS，SPK 默认启用 |
| `DSMPASS_TLS_CERT_FILE` / `DSMPASS_TLS_KEY_FILE` | 管理端口证书和私钥路径 |
| `DSMPASS_IDP_TLS_CERT_FILE` / `DSMPASS_IDP_TLS_KEY_FILE` | 认证端口证书和私钥路径 |
| `DSMPASS_ADMIN_ALLOWED_CIDRS` | 管理端口允许访问的来源网段，默认仅本机和内网 |
| `DSMPASS_IDP_ALLOWED_CIDRS` | 认证端口允许访问的来源网段，默认允许所有网络 |
| `DSMPASS_DSM_REDIRECT_URL` | 登录成功后跳转的 DSM 地址 |
| `DSMPASS_DSM_LOGIN_API` | DSM Auth API 地址 |
| `DSMPASS_LOGIN_DIAGNOSTICS` | 登录诊断日志开关，生产保持 `false` |
