# DSM Pass

DSM Pass 是面向 Synology DSM 的企业身份登录网关。它把企业身份源、OAuth 登录、通讯录同步和 DSM 本地账号体系连接起来，让用户可以使用企业身份进入 DSM。

当前主线实现为 **Go 后端 + Go DSM Helper + React 管理后台**，优先支持飞书企业自建应用。

> 项目仍处于 pre-1.0 阶段。DSM 登录中继、临时密码、Cookie 写入和 Helper 提权都属于高风险系统集成能力。生产使用前，请先在测试 NAS 上完整验证安装、升级、卸载、端口映射、登录和恢复流程。

## 目录

- [功能概览](#功能概览)
- [系统架构](#系统架构)
- [仓库结构](#仓库结构)
- [安装 DSM 套件](#安装-dsm-套件)
- [初始化后台](#初始化后台)
- [配置飞书身份源](#配置飞书身份源)
- [同步规则](#同步规则)
- [登录验证](#登录验证)
- [开发与测试](#开发与测试)
- [发布与打包](#发布与打包)
- [安全与公开发布](#安全与公开发布)
- [许可证](#许可证)

## 功能概览

| 能力 | 状态 |
| --- | --- |
| 飞书 OAuth 登录 DSM | 已支持 |
| 飞书通讯录用户、部门、成员同步 | 已支持 |
| DSM 用户、部门组和成员关系自动开通 | 已支持 |
| 用户级禁止登录 | 已支持 |
| 身份源级登录和同步开关 | 已支持 |
| 身份源级定时同步 | 已支持 |
| 登录审计和同步日志 | 已支持 |
| 同步、清理和批量操作进度展示 | 已支持 |
| DSM SPK 安装包 | 已支持 x86_64 / aarch64 |
| 管理后台 HTTPS | 默认启用，自签证书自动生成 |
| IDP 入口协议和端口 | 后台可配置，支持热重启 |
| IDP 入口校验 | 只允许通过系统配置的 IDP 地址访问认证入口 |
| 管理端内网访问开关 | 可选择让管理后台仅允许本机和内网访问 |

## 系统架构

```text
Browser
  -> DSM Pass Go Backend
    -> SQLite
    -> Unix Socket + HMAC
      -> DSM Helper
        -> synouser / synogroup / DSM Auth API

Feishu OAuth
  -> DSM Pass IDP endpoint
    -> DSM login relay
```

| 组件 | 职责 |
| --- | --- |
| Go Backend | 管理后台 API、IDP 入口、运行配置、同步调度、审计日志和静态前端服务 |
| Go Helper | 隔离 DSM 本地账号、群组和登录中继等高权限操作 |
| SQLite | 保存身份源配置、同步结果、DSM 映射、审计日志和操作进度 |
| React Frontend | 管理后台、身份源配置、同步进度、冲突处理和系统设置 |
| SPK scripts | DSM 安装、启动、卸载、升级和 Helper sudo 初始化 |

## 仓库结构

```text
.
├── go/                         Go 后端、Helper、数据库和 DSM 打包脚本
│   ├── cmd/backend/            管理后台和 IDP 服务入口
│   ├── cmd/helper/             DSM Helper 服务入口
│   ├── internal/backend/       HTTP 路由、同步、设置、审计和操作进度
│   ├── internal/db/            SQLite schema、查询和数据访问代码
│   ├── internal/helperclient/  后端到 Helper 的 Unix Socket 客户端
│   ├── internal/helperserver/  Helper 本机服务
│   ├── internal/identity/      用户名、部门名和跨源映射规则
│   ├── internal/provider/      身份源 provider 实现
│   ├── internal/syncsvc/       通讯录同步编排
│   └── scripts/dsm/            DSM tar / SPK 打包和套件脚本
├── frontend/                   React + Ant Design 管理后台
│   ├── src/                    前端源码
│   ├── public/                 前端静态资源
│   └── package.json            前端构建、lint 和依赖配置
├── docs/                       部署、测试、发布和 provider 开发文档
├── media/                      README 图文教程截图
├── scripts/                    仓库级测试和公开检查脚本
├── .github/                    CI、发布流程、CODEOWNERS 和 Dependabot
├── Makefile                    常用开发、测试和打包入口
├── LICENSE                     AGPLv3 许可证正文
└── README.md                   项目说明
```

## 安装 DSM 套件

### 下载 SPK

从 GitHub Releases 下载与 NAS 架构匹配的安装包：

| NAS 架构 | 文件 |
| --- | --- |
| Intel / AMD | `DSMPASS-<version>-linux-amd64.spk` |
| ARMv8 / aarch64 | `DSMPASS-<version>-linux-arm64.spk` |

也可以本地打包：

```bash
DSMPASS_VERSION=0.8.42 make package-spk
```

输出文件位于：

```text
go/dist/dsm/DSMPASS-<version>-linux-amd64.spk
go/dist/dsm/DSMPASS-<version>-linux-arm64.spk
go/dist/dsm/SHA256SUMS
```

### 手动安装

1. 打开 DSM「套件中心」并选择手动安装。
2. 上传与 NAS 架构匹配的 `.spk` 文件。
3. 同意第三方套件安装提示和许可证。
4. 在安装向导中填写管理后台端口，例如 `25000`。
5. 完成安装并启动套件。

<details>
<summary>查看安装截图</summary>

![选择 DSM Pass 安装包](media/17795482410730/17799554366438.jpg)

![同意第三方套件安装](media/17795482410730/17799554564978.jpg)

![同意许可协议](media/17795482410730/17799554746904.jpg)

![填写管理后台端口](media/17795482410730/17799554871604.jpg)

![确认安装](media/17795482410730/17799557535735.jpg)

</details>

## 初始化后台

### 配置 Helper sudo 初始化脚本

DSM Pass 后端默认不以 root 权限运行。创建 DSM 用户、部门组、成员关系和登录中继等高权限操作由 Helper 执行。安装完成后，需要在 DSM 中以 root 运行一次套件自带的 sudo 规则初始化脚本。

在 DSM 控制面板中新增用户定义脚本任务，选择以 root 运行，并执行：

```bash
/var/packages/DSMPASS/target/setup-helper-sudo.sh
```

<details>
<summary>查看 Helper 初始化截图</summary>

![新增用户定义脚本](media/17795482410730/ae04d3df18e2dd4f822bc40b6e2a4230.png)

![选择 root 运行](media/17795482410730/17799551840958.jpg)

![填写初始化命令](media/17795482410730/17799552428360.jpg)

![运行初始化任务](media/17795482410730/17799553118162.jpg)

![套件未运行时的提示](media/17795482410730/17799568488229.jpg)

</details>

### 首次登录

首次进入管理后台时，系统会引导创建后台管理员账号，并初始化系统运行配置。

| 配置项 | 说明 |
| --- | --- |
| IDP 协议 | 生产建议使用 `HTTPS` |
| 访问主机地址 | 填写用户能访问的 NAS IP 或域名，例如 `nas.example.com` |
| IDP 入口端口 | 建议 `26000`，必须未被占用 |
| DSM 地址 | 确认自动识别主机地址 |
| DSM Auth API | 确认自动识别主机地址 |

管理后台默认使用 HTTPS 和 DSMPASS 自签证书。测试环境可以在浏览器中继续访问；生产环境建议使用可信证书，并把管理后台限制在可信网络中。

<details>
<summary>查看初始化截图</summary>

![创建后台管理员](media/17795482410730/17799558114617.jpg)

![初始化系统设置](media/17795482410730/17799556832943.jpg)

</details>

## 配置飞书身份源

### 创建企业自建应用

1. 打开飞书开放平台：https://open.feishu.cn/
2. 创建「企业自建应用」。
3. 在「凭证与基础信息」中获取 `App ID` 和 `App Secret`。
4. 回到 DSM Pass，新建「飞书」身份源，填写 `App ID`、`App Secret` 和 DSM 初始密码。

<details>
<summary>查看应用创建截图</summary>

![飞书开放平台](media/17795482410730/9716d2e1dc8db84d041bec9e86f2e6c9.png)

![创建企业自建应用](media/17795482410730/d0e6c51d068ec72e7e8393e6ee2a05d6.png)

![获取应用凭证](media/17795482410730/fec73d9e86ed3d4acc567b93f0e99fad.png)

![新建飞书身份源](media/17795482410730/17799520508478.jpg)

</details>

### 配置主页和回调地址

保存身份源后，进入身份源详情页，记录页面显示的 `Launch` 和 `Callback` 地址。

| 飞书配置项 | 填写内容 |
| --- | --- |
| 桌面端主页 | DSM Pass 身份源详情页的 `Launch` 地址 |
| OAuth 重定向 URL | DSM Pass 身份源详情页的 `Callback` 地址 |

如果后续修改 DSM Pass 的 IDP 协议、访问域名或 IDP 端口，需要同步更新飞书里的主页地址和回调地址，并重新发布应用。

<details>
<summary>查看主页和回调配置截图</summary>

![身份源详情页](media/17795482410730/17799589536266.jpg)

![Launch 和 Callback 地址](media/17795482410730/17799622260694.jpg)

![添加网页应用能力](media/17795482410730/72f685586e995efd4107acd98289b549.png)

![填写桌面端主页](media/17795482410730/52c986502e212d0f3c2037afab894639.png)

![填写 OAuth 重定向 URL](media/17795482410730/a559161cb415ad364146bef744893132.png)

</details>

### 开通权限

DSM Pass 同步飞书通讯录时需要读取用户、部门、用户所属部门和部门成员关系。

| 类型 | 权限 | 用途 |
| --- | --- | --- |
| 必需 | `contact:contact.base:readonly` | 允许应用读取通讯录基础数据 |
| 必需 | `contact:user.base:readonly` | 读取用户姓名、用户 ID 等基础信息 |
| 建议 | `contact:user.basic_profile:readonly` | 登录时读取当前用户基础资料 |
| 必需 | `contact:user.department:readonly` | 读取用户所属部门，用于同步多部门用户和组成员关系 |
| 必需 | `contact:department.base:readonly` | 读取部门名称、部门 ID 等基础信息 |
| 必需 | `contact:department.organize:readonly` | 读取部门上下级组织架构 |
| 按需 | `contact:user.email:readonly` | 需要同步邮箱字段时开启 |
| 按需 | `contact:user.phone:readonly` | 需要同步手机号字段时开启 |

`corehr:department:read` 和 `directory:department.name:read` 属于飞书其他通讯录或人事接口权限，当前 DSM Pass 同步不会调用这些接口；如果已经开通可以保留，但不属于最小必需权限。

<details>
<summary>查看权限和发布截图</summary>

![开通权限入口](media/17795482410730/fdb1888d7409309c9b8905b463b787fa.png)

![权限配置参考](media/17795482410730/b1f30b847940f788506838bc74abccb5.png)

![保存权限范围](media/17795482410730/2bed13bf798298911d28ca7641c6303a.png)

![创建应用版本](media/17795482410730/adc2cc8a5fcc31014069edbca9a50129.png)

![配置应用可用范围](media/17795482410730/d81c52814e1640e61303710105d8b4ac.png)

![提交发布](media/17795482410730/64a58a9b30ab5a1b52d17be5ce03c3f5.png)

</details>

## 同步规则

### 用户处理

如果飞书只有一个用户映射到某个 DSM 用户名，而 DSM 本地已经有同名用户，DSM Pass 会直接建立飞书身份和 DSM 用户的映射，并把状态标记为「已关联」。这种情况不是冲突，不会要求管理员改名，也不会新建另一个 DSM 用户。

只有飞书通讯录里有多个用户清洗后会生成同一个 DSM 用户名时，DSM Pass 才会要求管理员处理。系统会先生成临时名，冲突处理窗口会把飞书内同名用户按姓名放在一起展示，并标记为「飞书内重名」。

如果 DSM Pass 数据库里已经有另一个飞书身份占用了同一个 DSM 用户名，页面会标记为「已被其他身份占用」，管理员需要决定修改哪一条或两条都修改。

### 部门组处理

DSM 本地群组不支持飞书那种同名部门层级。DSM Pass 的处理规则是：如果遇到部门名重名会先生成临时路径名并标记为冲突，等待管理员确认。

同名部门不会自动开通。打开身份源详情时如果还有冲突，页面会弹出冲突处理窗口；管理员可以参考飞书部门路径，把其中任意一个或多个改成最终 DSM 部门组名。冲突部门处理完成前，同步不会继续开通 DSM 用户和成员关系，避免权限落到错误部门。

### 手动同步

回到 DSM Pass 身份源详情页，点击「同步」。同步完成后检查：

| 页面 | 检查内容 |
| --- | --- |
| 用户 | 飞书用户是否映射为 DSM 用户 |
| 部门 | 飞书部门是否映射为 DSM 部门组 |
| 成员 | 部门成员关系是否已经生成 |
| 同步日志 | 是否存在阻断、失败或权限不足错误 |

<details>
<summary>查看同步截图</summary>

![手动同步](media/17795482410730/cd4bba6efc775873d84cc15057e9af19.png)

![权限不足提示](media/17795482410730/17799601557670.jpg)

![DSM 用户与群组检查](media/17795482410730/f5ac64896a4324e451988a56178c7828.png)

</details>

## 登录验证

完整登录流程如下：

![飞书登录流程](media/17795482410730/login-flow.gif)

验证步骤：

1. 打开 DSM Pass 身份源详情页，复制页面显示的 `Launch` 地址。
2. 访问 `Launch` 地址，浏览器会跳转至飞书登录页面。
3. 完成飞书登录并授权。
4. 如果浏览器尚未信任 NAS 的 HTTPS 证书，先打开 DSM 页面完成证书信任，再继续登录。
5. 登录成功后进入 DSM。

<details>
<summary>查看登录验证截图</summary>

![复制 Launch 地址](media/17795482410730/17799622566732.jpg)

![跳转飞书登录](media/17795482410730/17799623060137.jpg)

![飞书授权](media/17795482410730/17799623504317.jpg)

![回调地址错误提示](media/17795482410730/17799596979334.jpg)

![证书信任提示](media/17795482410730/17800355308190.jpg)

![打开 DSM 证书页面](media/17795482410730/17800356762727.jpg)

![确认 DSM 登录页可访问](media/17795482410730/17800356970670.jpg)

![修改 DSM 用户密码](media/17795482410730/17800358481397.jpg)

</details>

## 开发与测试

### 环境要求

| 工具 | 建议版本 |
| --- | --- |
| Go | `1.26.4` |
| Node.js | `>=22.12.0` |
| npm | `>=10.0.0` |

### 常用命令

```bash
# 安装前端依赖
make frontend-install

# 运行全部测试和公开文档检查
make test

# 只运行 Go 测试
make go-test

# 只运行前端构建
make build-frontend

# 只运行公开文档检查
make docs-test
```

前端也提供独立命令：

```bash
cd frontend
npm run lint
npm run build
```

Go 测试默认使用仓库内缓存目录，避免污染系统级 Go 缓存：

```bash
cd go
GOCACHE="$PWD/.gocache" GOMODCACHE="$PWD/.gomodcache" go test ./...
```

## 发布与打包

### 二进制 tar 包

```bash
make package-dsm
```

输出文件：

```text
go/dist/dsm/dsmpass-linux-amd64.tar.gz
go/dist/dsm/dsmpass-linux-arm64.tar.gz
```

### DSM SPK

```bash
DSMPASS_VERSION=0.8.42 make package-spk
```

输出文件：

```text
go/dist/dsm/DSMPASS-0.8.42-linux-amd64.spk
go/dist/dsm/DSMPASS-0.8.42-linux-arm64.spk
go/dist/dsm/SHA256SUMS
```

推送 `v*` 标签时，GitHub Actions 会构建 SPK 并上传到 GitHub Release。

## 安全与公开发布

- 不要提交真实飞书应用密钥、OAuth token、DSM SID、Cookie、临时密码、生产证书私钥、日志或数据库。
- README 截图发布前需要人工确认已移除组织名、真实域名、真实用户信息和敏感配置。
- 生产环境建议使用可信 HTTPS 证书，并限制管理后台访问范围。
- 发现安全问题时，请先私下联系维护者，不要在公开 issue 中披露可利用细节。
- 公开发布前执行 `make test`，并参考 [docs/publication-guidelines.md](docs/publication-guidelines.md)。

## 许可证

DSM Pass 以 GNU Affero General Public License v3.0 only（`AGPL-3.0-only`）授权，详见 [LICENSE](LICENSE)。
