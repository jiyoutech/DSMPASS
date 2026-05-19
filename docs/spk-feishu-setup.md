# SPK 安装到飞书配置

这份文档按首次部署顺序走一遍：先安装 DSM SPK，再初始化 DSM Pass 后台，最后在飞书开放平台配置 OAuth 登录和通讯录同步。

> 当前项目仍处于 pre-1.0 / alpha 阶段。建议先在测试 NAS 上完整验证安装、同步、登录、升级和卸载流程，再用于生产环境。

## 1. 准备信息

开始前先确认这些信息：

- NAS CPU 架构：Intel/AMD 机型使用 `linux-amd64`，ARMv8/aarch64 机型使用 `linux-arm64`。
- NAS 访问地址：用户浏览器能访问的 IP 或域名，例如 `nas.example.com`。
- DSM 协议：DSM 使用 HTTP 时默认端口是 `5000`，使用 HTTPS 时默认端口是 `5001`。
- 管理后台端口：SPK 安装时填写，默认建议 `25000`，只给管理员访问。
- IDP 入口端口：首次进入后台时填写，默认建议 `26000`，用户登录和飞书回调会访问这个端口。
- 飞书企业管理员账号：需要能创建企业自建应用、开通权限并发布应用。

推荐端口规划：

```text
https://nas.example.com:25000/                  DSM Pass 管理后台
https://nas.example.com:26000/idp/<source>/launch  用户飞书登录入口
https://nas.example.com:5001/                   DSM HTTPS
```

如果 NAS 在反向代理或公网网关后面，飞书回调必须能从公网访问到 IDP 入口地址。

## 2. 获取 SPK

如果已经有发布好的 SPK，直接下载与 NAS 架构匹配的文件：

```text
DSMPASS-<version>-linux-amd64.spk
DSMPASS-<version>-linux-arm64.spk
```

如果需要自己打包，在项目根目录执行：

```bash
DSMPASS_VERSION=0.8.10 make package-spk
```

输出文件在：

```text
go/dist/dsm/DSMPASS-0.8.10-linux-amd64.spk
go/dist/dsm/DSMPASS-0.8.10-linux-arm64.spk
go/dist/dsm/SHA256SUMS
```

## 3. 在 DSM 安装 SPK

1. 登录 DSM 管理界面。
2. 打开「套件中心」。
3. 如果 DSM 阻止手动安装第三方套件，先到「设置」里允许手动安装可信来源套件。
4. 点击「手动安装」，上传对应架构的 `.spk` 文件。
5. 安装向导里填写管理后台端口，例如 `25000`。
6. 完成安装并启动套件。

管理后台默认启用 HTTPS，并会自动生成自签证书。首次访问时浏览器可能提示证书不受信任，需要按内网环境策略信任或继续访问。

安装后常用路径：

```text
/var/packages/DSMPASS/var/dsmpass.env
/var/packages/DSMPASS/var/data/
/var/packages/DSMPASS/var/run/
/var/packages/DSMPASS/var/dsmpass.log
```

`dsmpass.env` 首次安装时会自动生成 `DSMPASS_HELPER_HMAC_SECRET`。不要把这个文件提交或分享给别人。

## 4. 初始化 DSM Pass 后台

用浏览器打开管理后台：

```text
https://<NAS-IP-or-domain>:25000/
```

首次进入会看到「初始化后台账号」：

1. 设置后台管理员账号，默认账号名可以保留为 `admin`。
2. 设置一个强密码。
3. 保存后进入「初始化配置」。

系统配置按下面填写：

- `IDP 协议`：用户访问 IDP 入口使用的协议。生产建议 `HTTPS`。
- `访问 IP / 域名`：用户和飞书回调能访问到的 NAS 域名或 IP，不包含协议和路径，例如 `nas.example.com`。
- `IDP 入口端口`：建议 `26000`，必须大于 `1024` 且未被占用。
- `IDP 地址`：自动生成，例如 `https://nas.example.com:26000`。
- `DSM 地址`：自动生成，HTTPS 对应 `https://nas.example.com:5001/`。
- `DSM Auth API`：自动生成，HTTPS 对应 `https://nas.example.com:5001/webapi/entry.cgi`。
- `DSM 登录模式`：优先使用「直接连接」。如果浏览器无法直接访问 DSM Auth API，再切换为「Helper 连接」。
- `直登 TTL 秒数`：默认 `30` 秒即可。
- `跳过 DSM TLS 校验`：DSM 使用自签证书时可以先打开；生产环境使用可信证书后建议关闭。

点击「检测」可以让后台尝试识别 DSM 地址。确认无误后点击「保存并进入」。

## 5. 创建飞书自建应用

在飞书开放平台创建企业自建应用：

1. 打开飞书开放平台，进入企业后台。
2. 创建「企业自建应用」。
3. 在应用的「凭证与基础信息」页面复制：
   - `App ID`
   - `App Secret`
4. 进入应用的网页能力配置，启用网页应用或配置桌面端主页。
5. 先不要发布，等 DSM Pass 生成登录地址和回调地址后再补齐配置。

DSM Pass 使用的默认飞书接口是：

```text
授权地址:       https://accounts.feishu.cn/open-apis/authen/v1/authorize
换取 token:    https://open.feishu.cn/open-apis/authen/v2/oauth/token
用户信息:       https://open.feishu.cn/open-apis/authen/v1/user_info
租户 token:    https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal
通讯录接口:     https://open.feishu.cn/open-apis/contact/v3
```

通常只需要填写 `App ID` 和 `App Secret`，这些接口地址保持默认。

## 6. 在 DSM Pass 添加飞书身份源

回到 DSM Pass 管理后台：

1. 进入「身份源」。
2. 新建身份源，类型选择「飞书」。
3. 填写名称，例如 `公司飞书`。
4. 填写飞书 `App ID`。
5. 填写飞书 `App Secret`。
6. 填写 `DSM 初始密码`。这是同步创建新 DSM 用户时使用的初始密码，已有 DSM 用户通常不会被改密码。
7. 打开「启用」「登录」「同步」。
8. 如果希望定时同步，填写「定期同步(分钟)」，例如 `60`；填 `0` 表示不定时自动同步。
9. 如需在飞书缺失用户时禁用对应 DSM 登录，打开「禁用缺失用户」。
10. 保存身份源。

保存后进入该身份源详情页，在「飞书」标签下会看到两个地址：

- `Launch`：用户登录入口，示例 `https://nas.example.com:26000/idp/<source>/launch`
- `Callback`：飞书 OAuth 回调地址，示例 `https://nas.example.com:26000/idp/<source>/callback`

这两个地址以后系统配置里的 IDP 协议、访问域名或 IDP 端口变化时会跟着变化。改动后要回飞书开放平台同步更新配置。

## 7. 在飞书填入地址和权限

回到飞书开放平台对应应用：

1. 在网页应用或桌面端主页里填入 DSM Pass 的 `Launch` 地址。
2. 在 OAuth 重定向 URL / 回调地址配置里填入 DSM Pass 的 `Callback` 地址。
3. 在「权限管理」里开通通讯录读取相关权限。
4. 配置应用通讯录权限范围，确保包含需要同步的部门和用户。
5. 配置应用可用范围 / 用户范围，确保允许使用 DSM Pass 登录入口的用户都在范围内。
6. 创建版本并发布应用，按企业要求完成管理员审核。

DSM Pass 同步用户和部门时至少需要读取用户、部门、用户所属部门和部门成员的能力。根据飞书权限页面展示，重点检查这些 scope 或等价权限：

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

飞书里有两个范围要分别设置：

| 范围 | 作用 | 配置建议 |
| --- | --- | --- |
| 通讯录权限范围 | 决定应用 API 能读取哪些部门和用户 | 覆盖需要同步到 DSM 的部门和用户 |
| 应用可用范围 / 用户范围 | 决定哪些用户能看到和使用飞书应用 | 覆盖需要通过 DSM Pass 登录 DSM 的用户 |

`contact:user.department:readonly` 用于读取用户所属部门，缺少时多部门用户可能无法和飞书权限保持一致。`contact:user.email:readonly` 和 `contact:user.phone:readonly` 只影响邮箱、手机号字段是否返回，不影响基础登录和部门同步。

飞书权限页面和 scope 名称可能会随开放平台调整。如果同步时报「飞书接口权限不足」或提示缺少某个 `contact:*` scope，按错误信息补开权限、扩大通讯录数据范围，然后重新发布应用。

## 8. 同步飞书通讯录

在 DSM Pass 身份源详情页点击「同步」。

同步完成后检查三个页面：

- 「用户」：确认飞书用户已经映射为 DSM 用户。
- 「部门」：确认飞书部门已经映射为 DSM 部门组。
- 「成员」：确认部门成员关系已经生成。

部门组名规则：

- 飞书部门名不重名时，DSM 部门组名使用原部门名，例如 `marketing`。
- 飞书部门名重名时，DSM Pass 会先生成临时路径名并标记为冲突，例如 `matrix/sup1/sup2/sup5` 会临时显示为 `matrix_sup1_sup2_sup5`。
- 同名部门不会自动开通。打开身份源详情时如果还有冲突，页面会弹出冲突处理窗口；请先参考飞书部门路径手动指定最终 DSM 部门组名，再继续同步用户和成员关系。

同名用户处理：

- 如果飞书只有一个用户映射到某个 DSM 用户名，而 DSM 本地已经有这个同名用户，DSM Pass 会直接建立飞书身份和 DSM 用户的映射，并标记为「已关联」。这种情况不是冲突，不会要求管理员改名，也不会新建另一个 DSM 用户。
- 已经存在的飞书到 DSM 映射不会因为后续同步又出现同名飞书用户而反复改写为冲突。
- 只有飞书通讯录里有多个用户清洗后会生成同一个 DSM 用户名时，DSM Pass 才会要求管理员处理。
- DSM Pass 会先生成临时名，并在冲突处理窗口显示飞书姓名、邮箱、手机号、身份 ID 和所属部门供管理员区分。
- 飞书通讯录内同名用户会按姓名放在一起展示，并标记为「飞书内重名」。
- 如果 DSM Pass 数据库里已经有另一个飞书身份占用了同一个 DSM 用户名，页面会标记为「已被其他身份占用」。
- 管理员可以保留其中一个原名，也可以两个都改名；保存后该记录会进入「待开通」，后续可重新同步或手动开通。

正常情况下，点击「同步」会自动通过 DSM Helper 创建或更新 DSM 用户、DSM 部门组和成员关系，不需要逐个点击「开通」。

如果用户或部门显示「待开通」，说明这条记录已经从飞书同步到 DSM Pass 数据库，但还没有成功落到 DSM 本地用户或部门组里。常见原因是 Helper 还没有完成提权、上次同步中断、DSM 已存在同名对象产生冲突，或某个空部门需要等有成员关系时再由 DSM 创建。修好问题后可以重新同步；页面里的「开通」按钮只作为单条记录的补偿操作。

如果出现冲突，常见原因是：

- 飞书姓名清洗后不符合 DSM 用户名规则。
- DSM 已存在同名用户或部门组。
- 飞书应用通讯录权限范围不包含该用户或部门。

处理冲突后重新同步。

## 9. 验证飞书登录 DSM

1. 用一个已经同步并开通 DSM 账号的飞书用户访问 `Launch` 地址。
2. 浏览器会跳转到飞书授权页。
3. 飞书授权成功后回到 DSM Pass `Callback`。
4. DSM Pass 会通过 Helper 准备 DSM 登录，并跳转到 DSM。
5. 最终应进入 DSM 网页界面。

如果登录失败，先检查：

- 飞书应用的回调地址是否和 DSM Pass 页面显示的 `Callback` 完全一致。
- IDP 地址是否能被用户浏览器访问；如果飞书要求公网回调，公网也必须能访问。
- 该飞书用户是否已经同步、开通 DSM 账号，并且「允许登录」为开启。
- DSM 地址和 DSM Auth API 是否能从用户浏览器访问。
- DSM 使用自签 HTTPS 证书时，用户浏览器是否已经信任或允许访问 DSM 证书页面。
- `/var/packages/DSMPASS/var/dsmpass.log` 是否有端口、权限或 Helper 错误。

如果后台提示 Helper 无法执行 DSM 用户和群组命令，或出现：

```text
dial unix .../helper.sock: connect: no such file or directory
```

说明 Helper 没有成功启动，或还没有拿到执行 DSM 用户、群组命令的权限。DSM Pass 后端不会直接以 root 权限运行；Helper 需要通过本机 sudo 规则提权，才能调用 DSM 的用户和群组命令。

处理步骤：

1. 在 DSM 控制面板中开启 SSH 服务。
2. 用 DSM 管理员账号 SSH 登录 NAS。
3. 切换到 root。
4. 执行 DSMPASS 自带的 Helper sudo 规则安装脚本。
5. 回到管理后台点击「重启并检查 Helper」。
6. 检查 `helper.sock` 是否已经生成。

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

脚本成功后会写入 `/etc/sudoers.d/DSMPASS-helper`，允许 DSMPASS 套件用户免密码执行 Helper 和 Helper 管理脚本。优先检查 Helper 是否提权成功，管理后台重启并检查 Helper 后 `/var/packages/DSMPASS/var/dsmpass.log` 是否还有启动错误。

卸载套件时会尝试删除这条 sudo 规则；保留套件数据只保留配置、数据库、日志和 TLS 文件。卸载后建议通过 SSH 确认：

```bash
sudo -i
ls -l /etc/sudoers.d/DSMPASS-helper
```

如果仍然存在，手动删除：

```bash
sudo rm -f /etc/sudoers.d/DSMPASS-helper
```

## 10. 变更和排障

修改 IDP 协议、访问域名或 IDP 端口后：

1. 在「系统设置」保存新配置。
2. 回到身份源详情页复制新的 `Launch` 和 `Callback`。
3. 更新飞书开放平台里的主页地址和 OAuth 回调地址。
4. 重新发布飞书应用。
5. 再做一次登录验证。

修改 SPK 环境变量后，重启套件：

```bash
sudo /var/packages/DSMPASS/scripts/start-stop-status restart
```

查看日志：

```text
/var/packages/DSMPASS/var/dsmpass.log
```

生产环境保持 `DSMPASS_LOGIN_DIAGNOSTICS=false`。只有排查问题时才临时打开诊断日志，问题解决后及时关闭。

## 参考

- 飞书开放平台：https://open.feishu.cn/
- 飞书授权地址接口：`https://accounts.feishu.cn/open-apis/authen/v1/authorize`
- 飞书通讯录接口文档入口：https://open.feishu.cn/document/server-docs/contact-v3
- SPK 打包和升级细节：[`dsm-spk-package.md`](dsm-spk-package.md)
