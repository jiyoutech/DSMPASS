# DSM Pass

DSM Pass 是面向 Synology DSM 的企业身份登录网关。它把飞书 OAuth 登录、通讯录同步和 DSM 本地账号体系连接起来，让用户可以使用企业身份进入 DSM。

如果需要方案部署或技术支持，请联系: sales@jiyou-tech.com

> DSM Pass 是独立第三方项目，与 Synology Inc. 无隶属、授权或背书关系。

## 功能概览

| 能力 | 状态 |
| --- | --- |
| 飞书 OAuth 登录 DSM | 已支持 |
| 企业微信 OAuth 登录 DSM | 已支持 |
| 钉钉 OAuth 登录 DSM | 已支持 |
| 通讯录用户、部门、成员同步 | 已支持 |
| DSM 用户、部门组和成员关系自动开通 | 已支持 |
| 用户级禁止登录 | 已支持 |
| 身份源级登录/同步开关 | 已支持 |
| 身份源级定时同步 | 已支持 |
| 登录审计和同步日志 | 已支持 |
| DSM SPK 安装包 | 已支持 x86_64 / aarch64 |
| 管理后台 HTTPS | 默认启用，自签证书自动生成 |
| IDP 入口协议和端口 | 后台可配置，支持热重启 |
| IDP 入口校验 | 只允许通过系统配置的 IDP 地址访问认证入口 |
| 管理端内网访问开关 | 可选择让管理后台仅允许本机和内网访问 |

<div STYLE="page-break-after: always;"></div>

## 快速安装

### 一、安装 DSM Pass 到 DSM

1、 打开 DSM「套件中心」点击手动安装套件，在浏览中选择DSM Pass安装包:
![-w400](../media/17795482410730/17799554366438.jpg)

2、同意第三方套件的安装:
![-w400](../media/17795482410730/17799554564978.jpg)

<div STYLE="page-break-after: always;"></div>

3、同意许可协议
![-w400](../media/17795482410730/1987667533266788315678.png)

4、在安装向导中填写管理后台端口，例如 `25000`。
![-w400](../media/17795482410730/17799554871604.jpg)

<div STYLE="page-break-after: always;"></div>

5、确认安装
![-w400](../media/17795482410730/17799557535735.jpg)

### 二、配置初始化套件脚本

在控制面板->任务计划->新增计划的任务，选择用户定义的脚本:
![-w400](../media/17795482410730/ae04d3df18e2dd4f822bc40b6e2a4230.png)

<div STYLE="page-break-after: always;"></div>

选择以root运行并取消勾选已启动:
![-w300](../media/17795482410730/17799551840958.jpg)

在运行命令中填写以下命令:
`/var/packages/DSMPASS/target/setup-helper-sudo.sh`
![-w300](../media/17795482410730/17799552428360.jpg)

<div STYLE="page-break-after: always;"></div>

选择初始化脚本的任务并点击运行:
![-w350](../media/17795482410730/17799553118162.jpg)

如果没有运行套件会有以下提示:
![-w500](../media/17795482410730/17799568488229.jpg)

### 三、 初始化后台

首次登录时自动创建后台账号，输入希望作为DSM Pass的管理员账号密码:
![-w350](../media/17795482410730/17799558114617.jpg)

<div STYLE="page-break-after: always;"></div>

IDP 协议: 生产建议 `HTTPS`
访问主机地址: 填写用户能访问的 NAS IP 或域名，例如 `nas.example.com`
IDP 入口端口: 建议 `26000`，必须未被占用
DSM 地址: 确认自动识别主机地址
DSM Auth API: 确认自动识别主机地址
![-w300](../media/17795482410730/17799556832943.jpg)

管理后台默认使用 HTTPS 和 DSMPASS 自签证书。测试环境可以在浏览器中继续访问；生产环境建议把管理后台限制在内网。认证端可以上传自己的证书，上传后系统会读取证书里的 DNS 域名并自动同步到 IDP 地址。

<div STYLE="page-break-after: always;"></div>

## 配置飞书连接

### 获取飞书应用`App ID`与`App Secret`

1、 在飞书开放平台创建「企业自建应用」

进入开发者后台:
https://open.feishu.cn/
![-w500](../media/17795482410730/9716d2e1dc8db84d041bec9e86f2e6c9.png)

选择创建企业自建应用并输入应用名称以及应用描述:
![-w500](../media/17795482410730/d0e6c51d068ec72e7e8393e6ee2a05d6.png)

<div STYLE="page-break-after: always;"></div>

2、 进入应用，在「凭证与基础信息」中获取`App ID`和`App Secret`
![-w500](../media/17795482410730/fec73d9e86ed3d4acc567b93f0e99fad.png)

3、 回到 DSM Pass 新建「飞书」身份源，填入`App ID`、`App Secret`并保存:
![-w500](../media/17795482410730/4691c56c9d97d7ee4ebba955a68cdb5e.png)

<div STYLE="page-break-after: always;"></div>

### 配置飞书应用

#### 配置飞书应用网页能力与重定向URL

1、在 DSM Pass 的飞书应用中记录页面显示的`Launch`和`Callback`地址。
![-w500](../media/17795482410730/17799622260694.jpg)

2、 回到飞书开发者应用，在添加应用能力中选择添加网页应用能力:
![-w500](../media/17795482410730/72f685586e995efd4107acd98289b549.png)

<div STYLE="page-break-after: always;"></div>

3、将 DSM Pass页面显示的`Launch`填写在桌面端主页中并选择在浏览器中打开后保存:
![-w500](../media/17795482410730/52c986502e212d0f3c2037afab894639.png)

4、在安全设置的重定向URL中将DSM Pass页面显示的`Callback`填写到重定向URL中:
![-w500](../media/17795482410730/a559161cb415ad364146bef744893132.png)

5、 如果后续修改 DSM Pass 的 IDP 协议、访问域名或 IDP 端口，需要同步更新飞书里的主页地址和回调地址，并重新发布应用。

<div STYLE="page-break-after: always;"></div>

#### 配置飞书应用权限

在权限管理中点击开通权限:
![-w350](../media/17795482410730/fdb1888d7409309c9b8905b463b787fa.png)

搜索`:read`，开通应用身份权限中通讯录以及组织架构的所有read权限，共93条:
![-w200](../media/17795482410730/b1f30b847940f788506838bc74abccb5.png)

范围中配置为全部并保存开通权限:
![-w300](../media/17795482410730/2bed13bf798298911d28ca7641c6303a.png)

<div STYLE="page-break-after: always;"></div>

#### 提交飞书应用版本

1、 在版本管理中选择创建版本:
![-w400](../media/17795482410730/adc2cc8a5fcc31014069edbca9a50129.png)

2、 在可用范围选择为所有员工或指定员工该范围决定哪些用户能看到和使用飞书应用:
![-w300](../media/17795482410730/d81c52814e1640e61303710105d8b4ac.png)

3、提交发布:
![-w350](../media/17795482410730/64a58a9b30ab5a1b52d17be5ce03c3f5.png)

<div STYLE="page-break-after: always;"></div>

### 同步飞书账号及群组

1、 登录 DSM Pass 点击同步以获取飞书账号及群组至NAS:
![-w500](../media/17795482410730/cd4bba6efc775873d84cc15057e9af19.png)

2、 前往NAS的控制面板->用户与群组中，确认账号与群组是否正确:
![-w500](../media/17795482410730/f5ac64896a4324e451988a56178c7828.png)

<div STYLE="page-break-after: always;"></div>

### 测试飞书单点登录

1、在 DSM Pass 的飞书应用中复制页面显示的`Launch`地址:
![-w500](../media/17795482410730/17799622566732.jpg)

2、访问`Launch`地址会跳转至飞书登录页面:
![-w300](../media/17795482410730/17799623060137.jpg)

3、登录后进行授权:
![-w300](../media/17795482410730/17799623504317.jpg)

<div STYLE="page-break-after: always;"></div>

4、如果没有信任过NAS的https则需要先打开DSM页面进行证书信任，然后再点击继续登录。
![-w300](../media/17795482410730/17800355308190.jpg)

点击打开DSM证书页面，选择信任继续前往:
![-w300](../media/17795482410730/17800356762727.jpg)

看到登录页面后关闭该登录页面：
![-w300](../media/17795482410730/17800356970670.jpg)

<div STYLE="page-break-after: always;"></div>

然后点击已信任继续登录:
![-w400](../media/17795482410730/17800355308190.jpg)

5、 如果有配置信任HTTPS证书则会直接登录到NAS，如果需要使用SMB则在右上角用户的个人设置中进行密码修改，当前密码为DSM Pass中配置的初始密码:
![-w500](../media/17795482410730/75fcc73feafcf8255c6eaa6a5ae5d614.png)

<div STYLE="page-break-after: always;"></div>

## 配置企业微信连接

### 获取企业微信企业ID，应用`Agentid`和`Secret`

1、 登录企业微信后台:
https://work.weixin.qq.com/wework_admin/frame#/apps

在我的企业 -> 企业信息 获取企业ID:
![-w400](../media/17795482410730/f4ca0491f8de7723e16f6d6a2cffee19.png)

2、 在企业微信后台的应用管理中创建「企业自建应用」
![-w400](../media/17795482410730/587120b1b1b8b1d55b43b850118175ee.png)

<div STYLE="page-break-after: always;"></div>

上传应用图标，输入应用名称以及应用描述，并选择应用的可见范围:
![-w400](../media/17795482410730/503f12b0f397bb0d54bd2a08a5763e03.png)

3、 进入应用，获取`Agentid`和`Secret`，Secret需要在企业微信手机端查看:
![-w400](../media/17795482410730/d797e8b255a5ea835ccd2e9cf862642f.png)

4、 回到 DSM Pass 新建「企业微信」身份源，填入企业ID、应用`Agentid`、`Secret`并保存:
![-w400](../media/17795482410730/bbd029ec370f9a356ed65b66a0bdb371.png)

<div STYLE="page-break-after: always;"></div>

### 配置企业微信应用接口

#### 配置可信域名

在应用的开发接口中选择设置可信域名，填写可信域名并申请校验域名:
(该域名仅需要通过80端口文件认证即可，不需要解析到公司公网IP)
![-w500](../media/17795482410730/c78bb7c563a5f46f02450743694965ec.png)

请确保可以通过域名访问到对应内容即可通过认证:
![-w300](../media/17795482410730/b812c1a74065264d5c91fd3e412a424b.png)

![-w400](../media/17795482410730/91778d83ceb4e74e80306fa3dc9ccc8d.png)

<div STYLE="page-break-after: always;"></div>

#### 配置企业可信IP

可以通过咨询网络运营商或通过以下网址查看当前公司的公网IP:
https://www.ip138.com/
![-w300](../media/17795482410730/2c9c754f171b2b4b07ca9fbd9474f616.png)

在企业微信应用的开发接口中选择设置企业可信IP:
![-w300](../media/17795482410730/6685270d2082b748a2fc46acba0d637a.png)

#### 配置应用授权回调域

1、 在 DSM Pass 的企业微信应用中查看页面显示的`Launch`中IP、域名及端口:
![-w400](../media/17795482410730/d3f85a92b8dad58dd666fd79f183e464.png)

<div STYLE="page-break-after: always;"></div>

2、 在企业微信应用的开发接口中选择设置企业微信授权登录:
![-w400](../media/17795482410730/84ae88064417cb82744d34d23ee79e65.png)

3、 编辑web网页的授权回调域为DSM Pass `Launch`中IP、域名及端口:
![-w400](../media/17795482410730/1e4e8258d312a7e55d727d81a954643a.png)

4、 如果后续修改 DSM Pass 的 IDP 协议、访问域名或 IDP 端口，需要同步更新企业微信应用中的授权回调域地址。

<div STYLE="page-break-after: always;"></div>

### 同步企业微信账号及群组

1、 登录 DSM Pass 点击同步以获取企业微信账号及群组至NAS:
![-w500](../media/17795482410730/7496d8085a5c8dff8196146e1b745384.png)

2、 前往NAS的控制面板->用户与群组中，确认账号与群组是否正确:
![-w500](../media/17795482410730/b9d7aa0bd3d9afd6c1312ec8e87885e3.png)

<div STYLE="page-break-after: always;"></div>

### 测试企业微信单点登录

1、 打开 DSM Pass 点击企业微信身份源，复制页面显示的`Launch`地址:
![-w400](../media/17795482410730/cddd44c02bf10ec7ed1545eefc921d85.png)

2、访问`Launch`地址会跳转至企业微信登录页面进行扫码登录:
![-w400](../media/17795482410730/91be364b7635f49ad5eb5cd066035197.png)

<div STYLE="page-break-after: always;"></div>

3、如果没有信任过NAS的https则需要先打开DSM页面进行证书信任，然后再点击继续登录。
![-w300](../media/17795482410730/17800355308190.jpg)

点击打开DSM证书页面，选择信任继续前往:
![-w300](../media/17795482410730/17800356762727.jpg)

看到登录页面后关闭该登录页面：
![-w300](../media/17795482410730/17800356970670.jpg)

<div STYLE="page-break-after: always;"></div>

然后点击已信任继续登录:
![-w400](../media/17795482410730/17800355308190.jpg)

4、 如果有配置信任HTTPS证书则会直接登录到NAS，如果需要使用SMB则在右上角用户的个人设置中进行密码修改，当前密码为DSM Pass中配置的初始密码:
![-w500](../media/17795482410730/75fcc73feafcf8255c6eaa6a5ae5d614.png)

<div STYLE="page-break-after: always;"></div>

## 配置钉钉连接

### 获取钉钉应用`App ID`与`App Secret`

1、 登录钉钉开发者平台:
https://open-dev.dingtalk.com/

2、 在应用开发 -> 钉钉应用 创建应用 输入应用名称、应用描述以及上传应用图标:
![-w500](../media/17795482410730/3625becb22952fd1adf9ae7a306f69a5.png)

3、 进入应用，在「凭证与基础信息」中获取`Client ID`和`Client Secret`
![-w500](../media/17795482410730/9d77a05bbc447b0c1061fb9bf67aaf57.png)

<div STYLE="page-break-after: always;"></div>

4、 回到 DSM Pass 新建「钉钉」身份源，填入`Client ID`、`Client Secret`并保存:
![-w500](../media/17795482410730/284a27bac645414eaf01bb720fc75a86.png)

### 配置钉钉应用

#### 配置钉钉应用网页能力与重定向URL

1、在 DSM Pass 的钉钉应用中记录页面显示的`Launch`和`Callback`地址。
![-w500](../media/17795482410730/30480ae4206a68bd8e71826b4d861291.png)

<div STYLE="page-break-after: always;"></div>

2、 回到钉钉开发者应用，在添加应用能力中选择添加网页应用能力:
![-w500](../media/17795482410730/9d7b33160689dd9b4b41b272998ea7fe.png)

3、在网页应用中选择编辑网页应用配置:
![-w500](../media/17795482410730/575ea8f9d20a86952caaf074b52f24af.png)

<div STYLE="page-break-after: always;"></div>

4、将 DSM Pass页面显示的`Launch`填写在PC端首页地址后保存:
![-w500](../media/17795482410730/9ef2cb995d3d2eea92c755f47724aca7.png)

5、在安全设置的重定向URL中将DSM Pass页面显示的`Callback`填写到重定向URL中:
![-w500](../media/17795482410730/e2fb962cc206adeea9c1369b82cf22f0.png)

6、 如果后续修改 DSM Pass 的 IDP 协议、访问域名或 IDP 端口，需要同步更新钉钉里的PC端首页地址和回调地址，并重新发布应用。

<div STYLE="page-break-after: always;"></div>

#### 配置钉钉应用权限

在权限管理中点击开通权限:

个人权限:
通讯录个人信息读取权限
![-w500](../media/17795482410730/c47c0280014d9e5d1eb4fe91a4e1bc57.png)

通讯录管理:
企业员工手机号信息
邮箱等个人信息
通讯录部门信息读权限
成员信息读权限
根据手机号获取成员基本信息权限
通讯录部门成员读权限
![-w500](../media/17795482410730/798e88ab20186046fff69e460d2916c1.png)

<div STYLE="page-break-after: always;"></div>

#### 提交钉钉应用版本

1、 在版本管理中选择创建版本:
![-w400](../media/17795482410730/a698cc0f172fea53d04fa240f6d6e70e.png)

2、 在可用范围选择为所有员工或指定员工该范围决定哪些用户能看到和使用钉钉应用:
![-w400](../media/17795482410730/0bb7e391a884719528b157d13b4c9158.png)

3、 提交发布:
![-w400](../media/17795482410730/0cc1c701d7651b8b5fffe82f9e3bcba2.png)

<div STYLE="page-break-after: always;"></div>

### 同步钉钉账号及群组

1、 登录 DSM Pass 点击同步以获取飞书账号及群组至NAS:
![-w500](../media/17795482410730/cd4bba6efc775873d84cc15057e9af19.png)

2、 前往NAS的控制面板->用户与群组中，确认账号与群组是否正确:
![-w400](../media/17795482410730/f5ac64896a4324e451988a56178c7828.png)

<div STYLE="page-break-after: always;"></div>

### 测试钉钉单点登录

1、在 DSM Pass 的钉钉应用中复制页面显示的`Launch`地址:
![-w500](../media/17795482410730/50211b5d765f89ba385c666dcc786c5a.png)

2、访问`Launch`地址会跳转至钉钉登录页面进行扫描登录:
![-w400](../media/17795482410730/72bfee48246df2bd3e52d8f1673d28ed.png)

<div STYLE="page-break-after: always;"></div>

3、如果没有信任过NAS的https则需要先打开DSM页面进行证书信任，然后再点击继续登录。
![-w300](../media/17795482410730/17800355308190.jpg)

点击打开DSM证书页面，选择信任继续前往:
![-w300](../media/17795482410730/17800356762727.jpg)

看到登录页面后关闭该登录页面：
![-w300](../media/17795482410730/17800356970670.jpg)

<div STYLE="page-break-after: always;"></div>

然后点击已信任继续登录:
![-w400](../media/17795482410730/17800355308190.jpg)

4、 如果有配置信任HTTPS证书则会直接登录到NAS，如果需要使用SMB则在右上角用户的个人设置中进行密码修改，当前密码为DSM Pass中配置的初始密码:
![-w500](../media/17795482410730/75fcc73feafcf8255c6eaa6a5ae5d614.png)

<div STYLE="page-break-after: always;"></div>

## 同步设计

### 用户处理

#### 用户名限制

系统保留名称限制（完全禁止，不区分大小写）:
`admin root guest`

特殊字符与格式限制:
非法的首尾字符: 用户名不能以减号或空格开头，也不能以空格结尾。
非法特殊字符包含以下任何一种字符的名称都会被拦截：
```
!"#$%&'()*+,/:;<=>?@[\]^`{}|~
```
不允许空字符作为用户名或群组名。

长度限制
长度不能超过64个字符。

![-w500](../media/17795482410730/1d5183aaf48e61524e3d463bc9ef8c5a.png)

<div STYLE="page-break-after: always;"></div>

#### 用户部门映射

如果身份源用户在不同部门或者在子部门下，DSM Pass同步后会将DSM 用户加入所有的所在部门以及父部门。
例如 aatest2 在test以及sup1部门:
![-w500](../media/17795482410730/8efa0c8d0eda38ab9676097cc413acda.png)

DSM同步后的用户会加入test、sup1部门，以及test的父部门marketing:
![-w450](../media/17795482410730/146c299a5036fd1838dc1deab84fde11.png)

<div STYLE="page-break-after: always;"></div>

#### DSM 已有同名用户

如果身份源只有一个用户映射到某个 DSM 用户名，而 DSM 本地已经有这个同名用户，DSM Pass 会直接建立身份源用户和 DSM 用户的映射，并把状态标记为「已关联」。这种情况不是冲突，不会要求管理员改名，也不会新建另一个 DSM 用户。
后续同步只要映射关系已经存在，也不会因为飞书新增同名用户而反复把已有映射改写成冲突。

#### 身份源包含同名用户

DSM 本地用户不支持身份源的同名用户功能。DSM Pass 的处理规则是:如果遇到用户重名会先生成临时用户名并标记为冲突，等待管理员确认。
管理员可以参考身份源姓名、邮箱、手机号、身份 ID 和所属部门，手动指定最终 DSM 用户名。可以保留其中一个原名，也可以两个都改名；保存后该记录会进入「待开通」，后续可重新同步或手动开通。
如果 DSM Pass 数据库里已经有另一个身份源占用了同一个 DSM 用户名，页面会标记为「已被其他身份占用」，管理员需要决定修改哪一条或两条都修改。
![-w500](../media/17795482410730/e7688899d99efbc235b5c5b418ac1a0a.png)

<div STYLE="page-break-after: always;"></div>

### 部门组处理

#### 部门名称限制

系统保留名称限制（完全禁止，不区分大小写）:
`admin`、`administrators`

特殊字符与格式限制:
非法的首尾字符: 用户组不能以减号或空格开头，也不能以空格结尾。
非法特殊字符包含以下任何一种字符的名称都会被拦截：
```
!"#$%&'()*+,/:;<=>?@[\]^`{}|~
```
不允许空字符作为用户名或群组名。

长度限制
长度不能超过32个字符。

![-w500](../media/17795482410730/4f4acb3147e425a35c87bd74c6dc1d85.png)

<div STYLE="page-break-after: always;"></div>

#### 身份源包含同名部门

DSM 本地群组不支持飞书那种同名部门层级。DSM Pass 的处理规则是：如果遇到部门名重名会先生成临时路径名并标记为冲突，等待管理员确认。
同名部门不会自动开通。打开身份源详情时如果还有冲突，页面会弹出冲突处理窗口；管理员可以在同一个窗口里先参考飞书部门路径，把其中任意一个或多个改成最终 DSM 部门组名。冲突部门处理完成前，同步不会继续开通 DSM 用户和成员关系，避免权限落到错误部门。

![-w500](../media/17795482410730/c2dfefc32c340cacff936464c81e59cf.png)

<div STYLE="page-break-after: always;"></div>


## 系统设置

### 入口与域名

查看管理页面的端口，配置认证端口与协议:
如果修改 DSM Pass 的 IDP 协议、访问域名或 IDP 端口，需要同步更新身份源的主页地址和回调地址，并重新发布应用。
![-w500](../media/17795482410730/46db99559a2f26db158a846bb45ae07d.png)

### DSM 登录链路

查看认证成功后浏览器跳转的DSM地址以及配置登录超时时间:
![-w500](../media/17795482410730/29746764f38fb6abe221f46e9f21f6a0.png)

<div STYLE="page-break-after: always;"></div>

### 访问安全

限制管理后台页面允许哪些来源IP访问：
![-w500](../media/17795482410730/974676e07b70702bd304684decd63b90.png)

### 证书与路由

配置管理端以及认证端的证书:
![-w500](../media/17795482410730/8221924fcba8f12cedd39020de77ae1f.png)
