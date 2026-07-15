# 企业微信和钉钉身份源开发计划

本文档记录为 DSM Pass 新增企业微信和钉钉身份源的开发计划。目标是让两类身份源具备与飞书相同的能力：OAuth 登录 DSM、通讯录用户/部门/成员同步、身份源级登录和同步开关、冲突处理、登录审计和同步日志。

## 任务边界

当前系统只支持 `feishu` provider，后端登录回调、通讯录同步、前端配置页和部分冲突提示存在飞书绑定点。

本次目标：

- 新增 `wecom` provider，展示名为「企业微信」。
- 新增 `dingtalk` provider，展示名为「钉钉」。
- 复用现有 DSM 用户开通、部门组开通、登录中继、审计和同步进度机制。
- 保持飞书现有行为不变。

本次不做：

- 不改 DSM Helper 的权限模型、登录中继协议和 Cookie 写入逻辑。
- 不引入新框架或无关依赖。
- 不升级无关依赖。
- 不重构无关页面和构建脚本。
- 不提交真实 App Secret、OAuth token、DSM SID、Cookie、临时密码或生产截图。

## 现有代码边界

provider 只负责外部身份系统：

- 生成外部授权地址。
- 用授权码换取 token。
- 获取外部用户资料。
- 拉取外部通讯录用户、部门和成员关系。
- 转换为 DSM Pass 的中间模型。

provider 不负责：

- 操作 DSM 用户或群组。
- 生成 DSM 用户名。
- 合并身份映射。
- 写 DSM Cookie。
- 执行系统命令。
- 记录或返回密钥。

相关文件：

- `go/internal/provider/provider.go`
- `go/internal/provider/feishu.go`
- `go/internal/backend/relay_handlers.go`
- `go/internal/backend/source_config.go`
- `go/internal/backend/provider_types.go`
- `go/internal/syncsvc/sync.go`
- `frontend/src/App.tsx`
- `frontend/src/types.ts`

## PR 拆分

### PR 1：泛化 OAuth 身份源框架

建议分支：

```bash
git checkout main
git pull jiyoutech main
git checkout -b refactor/generalize-oauth-providers
```

建议标题：

```txt
refactor: generalize oauth identity providers
```

目标：

- 抽出通用 OAuth provider 接口。
- 将飞书登录回调改为通用 OAuth 回调流程。
- 飞书实现迁移到通用接口下，行为保持不变。
- 将前端和同步冲突中的明显飞书绑定文案改为根据 provider 自动显示平台名。

后端实现要点：

- 在 `go/internal/provider/provider.go` 增加登录 provider 接口。
- 在后端增加 provider 工厂，通过 `identity_sources.provider_type` 选择登录和目录 provider。
- 将 `handleFeishuCallback` 拆成通用 `handleOAuthCallback`，保留状态校验、身份解析、Helper 登录中继、审计等现有逻辑。
- 将诊断事件名从强绑定飞书改成通用 provider 事件，事件字段保留 `provider_type` 和 `provider_slug`。
- 保留飞书 `BuildAuthorizeURL`、`ExchangeCode`、`FetchProfile`、subject 选择逻辑。

前端实现要点：

- 通过 provider type label 显示身份源类型。
- 将「飞书身份」「飞书部门」「飞书内重名」改成根据 provider 自动显示「飞书 / 企业微信 / 钉钉」。
- 地址页 tab 不固定显示「飞书」。

测试：

- 飞书授权 URL 参数不变。
- callback 使用受信任 `public_base_url`。
- 飞书 profile subject 选择顺序不变。
- provider type API 仍返回飞书。
- 前端构建通过。

### PR 2：新增企业微信 provider

建议分支：

```bash
git checkout main
git pull jiyoutech main
git checkout -b feat/add-wecom-provider
```

建议标题：

```txt
feat: add wecom identity provider
```

目标：

- 支持企业微信 OAuth 登录 DSM。
- 支持企业微信通讯录用户、部门、成员同步。
- 支持在管理后台创建和编辑企业微信身份源。

后端实现要点：

- 新增 `go/internal/provider/wecom.go`。
- 新增 `go/internal/provider/wecom_test.go`。
- 注册 `provider_type = "wecom"`。
- 配置项复用 `client_id` 和 `client_secret`，其中 `client_id` 对应企业微信 `CorpID`，`client_secret` 对应应用 Secret。
- 新增 `agent_id` 配置，用于企业微信授权地址。
- subject 建议使用企业微信 `UserId`，subject type 为 `wecom_userid`。
- 目录同步将企业微信部门转换为 `provider.Group`，用户转换为 `provider.User`。
- 错误解析包含企业微信错误码和可操作建议，不输出 secret/token。

企业微信前置配置：

- 企业微信后台需要配置可信域名 / OAuth 回调域名，且必须与 DSM Pass 生成的 Callback 域名一致。
- 调用企业微信服务端接口前，需要按企业微信后台要求配置可信 IP；生产部署时应填写 DSM Pass 后端实际出口公网 IP。
- 如果 DSM Pass 部署在反向代理或 NAT 后面，文档和 UI 需要提醒管理员确认「用户访问域名」「企业微信回调域名」「后端出口 IP」分别对应正确的入口和出口。
- 这些属于身份源平台配置和部署前置条件，不需要新增数据库表；后续可在前端配置说明中展示提醒。

官方文档复核项：

- 构造网页授权链接：`https://developer.work.weixin.qq.com/document/path/91022`
- 获取访问用户身份：`https://developer.work.weixin.qq.com/document/path/91023`
- 获取 access_token：`https://developer.work.weixin.qq.com/document/path/91039`

测试：

- 授权 URL 包含 `appid`、`agentid`、`redirect_uri`、`state`。
- access token 请求使用 `corpid` 和 `corpsecret`。
- 回调 code 能解析稳定 `UserId`。
- 部门树路径稳定。
- 用户多部门归属能写入 `DepartmentSubjects`。
- API 错误信息不泄漏 secret/token。

### PR 3：新增钉钉 provider

建议分支：

```bash
git checkout main
git pull jiyoutech main
git checkout -b feat/add-dingtalk-provider
```

建议标题：

```txt
feat: add dingtalk identity provider
```

目标：

- 支持钉钉 OAuth 登录 DSM。
- 支持钉钉通讯录用户、部门、成员同步。
- 支持在管理后台创建和编辑钉钉身份源。

后端实现要点：

- 新增 `go/internal/provider/dingtalk.go`。
- 新增 `go/internal/provider/dingtalk_test.go`。
- 注册 `provider_type = "dingtalk"`。
- 配置项复用 `client_id` 和 `client_secret`，对应钉钉 AppKey 和 AppSecret。
- 登录 subject 必须与通讯录用户 subject 使用同一个稳定字段。优先使用 `userid/userId`；如果实际登录接口只稳定返回 `unionid/unionId`，需要同步阶段也能映射到同一 subject 后再合并。
- 错误解析包含钉钉错误码、请求 ID 和可操作建议，不输出 secret/token。

官方文档复核项：

- 获取用户 token：`https://open.dingtalk.com/document/orgapp-server/obtain-user-token`
- 获取用户通讯录个人信息：`https://open.dingtalk.com/document/orgapp-server/dingtalk-retrieve-user-information`
- 获取企业内部应用 accessToken：`https://open.dingtalk.com/document/orgapp-server/obtain-the-access_token-of-an-internal-app`
- 获取部门列表：`https://open.dingtalk.com/document/orgapp-server/obtain-the-department-list-v2`

测试：

- 授权 URL 参数正确。
- code 换用户 token 的请求格式正确。
- 当前用户信息能解析稳定 subject。
- 企业内部应用 access token 请求格式正确。
- 部门和用户分页正确。
- 登录 subject 和同步 subject 一致。
- API 错误信息不泄漏 secret/token。

### PR 4：补充配置文档

建议分支：

```bash
git checkout main
git pull jiyoutech main
git checkout -b docs/add-wecom-dingtalk-setup
```

建议标题：

```txt
docs: add wecom and dingtalk setup guides
```

目标：

- 更新 README 支持能力表。
- 增加企业微信和钉钉配置步骤。
- 更新测试说明和 provider 开发文档。

候选文件：

- `README.md`
- `docs/README.md`
- `docs/provider-development.md`
- `docs/testing.md`
- `docs/spk-wecom-setup.md`
- `docs/spk-dingtalk-setup.md`

测试：

```bash
scripts/test.sh docs
```

## 当前进展

- PR 1 泛化 OAuth 身份源框架已完成，当前分支提交为 `9c1409b refactor: generalize oauth identity providers`。
- PR 2 企业微信 provider 已进入实现阶段：后端已新增 `wecom` provider、provider-aware 配置默认值、企业微信凭据完整性判断、OAuth 登录、部门/用户/成员同步和错误提示；前端已支持企业微信 `Agent ID` 配置项。
- 企业微信真实联调需要管理员在企业微信后台准备 `CorpID`、自建应用 `Agent ID`、应用 Secret、可信域名/OAuth 回调域名，以及 DSMPASS 后端出口公网 IP 的可信 IP 配置。
- mock 单元测试覆盖授权 URL、code 换 UserId、部门路径、用户多部门合并和可信 IP 错误提示。真实联调通过前，不应宣称企业微信生产配置已验证完成。
- 钉钉 provider 尚未开始实现。

## 执行顺序

1. 先做 PR 1，确保飞书行为不变，并降低后续 provider 复制登录中继逻辑的风险。
2. 再做企业微信。企业微信 subject 与通讯录 subject 相对清晰，适合作为第一个新增 provider。
3. 再做钉钉。钉钉必须先用真实应用确认登录 subject 和通讯录 subject 的一致性。
4. 最后写配置文档，避免文档提前承诺未验证行为。

## 验收标准

每个 provider 合并前必须满足：

- 可以创建身份源。
- 可以生成正确的 Launch 和 Callback 地址。
- OAuth 登录后能解析稳定外部 subject。
- 通讯录同步能写入用户、部门、成员关系。
- DSM 用户、部门组和成员开通仍走现有后端与 Helper 流程。
- 冲突处理页面不显示错误平台名称。
- 登录审计按 provider slug 记录。
- 不泄漏 secret/token 到响应体、同步日志或公开文档。
- 飞书现有测试全部通过。

## 验证命令

后端变更：

```bash
cd go
GOCACHE="$PWD/.gocache" GOMODCACHE="$PWD/.gomodcache" go test ./...
```

前端变更：

```bash
cd frontend
npm run build
```

文档变更：

```bash
scripts/test.sh docs
```

发布前建议：

```bash
make test
```

## 风险说明

- 钉钉登录身份字段和通讯录身份字段可能不一致。该问题必须在真实钉钉企业内部应用中验证，否则不能标记为 Ready。
- 企业微信需要 `agent_id`。优先放入现有 `config_json`，除非实现中发现现有配置结构无法安全表达。
- 新 provider 会增加外部 API 错误面。错误消息必须可操作，但不能包含密钥、token 或完整敏感响应。
- 通用化 OAuth 回调时必须避免改变飞书现有状态校验、redirect URI 构造和 DSM 登录中继行为。
- 前端文案泛化要避免大规模 UI 重排，保持可审查。

## Reviewer 重点关注

- 飞书行为是否完全回归。
- OAuth state、redirect URI 和 trusted public base URL 是否仍然安全。
- 新 provider 的 subject 是否稳定，且登录与同步一致。
- provider 是否严格限制在外部身份系统边界内。
- 日志和错误响应是否有敏感信息泄漏。
