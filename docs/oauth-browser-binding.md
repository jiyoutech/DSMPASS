# OAuth 回调的浏览器绑定

旧实现保存随机 `state` 并检查来源、过期和一次性消费，但没有记录发起登录的浏览器。攻击者在自己的浏览器发起授权后，将完整 callback 链接转给另一浏览器，服务器无法仅凭 state 区分这两者。这属于登录 CSRF 风险；HMAC 的 Helper 通信签名不能解决浏览器回调归属。

Launch 现在一次生成独立的 128 位 state 和 256 位浏览器随机值。state 进入授权 URL；浏览器随机值只写入 HttpOnly Cookie，服务端保存其 SHA-256 摘要。随机生成失败直接拒绝，不使用时间戳回退。

每次登录使用不同 Cookie 名称，多标签页不覆盖。Cookie 有效期为 10 分钟，SameSite=Lax、Path=/、无 Domain；HTTPS 使用 Secure 和 `__Host-` 前缀。显式 HTTP 模式仍可使用浏览器绑定，但不能抵御链路窃听或篡改。

回调在交换 code、调用 Helper 之前，原子检查身份源、有效期以及 Cookie 摘要。缺少 Cookie、另一个浏览器、重复同名 Cookie 或重复 state 参数均失败。验证失败不消费其他浏览器的有效 state；成功仅允许消费一次，并清理对应 Cookie。Launch/callback 禁止缓存并设置 no-referrer。

需要在发起登录的同一个浏览器完成回调。跨设备复制 callback 链接、外部浏览器与企业应用内浏览器之间切换、禁用 Cookie 时，用户会收到重新发起登录的提示。企业微信/飞书/钉钉各自的扫码和内置浏览器行为还需要实测；此变更不修改提供方协议，也不宣称覆盖所有类型的 OAuth 中继攻击。

测试覆盖跨浏览器拒绝且原流程仍可继续、过期、重放、错源、Cookie/参数重复、并发回调只成功一次、多标签页和随机源失败。路由测试验证 Launch 设置 Cookie、无绑定回调在 code 交换前被拒绝、正确浏览器进入后续校验，且响应清理 Cookie。测试不连接真实身份源或 NAS。

## 本轮复查入口

本轮分为三个依赖的 Draft PR：受保护的 Helper 启动链、[Helper 账号授权](helper-account-authorization.md)、本文的 OAuth 浏览器绑定。检查全部改动时，用 `fix/oauth-browser-state-binding` 分支相对 `main` 的差异；按问题单独检查时使用各 PR 的 diff。版本仍为 0.8.49，未自动合并、部署或发布新 SPK。

除了自动化测试，请重点复核固定路径和 sudo 参数约束、已有授权迁移、实际 DSM 管理员成员识别、账号/群组写入口完整性，以及 Cookie 在真实身份源扫码回调中的保留情况。
