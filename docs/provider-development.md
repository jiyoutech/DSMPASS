# 身份源开发

身份源 provider 负责对接外部身份系统。当前主线是 Go 实现，provider 代码位于 `go/internal/provider/`。

认证 provider 只负责外部认证：

- 生成授权 URL
- 用授权码换取 token
- 拉取外部用户资料
- 返回稳定的外部用户标识

目录 provider 只负责读取外部通讯录：

- 拉取用户
- 拉取部门或群组
- 拉取成员关系
- 把外部数据转换成 DSM Pass 的中间模型

provider 不允许做这些事：

- 直接操作 DSM
- 执行系统命令
- 读取或写入 `/etc/shadow`
- 生成 DSM 用户名
- 写 DSM Cookie
- 合并身份映射
- 保存密钥到日志或响应体

DSM 用户名分配、账号开通、群组开通、登录中继和审计都由后端服务和 Helper 边界处理，不能放进 provider。
