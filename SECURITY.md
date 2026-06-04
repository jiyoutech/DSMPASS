# 安全策略

## 敏感数据

不要提交或公开以下内容：

- 身份源应用密钥，例如飞书 `App Secret`
- OAuth access token、refresh token 或 ID token
- DSM SID、Cookie 或 Synology token
- 临时密码
- `/etc/shadow` 原文、片段或哈希
- Helper HMAC 密钥
- 生产环境 TLS 私钥
- 真实用户、组织、域名、内网 IP、日志和数据库

## 生产环境要求

启动服务前必须配置强随机 Helper 密钥：

```bash
export DSMPASS_HELPER_HMAC_SECRET="$(openssl rand -hex 32)"
```

除非正在排障，否则保持诊断日志关闭：

```bash
export DSMPASS_LOGIN_DIAGNOSTICS=false
```

诊断日志默认会脱敏，但仍会暴露运行流程、请求路径和错误状态，应按敏感运行数据处理。

## Helper 边界

后端进程不应以 root 权限运行。涉及 DSM 本地账号、群组和登录中继的高权限操作必须限制在 Helper 进程内。Helper 必须满足：

- 只监听本机 Unix Socket
- 校验 HMAC 签名请求
- 对用户和关键系统状态做互斥保护
- 记录必要恢复状态
- 启动时恢复未完成操作

## 登录中继风险

DSM 登录中继会触碰本地账号状态，属于高风险系统集成能力。生产环境应只部署在可信网络中，或放在可信 HTTPS 反向代理之后，并限制管理后台访问范围。

## 漏洞报告

发现安全问题时，请先私下联系维护者，不要在公开 issue、讨论区或日志附件里披露可利用细节、真实密钥、Cookie、token、SID 或用户数据。
