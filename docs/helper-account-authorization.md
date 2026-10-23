# Helper 账号授权边界

HMAC 只证明请求持有套件密钥，不证明目标 DSM 账号允许被 DSMPASS 管理。后端拥有数据库写权限，因此仅增加数据库查询不能隔离后端被入侵后的影响。

本次将两种检查同时放在 Helper 边界：

- 登录要求 `identity_id`、`login_source`、DSM 用户名对应同一个有效用户映射；身份源、外部账号、内部身份、登录许可和创建状态均须有效。`managed=0` 表示手工命名，不代表账号未受管，不以此字段判断授权。
- `/var/lib/dsmpass/account-policy.json` 由 root 独立保存用户名/UID 和群组名/GID。套件用户无法修改。已有账号和群组必须由 root 明确登记；新账号/群组仅在 Helper 创建成功并重新查询系统身份后登记。
- 实际属于 `administrators` 的用户、UID 小于 1024 的系统账号、特权主组、系统群组、无效名称均禁止。读取系统账号信息有歧义或授权文件损坏时拒绝操作。账号改名或 UID/GID 改变后必须重新授权。
- 兼容 DSM 账号文件中的注释、空行及无关系统账号共用 UID；目标账号自身的 UID、目标群组自身的 GID 有别名歧义时仍拒绝。管理员组的 GID 别名同样按管理员权限检查。
- 登录写 shadow、永久改密、启用/修改/停用账号及群组成员操作均检查独立授权。检查在相应账号锁或全局写锁内再次进行。密码恢复不因撤销授权而被阻断。
- 群组移除使用固定 `/usr/syno/bin/synowebapi` 的 `SYNO.Core.Group.Member.remove` 接口，并检查 JSON 成功字段；DSM 没有 `synogroup --memberdel`。应用只提交需要移除的成员，不读取整组名单后覆盖其余成员。
- root 进程不直接打开套件可写的 SQLite 数据库。固定 Helper 二进制以套件 UID/GID、空附加组和清理后的环境启动查询子进程，使用只读连接；父进程限制时间和输出。数据库校验仍不是独立可信的身份证明，root 授权名单才限制其操作范围。
- 写操作改用 `scoped_*` 协议名，旧 Helper 无法接受新客户端请求，不会忽略新增授权字段后继续写入。恢复请求保留，便于完成已开始的恢复。

## 已有安装迁移

先按 [部署说明](go-dsm-binary-deployment.md) 停止旧 Helper、确认临时密码恢复并安装受保护的 Helper。然后由管理员在 root shell 中对实际需要接管的普通账号和自定义群组逐个执行以下命令，将示例名称替换为实际名称：

```sh
/usr/local/libexec/dsmpass/dsmpass-helper authorize-user alice
/usr/local/libexec/dsmpass/dsmpass-helper authorize-group engineering
```

该命令不能通过套件的免密 sudo 控制入口调用，也没有对应的 socket 操作。禁止将后端数据库导出的名单自动全部批准，因为它不是独立授权来源。已有但未批准的账号会显示授权错误，不会自动重置密码或接管。

撤销使用 `revoke-user alice` 或 `revoke-group engineering`。撤销用户先保存拒绝策略，再恢复其尚未结束的临时密码；若锁正被占用或恢复失败，命令会报错，需要处理后重试。已经建立的 DSM 会话不会因此自动退出。

## 复查与验证范围

重点审查 `account_policy.go`、`authorization.go`、`group_commands.go`、`account_commands.go`、`sync_password.go` 和查询子进程 `cmd/helper/account_query.go`。测试覆盖身份/来源不匹配、失效映射、管理员组成员、UID/GID 改变、授权文件异常、旧协议拒绝、已有账号拒绝接管、新建账号登记和撤销后的恢复。

本地使用隔离账号文件、假 DSM 命令和临时 SQLite 验证；Linux 交叉编译与 CI 不能代替 DSM 实机的安装迁移和系统命令测试。旧数据迁移、不同 DSM 的系统组布局及真实降权查询仍须在测试 NAS 验证，因此保持 Draft PR，不自动部署。

后端被完全控制时，攻击者仍可请求操作已经登记的普通账号、创建新的普通账号以及修改受管群组成员；后端也持有业务数据。这项修改限制受影响的账号范围，不宣称后端失陷对 DSM 毫无影响。管理员后来授予受管账号额外共享权限时，这些权限也属于受影响范围。系统管理员并发修改账号不受本项目锁约束，保留 shadow 恢复时的身份与当前值检查。
