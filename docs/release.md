# 发布检查清单

发布 GitHub 版本前按这份清单检查。

## 仓库卫生

- `git status --short` 里只有本项目预期文件。
- 没有把父目录、临时目录或本机环境文件加入提交。
- 没有 `.env`、数据库、日志、TLS 私钥、token、SID、临时密码或 shadow 内容。
- 没有真实企业名称、用户信息、内网地址、域名或部署拓扑。
- `CHANGELOG.md` 已经包含当前发布版本。
- 安装、升级、端口、协议或安全行为变化已经同步到 `README.md` 和 `docs/`。
- 已按 [`publication-guidelines.md`](publication-guidelines.md) 检查公开范围。

## 验证

执行：

```bash
make test
DSMPASS_VERSION=<version> make package-spk
```

测试入口和覆盖范围见 [`testing.md`](testing.md)。

确认产物存在：

```text
go/dist/dsm/DSMPASS-<version>-linux-amd64.spk
go/dist/dsm/DSMPASS-<version>-linux-arm64.spk
go/dist/dsm/SHA256SUMS
```

## DSM 冒烟测试

在测试 DSM 7 主机上验证：

1. 按 NAS 架构安装 amd64 或 arm64 SPK。
2. 选择大于 `1024` 的管理后台端口。
3. 使用 HTTPS 打开管理后台。
4. 完成后台账号初始化。
5. 配置 IDP 协议和 IDP 端口。
6. 创建飞书身份源。
7. 确认生成的 `/idp/<source>/launch` 地址使用已配置的 IDP 协议和端口。
8. 切换 IDP 协议或端口，确认只重启 IDP listener，管理后台不重启。
9. 确认 DSM 默认跳转端口：
   - HTTP -> `5000`
   - HTTPS -> `5001`
10. 覆盖升级已安装套件，确认数据保留。
11. 卸载时选择保留套件数据，确认数据仍在。
12. 在一次性测试环境里选择删除套件数据，确认数据被删除。

## 发布说明

发布说明应包含：

- 版本号
- 支持的 DSM 版本
- 支持的 CPU 架构
- 两个 SPK 文件的下载链接
- `SHA256SUMS`
- 升级说明
- 安全说明
- 已知限制

## 当前已知限制

- 项目处于 pre-1.0 阶段，应先在非生产 DSM 上验证。
- 当前一方身份源只实现了飞书。
- DSM 登录中继会触碰敏感账号状态，需要严格控制 Helper 权限和日志。
- 管理后台通常只应在内网开放。
