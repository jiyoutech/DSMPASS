# 贡献指南

## 开发环境

```bash
cd frontend
npm ci
npm run build

cd ../go
GOCACHE="$PWD/.gocache" go test ./...
```

## 基本规则

- 不提交密钥、token、DSM Cookie、SID、临时密码、shadow 内容、日志或数据库。
- DSM 高权限操作必须留在 Helper 边界内，后端和前端不要绕过 Helper。
- 修改后端行为、Helper 安全逻辑或身份源解析时，需要补测试。
- 诊断日志必须脱敏。
- 新增前端身份源选项时，必须同步后端 provider type API，避免前后端配置不一致。
- 面向公开仓库的文档只写通用步骤和示例值，不写真实部署信息。

## PR 检查清单

- `make test` 通过。
- 修改套件脚本、启动脚本或 DSM 安装行为时，`make package-spk` 通过。
- 行为、配置或安装流程变化时，同步更新 `README.md` 和 `docs/`。
- 安全敏感日志已经脱敏。
- 新运行时配置已经同步到 `.env.example`。
- 用户可感知变更已经写入 `CHANGELOG.md`。
- 发布前按 [`docs/publication-guidelines.md`](docs/publication-guidelines.md) 检查公开范围。
