#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

usage() {
  cat <<'EOF'
用法:
  scripts/test.sh [all|go|frontend|docs]

说明:
  all       运行 Go 单元测试、前端构建和文档公开检查
  go        只运行 Go 单元测试
  frontend  只运行前端类型检查和构建
  docs      只运行文档公开检查
EOF
}

log() {
  printf '\n==> %s\n' "$1"
}

fail() {
  printf '错误: %s\n' "$1" >&2
  exit 1
}

scan() {
  pattern=$1
  shift
  if command -v rg >/dev/null 2>&1; then
    rg -n "$pattern" "$@"
  else
    grep -RInE "$pattern" "$@"
  fi
}

run_go_tests() {
  log "运行 Go 单元测试"
  cd "$ROOT_DIR/go"
  GOCACHE="${GOCACHE:-$PWD/.gocache}" go test ./...
}

run_frontend_build() {
  log "运行前端构建"
  cd "$ROOT_DIR/frontend"
  if [ ! -d node_modules ]; then
    fail "frontend/node_modules 不存在，请先运行 make frontend-install 或 cd frontend && npm ci"
  fi
  npm run build
}

check_docs_required_files() {
  log "检查公开文档清单"
  for file in \
    README.md \
    SECURITY.md \
    CONTRIBUTING.md \
    CHANGELOG.md \
    docs/README.md \
    docs/publication-guidelines.md \
    docs/spk-feishu-setup.md \
    docs/dsm-spk-package.md \
    docs/go-dsm-binary-deployment.md \
    docs/go-version.md \
    docs/provider-development.md \
    docs/testing.md \
    docs/release.md
  do
    [ -f "$ROOT_DIR/$file" ] || fail "缺少文档: $file"
  done
}

check_docs_removed_refs() {
  log "检查已删除内部文档引用"
  if scan 'admin-console-functional-design|dsm-cookie-relay-mode|Cookie Relay Mode|Admin Console Functional Design|backend/app/providers/base\.py|legacy-python' \
    "$ROOT_DIR/README.md" "$ROOT_DIR/SECURITY.md" "$ROOT_DIR/CONTRIBUTING.md" "$ROOT_DIR/CHANGELOG.md" "$ROOT_DIR/docs" >/tmp/dsmpass-doc-removed-refs.txt
  then
    cat /tmp/dsmpass-doc-removed-refs.txt >&2
    fail "发现不应公开的内部文档引用"
  fi
}

check_docs_sensitive_examples() {
  log "检查明显敏感内容"
  if scan '/Users/|/private/tmp|BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY|client_secret[=:][^<[:space:]]|app_secret[=:][^<[:space:]]|refresh_token[=:][^<[:space:]]|access_token[=:][^<[:space:]]|10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3}' \
    "$ROOT_DIR/README.md" "$ROOT_DIR/SECURITY.md" "$ROOT_DIR/CONTRIBUTING.md" "$ROOT_DIR/CHANGELOG.md" "$ROOT_DIR/docs" >/tmp/dsmpass-doc-sensitive.txt
  then
    cat /tmp/dsmpass-doc-sensitive.txt >&2
    fail "发现疑似真实路径、密钥或内网地址；请改成占位值"
  fi
}

check_docs_old_english_titles() {
  log "检查英文旧标题回流"
  if scan '^# (Security Policy|Contributing|Changelog|Release Checklist|Go Version|Go DSM Binary Deployment|DSM SPK Package|Provider Development|Admin Console Functional Design|DSM Cookie Relay Mode)$' \
    "$ROOT_DIR/README.md" "$ROOT_DIR/SECURITY.md" "$ROOT_DIR/CONTRIBUTING.md" "$ROOT_DIR/CHANGELOG.md" "$ROOT_DIR/docs" >/tmp/dsmpass-doc-english-titles.txt
  then
    cat /tmp/dsmpass-doc-english-titles.txt >&2
    fail "发现英文旧标题，请保持公开文档中文化"
  fi
}

run_docs_checks() {
  check_docs_required_files
  check_docs_removed_refs
  check_docs_sensitive_examples
  check_docs_old_english_titles
}

target=${1:-all}

case "$target" in
  all)
    run_go_tests
    run_frontend_build
    run_docs_checks
    ;;
  go)
    run_go_tests
    ;;
  frontend)
    run_frontend_build
    ;;
  docs)
    run_docs_checks
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
