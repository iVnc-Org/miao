# 构建与验证

[文档目录](README.md)

## 本地构建

需要 Git、Rust/Cargo、Node.js/npm，以及满足目标 sing-box 源码 `go.mod` 要求的 Go 版本。在 Linux amd64/arm64 上运行：

```bash
bash build.sh
```

脚本校验固定的 sing-box 源码提交、构建内核和前端，再编译 Miao；产物为 `target/release/miao-rust`。需要访问源码与依赖下载地址。跨架构发布流程见 [GitHub Actions](../.github/workflows/)。

## 内嵌内核

内核固定为 sing-box **1.14.4**，版本、提交和构建标签统一维护在 [`scripts/sing-box.env`](../scripts/sing-box.env)。本地与 CI 均校验提交，启用 QUIC、Clash API 和 uTLS，并注入版本号。版本 API 返回内核构建信息，顶部提交标记的悬浮提示也可查看。释放内核和规则文件时会比对 SHA256，以原子替换方式更新旧文件。

## 自动验证

准备好前端和内核资源后：

```bash
npm --prefix frontend test
npm --prefix frontend run lint
npm --prefix frontend run build
cargo test
python3 -m pip install 'PyYAML==6.0.2'
MIAO_TEST_SING_BOX="$PWD/embedded/sing-box-amd64" \
  python3 -m unittest discover -s scripts/tests -p '*_test.py' -v
```

Python 部署测试隔离路径与系统命令，不访问真实 VPS，可由普通用户运行。夹具只模拟临时目录中的 root 属主，保留真实文件类型和权限检查；覆盖锁竞争、超时、复用、错误属主和危险权限。

可在准备好前端和 `embedded/` 资源后运行 `cargo test`。额外的本地连接测试需要 `openssl`，仅启动回环地址上的临时服务，覆盖 SOCKS5、HTTPS CONNECT、Hysteria2、TUIC 和 VLESS Reality：

```bash
MIAO_TEST_SING_BOX="$PWD/embedded/sing-box-amd64" cargo test -- --include-ignored --skip private_subscription_acceptance
```

这也会验证全局、进程黑/白名单及代理池配置能被目标内核接受。私有样本验收单独运行，样本不进入仓库、不输出节点凭据：

```bash
MIAO_TEST_SUBSCRIPTION=/tmp/sub.txt MIAO_TEST_SING_BOX="$PWD/embedded/sing-box-amd64" \
  cargo test private_subscription_acceptance -- --ignored
```

arm64 主机请将上述 `sing-box-amd64` 替换为 `sing-box-arm64`。真实 VPS 的发行版、初始化系统与架构组合仍需独立验收，回环测试不能代替 release 服务端验收。
