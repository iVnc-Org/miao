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

透明代理验收需要 root、iproute2、iptables、curl、dnsmasq-base、nftables 和 mount/network namespace 支持，直接测试构建出的二进制：

```bash
sudo python3 scripts/tests/openwrt_runtime_test.py --simulate-fw3 \
  --dnsmasq-binary /usr/sbin/dnsmasq \
  --binary "$PWD/target/x86_64-unknown-linux-musl/release/miao-rust"
sudo python3 scripts/tests/openwrt_runtime_test.py --simulate-fw4 --external-system-dns \
  --dnsmasq-binary /usr/sbin/dnsmasq \
  --binary "$PWD/target/x86_64-unknown-linux-musl/release/miao-rust"
```

测试将路由器、WAN SOCKS/DNS 服务端和 LAN 客户端放进独立命名空间，并通过私有挂载隔离账户数据。另设只有独立策略路由表可达的 VPN 节点，验证原生 nftables 接管不会错误绑定默认网卡，覆盖旧运行配置与管理器重启。验证首次网页启动、两种接管策略、本机/LAN TCP/UDP/DNS（含 TCP DNS）、进程名单、fw3 规则恢复、失败回滚、代理池、缓存迁移、状态恢复与取消，以及内核和管理器被强制结束后的资源回收。所有服务端均为本地夹具，不访问公网；前后比较宿主路由和防火墙。OpenWrt 真机运行时可省略 `--simulate-fw3`，使用实际 fw3 程序。

Node 25/26 开启实验性全局 Web Storage 时，部分测试环境需要 `NODE_OPTIONS=--no-experimental-webstorage npm --prefix frontend test`；CI 的 Node 20 不需要此参数。

`--dnsmasq-binary` 启用真实 dnsmasq 和独立的服务管理夹具：先缓存模拟上游返回的错误 Google 地址，验证接管后 UDP/TCP 与 LAN 查询、本地 DHCP 名称、上游互斥、停止恢复、配置归属冲突、重启失败和取消。模拟核心就绪期间配置重新生成，验证完整复检允许安全更新，同时拒绝新出现的竞争上游。分别强制结束核心及管理器，在重启 Miao 前验证独立守护恢复系统 DNS、策略路由与 fw3 规则。`/etc` 使用私有副本；测试不启动宿主 DNS 服务，也不改宿主配置。CI 安装不带服务启动的 `dnsmasq-base` 包。

`--external-system-dns` 将系统默认解析器设为模拟 Tailscale IPv4/IPv6 地址，验证 UDP/TCP 都不能绕过保护，同时保留私有域的 A 与 ULA AAAA。覆盖同名外部 nft 表、运行中表被替换、故障停止保留核心、WAN DNS 变化及退出后的独立回收。此选项需要 nft 工具；CI 在 fw4 别名套件中启用。

`--simulate-fw4` 在私有 PATH 中创建 `fw3 -> fw4`，验证兼容入口不会产生旧 iptables 规则。可附加 `--subscription-file /tmp/sub.txt`，通过本地 HTTP 夹具和粘贴接口验证私有订阅导入、重启和删除；仅输出节点计数，失败时隐藏运行日志。私有内容不加入仓库。

接管策略由系统自动检测；隔离验收通过诊断环境变量模拟缺少 nftables 的主机，并验证旧 YAML/HTTP 手动选择会迁移到自动适配，覆盖缓存迁移与运行状态恢复。前端验证没有接管选择器、停止后不显示旧接管方式为活动状态，且启动期间可以取消。
