# Miao

开箱即用的透明代理分流器，基于 sing-box 内核。单文件、零依赖，支持 Linux 与 OpenWrt。

<img width="1487" height="980" alt="image" src="https://github.com/user-attachments/assets/0466686d-54be-4192-a2c4-954a1e789b6e" />

<img width="1564" height="980" alt="image" src="https://github.com/user-attachments/assets/e1a5876f-da08-4c51-aeee-4127a36950a2" />

<img width="1460" height="968" alt="image" src="https://github.com/user-attachments/assets/a12dfbe1-4147-45a8-9c69-9b346e474141" />


## 快速开始

```bash
mkdir ~/miao && cd ~/miao
# amd64
wget https://github.com/iVnc-Org/miao/releases/download/latest/miao-rust-linux-amd64 -O miao && chmod +x miao
```

```bash
mkdir ~/miao && cd ~/miao
# arm64
wget https://github.com/iVnc-Org/miao/releases/download/latest/miao-rust-linux-arm64 -O miao && chmod +x miao
```

运行（需要 root 权限以创建 TUN 网卡）：

```bash
sudo ./miao
```

访问 `http://localhost:6161`，未设置密码时会显示初始密码设置页面，设置成功后自动进入面板；已有密码时输入密码登录。首次进入后可添加订阅链接或手动节点。初始化完成前管理接口保持锁定。

面板只有一个管理员密码，可在网页右上角修改密码或退出登录，也可通过 CLI 设置/重置：

```bash
# 交互输入两次，设置完成后退出；运行中的面板自动识别修改
sudo ./miao password set
# 明确指定配置实例；密码不会写入普通代理配置
sudo ./miao --config /etc/miao/config.yaml password set '你的新密码'
# 设置持久密码并启动
sudo ./miao --password '你的密码'
```

认证文件为配置文件同名的 `.auth.json`，明文存储密码，权限 `0600`。启动不带 `--password` 时沿用保存的密码；显式带此参数会重设密码，因此服务配置长期使用普通启动命令，避免重启覆盖网页改密。内置升级重启不会重放密码参数。登录会话有效期 7 天；改密、CLI 重置或进程重启后需要重新登录。命令行明文密码可能进入 shell 历史/进程参数，推荐交互输入。HTTP 支持保留，但不提供传输加密。详细说明见 [面板认证](docs/panel-auth.md)。

查看启动参数：

```bash
./miao --help
```

将本机 SOCKS5 入站开放到所有网卡：

```bash
sudo ./miao --socks-listen 0.0.0.0 --socks-port 1080
```

`--socks-listen` 默认是 `127.0.0.1`，`--socks-port` 默认是 `1080`。监听 `0.0.0.0` 会把代理暴露给网络中的其他设备，建议仅在可信内网或有防火墙限制时使用。

### 配置文件位置

Miao 会按以下顺序选择配置文件：

1. 命令行 `--config /path/to/config.yaml`
2. 可执行文件同目录下已有的 `config.yaml`
3. `$HOME/.miao/config.yaml`

为兼容旧部署，如果 `$HOME/.miao/config.yaml` 尚不存在但 `/etc/miao/config.yaml` 已存在，Miao 会继续使用 `/etc/miao/config.yaml`。新安装及后续通过面板创建的默认配置均写入 `$HOME/.miao/config.yaml`。

如果启动时没有找到配置文件，Miao 只会使用内存中的默认配置并进入引导页面，不会主动写入空配置文件。只有通过面板添加订阅、添加节点、自动初始化 VPS，或其它需要持久化的配置变更时，才会写入配置文件。

所有需要跨重启保留的数据默认集中在 `$HOME/.miao`：主配置 `config.yaml`、生成配置缓存 `config.json`、缓存元数据 `config.meta.json`、订阅节点 `sub_nodes.json`、代理池端口账本 `share_ports.json`、最后选择节点 `last_proxy.json` 和运行状态 `runtime.json`。目录权限在启动时收紧为 `0700`。从旧版本升级时，Miao 会把当前工作目录 `data/cache` 中尚未迁移的文件复制到该目录，不覆盖已经存在的新文件。

网页升级在后台运行，刷新或关闭页面不会取消升级。升级请求会实际 GET 检查下载地址，GitHub 直连请求失败或在 8 秒内未收到响应头时，自动尝试在原 URL 前加上 `https://httptunnel.top/gh/`；版本元数据、SHA256 文件和程序下载均有代理回退。下载仍必须通过大小、SHA256 和程序版本校验。升级过程与结果保存在主配置同目录的 `config.upgrade.json`（自定义配置名时使用对应文件名），弹窗会在刷新后恢复，右上角显示“升级中”。重启后只有目标版本和 sing-box 恢复检查通过才显示成功；失败结果会保留到用户关闭弹窗。

sing-box 二进制和本次运行生成的 `config.json` 仍放在 `/tmp/miao-sing-box`，它们是可重建的运行产物，不属于持久化数据。Miao 重启后会从 `$HOME/.miao` 恢复上次的启动/停止状态、代理模式和节点选择；旧版 `runtime.json` 中的 `route_mode` 会被忽略。

### 订阅格式与内核

面板的“粘贴内容”支持 Clash.Meta YAML、明文 URI 列表及 Base64 编码的 URI 列表。URI 支持 `ss://`、`anytls://`、`socks5://`（或 `socks://`）、`hysteria2://`（或 `hy2://`）、TUIC v5 的 `tuic://` 和 `vless://`。VLESS 支持 TCP、WS、gRPC、HTTP/H2，以及 TLS/Reality；不支持的加密、传输或 URI 参数会明确报错，不会静默丢弃。

HTTP CONNECT 和 HTTPS CONNECT 代理自动识别，无需勾选：支持明文的 `http(s)://用户名:密码@主机:端口/#名称`，以及 `http(s)://Base64(用户名:密码@主机:端口/#名称)`。没有认证信息但带显式端口的明文地址也作为代理候选解析；普通或无法确认用途的网页链接跳过，不递归访问。Base64 解码保留原始大小写，并恢复中文节点名。成功解析不代表连通性已经验证。

部分节点无效或协议不支持时显示告警并保留成功节点；跳过普通网页、忽略 Hysteria2 的 TCP `fastopen` 参数仅在“解析详情”展示。升级后会从已保存原文重新解析旧的本地内容订阅，原子保存成功结果并重新生成配置；迁移失败保留已有节点。远程订阅保持缓存，等下一次成功刷新应用解析改进，不因升级强制联网刷新。

Hysteria2 的 `fastopen` 对 QUIC 不适用，会提示忽略；不填写带宽时沿用内核默认拥塞控制。TLS 默认验证证书，只有链接明确设置 `insecure=1` / `allow_insecure=1` 等参数才会关闭校验。

内核固定为 sing-box **1.14.4**，版本、提交和构建标签统一维护在 `scripts/sing-box.env`。本地与 CI 均校验提交，启用 QUIC、Clash API 和 uTLS，并注入版本号。版本 API 返回内核构建信息，顶部提交标记的悬浮提示也可查看。释放内核和规则文件时会比对 SHA256，以原子替换方式更新旧文件。

可在准备好前端和 `embedded/` 资源后运行 `cargo test`。额外的本地连接测试需要 `openssl`，仅启动回环地址上的临时服务，覆盖 SOCKS5、HTTPS CONNECT、Hysteria2、TUIC 和 VLESS Reality：

```bash
MIAO_TEST_SING_BOX="$PWD/embedded/sing-box-amd64" cargo test -- --include-ignored --skip private_subscription_acceptance
```

这也会验证全局、进程黑/白名单及代理池配置能被目标内核接受。私有样本验收单独运行，样本不进入仓库、不输出节点凭据：

```bash
MIAO_TEST_SUBSCRIPTION=/tmp/sub.txt MIAO_TEST_SING_BOX="$PWD/embedded/sing-box-amd64" \
  cargo test private_subscription_acceptance -- --ignored
```

### 进阶：手动编写配置文件

你也可以在 `$HOME/.miao/config.yaml`、可执行文件同目录，或兼容路径 `/etc/miao/config.yaml` 预先创建配置文件跳过引导：

```yaml
port: 6161  # Web 面板端口，默认 6161
socks_listen: 127.0.0.1  # 可选：覆盖本机 SOCKS5 监听地址，默认 127.0.0.1
socks_port: 2080  # 可选：覆盖本机 SOCKS5 端口，默认监听 127.0.0.1:1080
mode: global  # global | process | pool，三种模式互斥

# 订阅链接（支持 Clash.Meta YAML，以及 SS、AnyTLS、SOCKS5、Hysteria2、TUIC、VLESS URI 列表）
subs:
  - "https://your-subscription-url"

# 或手动配置节点（可与 subs 混合使用）
nodes:
  - '{"type":"hysteria2","tag":"HY2","server":"example.com","server_port":443,"password":"xxx","tls":{"enabled":true}}'
  - '{"type":"anytls","tag":"AnyTLS","server":"example.com","server_port":443,"password":"xxx","tls":{"enabled":true}}'
  - '{"type":"shadowsocks","tag":"SS","server":"example.com","server_port":443,"method":"2022-blake3-aes-128-gcm","password":"xxx"}'
```

miao 默认会开启一个仅本机可访问的 SOCKS5 入站，监听 `127.0.0.1:1080`。设置 `socks_port` 可以覆盖默认端口；启动参数 `--socks-listen` 和 `--socks-port` 会覆盖本次运行的监听地址和端口，但不会改写 `config.yaml`。

`mode` 默认是 `global`：除私网直连规则外，其余流量使用当前代理节点。`process` 按进程名单决定代理或直连，不做国内外分流。`pool` 不创建 TUN 入站，只保留本地 SOCKS5 入站和每个节点的独立 SOCKS5 端口。

### 进程代理

进程代理基于 sing-box TUN route rule，支持两种名单类型：

- 黑名单：名单内进程直连，其余进程使用当前代理节点。
- 白名单：仅名单内进程使用当前代理节点，其余进程直连。

进程清单填写真实可执行文件名，不是完整命令行参数。例如 `curl`、`git`、`git-remote-https`、`ssh`。`git clone https://...` 实际联网进程可能是 `git-remote-https`；`git clone git@...` 实际联网进程可能是 `ssh`。

也可以手动写入配置：

```yaml
mode: process
tun_process:
  mode: whitelist   # blacklist | whitelist
  match:
    names:
      - curl
      - git
      - git-remote-https
      - ssh
  dns_follow_process: true
  bypass_action: bypass
```

进程匹配主要适用于本机进程。部分系统的 DNS 可能由 `systemd-resolved`、`dnsmasq` 或浏览器网络服务代发，这种情况下 DNS 是否能完全跟随原始进程取决于系统行为。

### 代理池

代理池模式不会创建 TUN 入站，并会为每个节点额外监听一个独立的 SOCKS5 端口，流量固定走对应节点（不经面板当前选中的 selector）。外部客户端可用 `socks5://ip:port` 使用：

```yaml
mode: pool
share:
  listen: 0.0.0.0      # 分享端口监听地址，默认监听所有 IPv4 网卡
  base_port: 50000     # 默认起始端口；端口段和节点端口持久化到 $HOME/.miao/share_ports.json
  username: ""         # 可选；填写时需和密码同时填写
  password: ""         # 可选；填写时需和用户名同时填写
```

**鉴权**：用户名和密码可同时留空，此时代理池端口不鉴权；如需鉴权则两项必须同时填写。默认 `listen` 为 `0.0.0.0`，会向所有可达网络暴露代理池端口，请按部署环境配置防火墙或访问控制。

**端口分段**：每段最多 1000 个端口。`base_port..base_port+999` 固定分配给手动添加的节点；每个订阅从下一段开始独占一个端口段。例如起始端口为 `10000` 时，手动节点使用 `10000-10999`，订阅 A 使用 `11000-11999`，订阅 B 使用 `12000-12999`。订阅 URL 与段号会持久化，订阅重排不会改变已有订阅的端口段。

**端口稳定性**：段内端口按节点名持久分配，节点增删或订阅刷新重排都不会改变已有节点的端口。订阅临时抓取失败时不会回收端口，恢复后仍是原来的端口。修改 `base_port` 会按新布局重新分配所有端口。每组节点不会溢出到下一组，分配时会跳过面板端口、本地 SOCKS 端口和 Clash API 端口；端口段容量不足或起点超过 `65535` 时保存会报错。

**端口列表**：面板显示的端口来自已生成的 sing-box 配置，而不是分配账本，所以列出来的地址就是实际在监听的地址。每个节点旁的测试按钮会由后端通过对应 SOCKS5 端口请求 `http://3.0.3.0/`，并显示 HTTP 状态码和格式化后的 JSON 响应。

### 订阅缓存

miao 会把成功解析的订阅节点持久化到 `$HOME/.miao/sub_nodes.json`。添加订阅、替换失效链接或手动点击“刷新”时才会请求订阅链接；添加/删除手动节点、删除订阅、切换模式、启停服务和修改代理池/进程代理设置都只读取本地缓存。仅当本地一个订阅节点都没有时，启动流程才会做一次初始化抓取。

刷新失败不会删除旧节点。面板会把该订阅标记为“订阅链接已失效”，继续使用上次成功保存的节点，也不会弹出红色错误提示。停止 sing-box 后，节点清单仍由持久缓存提供；节点切换和延迟测试会保持禁用，直到服务重新启动。

上一次成功生成的完整 sing-box 配置仍会保存到 `$HOME/.miao/config.json`，`$HOME/.miao/config.meta.json` 记录当前配置指纹。升级自旧版本而 `sub_nodes.json` 尚不存在时，miao 会先从旧 `config.json` 导入其中的订阅节点，避免短时效链接已经过期后丢失现有节点。

节点选择会持久化到 `$HOME/.miao/last_proxy.json`，启动/停止状态持久化到 `$HOME/.miao/runtime.json`，代理模式持久化到 `$HOME/.miao/config.yaml`。重启后 sing-box 启动成功时，miao 会自动恢复上次选择的节点；如果订阅刷新后该节点不存在，则跳过恢复并保留默认选择。

如果订阅链接是短时效链接，建议在链接有效期内完成首次添加或手动刷新。之后只要 `$HOME/.miao` 被持久化，重启不会依赖订阅链接仍然有效。容器部署时应把 `$HOME/.miao` 挂载到持久卷。

## 实验性功能

### VPS 部署与恢复

“添加节点 → VPS 部署”支持通过 SSH 安装 Hysteria2、恢复已有 Miao 节点或迁移旧部署。支持密码/密钥认证、自定义 SSH 和节点端口、IPv6/私网/NAT 映射；进度持久化，刷新后恢复弹窗。未知部署默认保护，安装失败执行事务回滚，新节点固定信任证书。

默认放行 SSH 22/TCP 与 Hysteria2 543/UDP；安全组和防火墙不会自动修改。部署入口支持通过服务器 IP/域名使用 HTTP 或 HTTPS 访问，登录面板后直接使用，无需单独的 VPS 访问令牌。HTTP 会明文传输密码及 SSH 凭据，建议使用 HTTPS 或 SSH 隧道。SSH 凭据不保存。

原有 `vps_ip` 配置继续支持，改用同一后台引擎和本机密钥认证，SSH 期间不占配置锁，探测失败不再自动重装：

```yaml
vps_ip: "203.0.113.10"
```

详细前提、网络配置、失败恢复、访问控制和测试说明见 [VPS 部署文档](docs/vps-deployment.md)。
