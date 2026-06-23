# Miao

开箱即用的透明代理分流器，基于 sing-box 内核。单文件、零依赖，支持 Linux 与 OpenWrt。

<img width="1415" height="952" alt="image" src="https://github.com/user-attachments/assets/172530bf-cb7e-4482-8dfd-ea8146c33eb0" />

## 快速开始

```bash
mkdir ~/miao && cd ~/miao
# amd64
wget https://github.com/YUxiangLuo/miao/releases/latest/download/miao-rust-linux-amd64 -O miao && chmod +x miao
```

```bash
mkdir ~/miao && cd ~/miao
# arm64
wget https://github.com/YUxiangLuo/miao/releases/latest/download/miao-rust-linux-arm64 -O miao && chmod +x miao
```

运行（需要 root 权限以创建 TUN 网卡）：

```bash
sudo ./miao
```

访问 `http://localhost:6161`，首次启动会进入引导页面，添加订阅链接或手动节点即可开始使用。

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
3. `/etc/miao/config.yaml`

如果启动时没有找到配置文件，Miao 只会使用内存中的默认配置并进入引导页面，不会主动写入空配置文件。只有通过面板添加订阅、添加节点、自动初始化 VPS，或其它需要持久化的配置变更时，才会写入配置文件。

sing-box 二进制和生成的 `config.json` 放在 `/tmp/miao-sing-box`；缓存、最后选择的节点和运行状态放在运行目录下的 `data/cache`。通过面板切换“分流/全局”不写入 `config.yaml`，但会写入运行状态；Miao 重启后会恢复上次的启动/停止状态和代理模式。配置文件中的 `route_mode` 会被忽略。

### 进阶：手动编写配置文件

你也可以在可执行文件同目录或 `/etc/miao/config.yaml` 预先创建配置文件跳过引导：

```yaml
port: 6161  # Web 面板端口，默认 6161
socks_listen: 127.0.0.1  # 可选：覆盖本机 SOCKS5 监听地址，默认 127.0.0.1
socks_port: 2080  # 可选：覆盖本机 SOCKS5 端口，默认监听 127.0.0.1:1080
route_mode: rule  # 可选：`tunnel` 为默认全量代理，`global` 保留私网直连，`rule` 为国内直连/国外代理

# 订阅链接（支持 Clash.Meta 格式，以及 ss:// / anytls:// URI 订阅）
subs:
  - "https://your-subscription-url"

# 或手动配置节点（可与 subs 混合使用）
nodes:
  - '{"type":"hysteria2","tag":"HY2","server":"example.com","server_port":443,"password":"xxx","tls":{"enabled":true}}'
  - '{"type":"anytls","tag":"AnyTLS","server":"example.com","server_port":443,"password":"xxx","tls":{"enabled":true}}'
  - '{"type":"shadowsocks","tag":"SS","server":"example.com","server_port":443,"method":"2022-blake3-aes-128-gcm","password":"xxx"}'
```

miao 默认会开启一个仅本机可访问的 SOCKS5 入站，监听 `127.0.0.1:1080`。设置 `socks_port` 可以覆盖默认端口；启动参数 `--socks-listen` 和 `--socks-port` 会覆盖本次运行的监听地址和端口，但不会改写 `config.yaml`。

`route_mode` 默认是 `tunnel`：公网流量和 DNS 默认都经代理转发，不做国内外分流；`127.0.0.1`、`localhost` 和其他私网地址仍保持直连。设置为 `global` 时保留私网直连和本地 DNS 兼容性；设置为 `rule` 时恢复原先的国内直连、国外代理策略。

### TUN 进程代理

面板中的“进程代理”是基于 sing-box TUN route rule 的高级选项，支持两种模式：

- 清单绕过：默认仍接管全局 TUN 流量，清单内进程绕过代理。
- 仅清单代理：默认不接管，只有清单内进程走 TUN 代理；这就是局部代理模式。

进程清单填写真实可执行文件名，不是完整命令行参数。例如 `curl`、`git`、`git-remote-https`、`ssh`。`git clone https://...` 实际联网进程可能是 `git-remote-https`；`git clone git@...` 实际联网进程可能是 `ssh`。

也可以手动写入配置：

```yaml
tun_process:
  enabled: true
  mode: process_only   # global_bypass | process_only
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

### 订阅缓存

miao 会把上一次成功生成的 sing-box 配置持久化到 `data/cache/config.json`，并在 `data/cache/config.meta.json` 记录当前配置指纹。重启时如果缓存和当前 `config.yaml` 匹配，会优先使用缓存启动，不会自动刷新订阅；只有没有匹配缓存、手动刷新订阅、或通过面板修改订阅/节点时才会重新拉取订阅。

节点选择会持久化到 `data/cache/last_proxy.json`，启动/停止状态和上次运行的代理模式会持久化到 `data/cache/runtime.json`。重启后 sing-box 启动成功时，miao 会自动恢复上次选择的节点；如果订阅刷新后该节点不存在，则跳过恢复并保留默认选择。

如果订阅链接是短时效链接，建议在链接有效期内完成首次添加或手动刷新。之后只要 `data/cache` 被持久化，重启不会依赖订阅链接仍然有效。容器部署时需要把运行目录或至少 `data/cache` 挂载到持久卷。

## 实验性功能

### 自动初始化 Hysteria2 VPS

如果你有一台全新的 VPS，并且当前运行 Miao 的 root 环境可以通过 SSH 私钥免交互登录 `root@<vps_ip>`，可以在当前配置文件中添加：

```yaml
vps_ip: "203.0.113.10"
```

启动时，Miao 会检查 `nodes` 中是否已经存在 `server` 相同的手动节点。不存在时，它会通过 SSH 在该 VPS 上安装 Hysteria2，写入 `/etc/hysteria/config.yaml`，使用 543 端口、自签名证书、随机密码和 Gecko 混淆，然后重启 `hysteria-server.service`。部署成功后，Miao 会把对应的 Hysteria2 手动节点写回解析到的本地配置文件。

如果 `vps_ip` 仍保留，但本地对应的手动节点被删除，Miao 会先尝试通过 SSH 读取远端已有的 `/etc/hysteria/config.yaml` 并恢复本地节点；如果远端配置缺少 Gecko 混淆，Miao 会补写后再恢复本地节点。只有远端没有可复用配置时才重新初始化。

运行前建议先确认：

```bash
sudo ssh -o BatchMode=yes root@203.0.113.10 true
```

如果这条命令失败，自动初始化也会失败。使用 root 运行 Miao 时，SSH 使用的是 `/root/.ssh` 下的密钥和配置。
