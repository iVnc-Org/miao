# Miao

开箱即用的透明代理分流器，基于 sing-box 内核。单文件、零依赖，支持 Linux 与 OpenWrt。

<img width="1415" height="952" alt="image" src="https://github.com/user-attachments/assets/172530bf-cb7e-4482-8dfd-ea8146c33eb0" />

## 特性

- **单文件部署** — 内嵌 sing-box + GEO 规则，下载即用
- **TUN 透明代理** — 自动创建虚拟网卡接管全局流量
- **国内外自动分流** — 内置 GEOIP/GEOSITE 规则，大陆直连、海外走代理
- **Web 控制面板** — 订阅管理、节点切换、延迟测速、流量监控
- **协议支持** — Hysteria2 / AnyTLS / Shadowsocks
- **静默升级** — 一键更新到最新 Release（SHA256 校验）
- **开箱引导** — 无需手写配置文件，首次启动通过 Web 面板添加订阅或节点即可使用
- **OpenWrt 适配** — 自动安装 TUN 所需内核模块

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

### 进阶：手动编写配置文件

你也可以预先创建 `config.yaml` 跳过引导：

```yaml
port: 6161  # Web 面板端口，默认 6161
socks_port: 2080  # 可选：覆盖本机 SOCKS5 端口，默认监听 127.0.0.1:1080
route_mode: rule  # 可选：`tunnel` 为默认全量代理，`global` 保留私网直连，`rule` 为国内直连/国外代理

# 订阅链接（推荐，Clash.Meta 格式）
subs:
  - "https://your-subscription-url"

# 或手动配置节点（可与 subs 混合使用）
nodes:
  - '{"type":"hysteria2","tag":"HY2","server":"example.com","server_port":443,"password":"xxx","tls":{"enabled":true}}'
  - '{"type":"anytls","tag":"AnyTLS","server":"example.com","server_port":443,"password":"xxx","tls":{"enabled":true}}'
  - '{"type":"shadowsocks","tag":"SS","server":"example.com","server_port":443,"method":"2022-blake3-aes-128-gcm","password":"xxx"}'
```

miao 默认会开启一个仅本机可访问的 SOCKS5 入站，监听 `127.0.0.1:1080`。设置 `socks_port` 可以覆盖默认端口。

`route_mode` 默认是 `tunnel`：公网流量和 DNS 默认都经代理转发，不做国内外分流；`127.0.0.1`、`localhost` 和其他私网地址仍保持直连。设置为 `global` 时保留私网直连和本地 DNS 兼容性；设置为 `rule` 时恢复原先的国内直连、国外代理策略。

### 订阅缓存

miao 会把上一次成功生成的 sing-box 配置持久化到 `data/cache/config.json`，并在 `data/cache/config.meta.json` 记录当前配置指纹。重启时如果缓存和当前 `config.yaml` 匹配，会优先使用缓存启动，不会自动刷新订阅；只有没有匹配缓存、手动刷新订阅、或通过面板修改订阅/节点时才会重新拉取订阅。

如果订阅链接是短时效链接，建议在链接有效期内完成首次添加或手动刷新。之后只要 `data/cache` 被持久化，重启不会依赖订阅链接仍然有效。容器部署时需要把运行目录或至少 `data/cache` 挂载到持久卷。
