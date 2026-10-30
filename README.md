# Miao

基于 sing-box 的代理管理工具，支持 Linux 与 OpenWrt，内嵌内核和网页面板，以单个二进制分发。

- 三种代理模式：全局代理、进程代理、代理池。
- 订阅与手动节点管理，支持多种 URI 协议和本地缓存。
- 面板密码登录、网页升级与运行状态恢复。
- 通过 SSH 部署或恢复 VPS Hysteria2 节点，也可由 CLI 自动部署并启用全局代理。

[界面预览](docs/screenshots.md) · [完整文档](docs/README.md) · [下载最新版本](https://github.com/iVnc-Org/miao/releases/tag/latest)

## 快速开始

以下示例适用于 Linux amd64；arm64 将文件名中的 `amd64` 替换为 `arm64`。

```bash
mkdir -p ~/miao
cd ~/miao
curl -fL https://github.com/iVnc-Org/miao/releases/download/latest/miao-rust-linux-amd64 -o miao
chmod +x miao
sudo ./miao
```

GitHub 无法直连时，可在下载地址前加 `https://httptunnel.top/gh/`。

打开 `http://localhost:6161`；远程部署时将 `localhost` 替换为 Miao 主机地址。首次访问先设置面板密码，再添加订阅或节点并启动代理。远程访问建议使用 HTTPS 或 SSH 隧道。

**首次无参数运行仅启动面板；以后无参数启动恢复上次代理运行或停止状态、模式及节点选择。** 全局和进程模式需要创建 TUN，运行 Miao 使用 root 权限。

## 常用命令

```bash
sudo ./miao --mode global       # 启动全局代理；也支持 process / pool
sudo ./miao --no-start          # 仅启动面板，保存代理停止状态
sudo ./miao password set        # 交互设置或重置面板密码，完成后退出
./miao --help                  # 查看全部启动参数
```

部署 VPS 并启用全局代理（将示例 IP 替换为你的 VPS 地址）：

```bash
sudo ./miao --mode global --vps-host 203.0.113.10
```

默认使用 root、SSH 22/TCP、本机 SSH 密钥及节点 543/UDP；远端需满足 Linux 和初始化系统要求，端口须自行放行。密码认证和过程说明见 [CLI 启动](docs/cli-startup.md)，自定义节点端口、NAT 等使用 [网页 VPS 部署](docs/vps-deployment.md)。

## 使用指南

| 内容 | 文档 |
| --- | --- |
| 启动模式、状态恢复、CLI 自动部署 | [CLI 启动](docs/cli-startup.md) |
| 登录、改密、会话有效期与认证文件 | [面板认证](docs/panel-auth.md) |
| 配置路径、进程名单、代理池与持久化 | [配置与代理模式](docs/configuration.md) |
| 订阅格式、URI 支持与解析提示 | [订阅与节点导入](docs/subscriptions.md) |
| VPS 前提、端口、节点复用与失败恢复 | [VPS 部署](docs/vps-deployment.md) |
| 网页升级、备份迁移与常见问题 | [升级与维护](docs/maintenance.md) |
| 内核版本、源码构建与测试 | [构建与验证](docs/development.md) |
| iVnc 后台应用、宿主环境与配套发布 | [iVnc 嵌入接口](docs/ivnc-embedding.md) |
