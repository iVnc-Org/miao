# VPS 部署 / VPS deployment

在“添加节点 → VPS 部署”填写管理地址和 SSH 凭据，先检查环境，再执行检查结果。支持 root 密码、临时未加密私钥或 Miao 主机已有密钥。SSH 凭据不写入配置、任务记录或浏览器存储；临时文件权限为 0600，关闭弹窗清空 SSH 凭据输入。

Install or recover Hysteria2 from **Add node → VPS deployment**. Inspect first, then execute. Root access is required. SSH passwords and private keys are not persisted in configuration, task history or browser storage.

## 前提与访问控制

- Miao 主机安装 OpenSSH 客户端。使用已有密钥时，读取运行 Miao 账户的密钥和 known_hosts；忽略用户 SSH 配置，连接端口以表单为准。
- VPS：Linux amd64/arm64、实际运行的 systemd/OpenRC。正式部署按需安装 Python 3.8+、PyYAML、OpenSSL、CA、iproute 等依赖。发行版软件源必须可用；不执行系统升级。
- 入站：SSH TCP（默认 22），节点 UDP（默认 543）。只开放 TCP 不能使用 Hysteria2。出站需访问软件源、GitHub、DNS 和代理目标。
- 防火墙、安全组、NAT、sshd 配置均不自动修改。没有公网 IP 时，需私网/VPN 互通或支持 UDP 的端口映射。
- 面板没有通用登录系统，因此 VPS API 默认仅允许真实回环连接且 Host 为 localhost/回环 IP。可使用 SSH 隧道访问 `http://localhost:6161`。
- 远程网页访问必须使用 HTTPS，并在 **Miao 进程**配置至少 32 字符的 `MIAO_VPS_TOKEN`。在高级设置中输入同一令牌，仅保留到当前浏览器会话结束。反向代理须保留外部 Host 和同源 Origin/Referer；不信任 X-Forwarded-* 来识别用户。
- 远程调用 API 也必须提供 `Authorization: Bearer …` 和匹配 Host 的 HTTPS Origin。GET 允许使用同源 HTTPS Referer。令牌拥有部署权限，应作为管理凭据保护。不要将未受保护的面板直接暴露到公网。

Remote access requires HTTPS and a server-side `MIAO_VPS_TOKEN` (32+ characters); alternatively use a localhost SSH tunnel. First SSH contact uses TOFU: check the VPS fingerprint through the provider console when possible. Changed host keys are rejected; fix known_hosts only after independently verifying the replacement.

## NAT 与端口

高级设置分别配置：

| 设置 | 示例 |
| --- | --- |
| SSH 管理地址/端口 | `203.0.113.10:22022` |
| VPS 服务监听端口 | `543/UDP` |
| 节点连接地址/端口 | `node.example.com:30543/UDP` |

上游映射为 `22022/TCP → VPS:22/TCP`、`30543/UDP → VPS:543/UDP`。映射由服务商或网关配置。

## 执行与保护规则

- 预检只读，不安装依赖、不启停服务。缺少 Python/PyYAML 时，正式执行先补依赖，再重新检查归属；未知部署仍不覆盖。
- 全新安装固定 Hysteria2 `v2.12.1`，下载官方 binary 和 SHA256 清单，校验后检查可执行版本。不执行网络下载的安装脚本。高级设置可指定 HTTPS 下载代理前缀，直连失败后回退，同样校验。
- 健康的已有 Miao 节点仅恢复，不重启、不改密码。停止的已有服务可以修复重启。
- 旧版 Miao 使用 CN-only 证书时，迁移生成含 SAN 的证书、更新内核，保留原认证密码、混淆与其他配置。迁移会重启服务。新节点固定信任证书并验证 `miao-hysteria`，不跳过 TLS 验证。
- 第三方、归属不明、被修改的托管配置、未知服务覆盖项、符号链接和不安全权限默认阻止。旧部署识别同时检查证书、binary、服务路径和生成配置特征；有歧义时使用手工节点导入。
- 新服务以 `miao-hysteria` 专用用户运行。systemd 使用权限隔离和日志速率限制；OpenRC 使用日志轮转配置。软件包及新建系统账户不属于文件回滚范围。
- 远端主机锁覆盖部署事务；配置、binary、服务文件、自启/运行状态和部署元数据纳入备份。保留最近两个完成事务的备份，未解决的事务不自动清理。

## 进度、刷新与失败恢复

任务在后台运行，关闭弹窗不取消；刷新后自动恢复活动任务弹窗，可通过页面 VPS 按钮重新打开。下载有字节进度，其他阶段显示真实操作名称。

远端优先使用 systemd transient service，OpenRC 使用独立后台进程。Miao 重启后将未完成任务标记为“待核查”，重新输入 SSH 凭据后检查原任务，避免自动重装。

| 最终状态 | 含义与动作 |
| --- | --- |
| 完成 | 远端服务健康、本地节点已保存、隔离核心真实代理请求成功 |
| 连通性失败 | 节点已保存，检查 UDP、安全组、NAT、出站访问；不会因此自动卸载 |
| 待核查 | SSH 断开/进程重启等；重新认证检查原任务 |
| 已回滚 | 恢复旧文件及原服务状态；可以重新检查后创建任务 |
| 需要手工恢复 | 保留备份，不再盲目部署；先检查远端事务和服务 |

远端任务：`/var/lib/miao-vps/tasks/<任务ID>/`。其中 `status.json` 含节点凭据，仅供 root 读取，**不要粘贴到工单或日志**。`journal.json` 记录事务阶段；`backup/0` 为配置目录、`1` 为 binary、`2` 为 systemd unit、`3` 为 OpenRC 脚本、`4` 为部署元数据、`5` 为日志轮转配置。目录或文件不存在表示部署前原本不存在，不应凭空创建。

人工恢复前停止对应任务和 Hysteria2 服务，确认没有部署进程持锁；根据 `journal.json` 和备份恢复对应路径，再恢复原运行/自启状态。不要直接清理未完成事务的备份或锁文件。断电和 SIGKILL 无法当场回滚；重新核查时会在主机锁内恢复未完成激活。

本地任务保存在配置文件同名的 `.vps/` 目录，仅包含脱敏进度及目标，不含 SSH 凭据。远端已成功但本地提交失败时，重新核查原任务即可恢复节点，无需重新安装。升级与活动部署互斥。

## 兼容 vps_ip

```yaml
vps_ip: "203.0.113.10"
```

保留原配置，使用同一后台引擎和本机密钥认证，默认 SSH 22、UDP 543。仅当缺少相同服务器、协议和端口的节点时执行，不在 SSH 阶段占用配置更新锁。探测失败不会回退重装；存在未解决任务时需先核查。NAT 或自定义端口请使用网页入口。

## 验证 / Validation

```bash
cargo test
npm --prefix frontend test
npm --prefix frontend run lint
npm --prefix frontend run build
python3 -m pip install 'PyYAML==6.0.2'
MIAO_TEST_SING_BOX="$PWD/embedded/sing-box-amd64" \
  python3 -m unittest discover -s scripts/tests -p '*_test.py' -v
```

脚本测试将文件路径和系统命令隔离到临时目录；真实核心测试只访问回环 HTTP 服务，验证 Gecko 转发和错误证书拒绝，不连接订阅节点或真实 VPS。CI 使用仓库声明构建的主机核心重复该测试。

发行版分支以模拟命令验证；真实 VPS 的 apt/dnf/apk、systemd/OpenRC、amd64/arm64 全矩阵仍需在有授权的隔离主机上验收。同一 sing-box 的回环互通测试不能代替真实 Hysteria2 release 服务端验收。
