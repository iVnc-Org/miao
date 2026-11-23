# OpenWrt 接管方式与故障排查

[文档目录](README.md) · [配置与代理模式](configuration.md)

Miao 支持 amd64、arm64 的 OpenWrt。全局和进程模式需要可用的 `/dev/net/tun` 与 `CAP_NET_ADMIN`；代理池模式只提供 SOCKS 端口，不需要 TUN 或 nftables。

安装时使用对应架构的 Linux release 产物，其 Rust 程序使用 musl，内嵌 sing-box 关闭 CGO。自行构建时同样需要 musl 目标与静态内核；普通发行版上的 glibc 构建不能直接代替 OpenWrt 产物。

## 接管策略

默认自动检测当前进程可用的内核能力，不依赖 `nft` 命令是否安装，也不单凭固件名称或软件包记录判断。

```yaml
tun:
  routing: auto  # auto | nftables | policy_route
  # 自定义 LAN 区域时可指定可信设备名；默认从 UCI 的 lan 区域与 ubus 发现。
  # lan_interfaces: [br-lan]
```

| 策略 | 行为 |
| --- | --- |
| `auto` | nftables 查询可用时启用增强接管；明确缺少内核支持时使用兼容策略路由 |
| `nftables` | 要求增强接管，缺少能力或与环境变量冲突时报告错误 |
| `policy_route` | `auto_redirect: false`，保留 `auto_route: true` 与 `strict_route: true` |

网页状态卡可以选择策略，并分别显示选择值与当前运行方式。`/api/tun` 提供 GET/PUT，`/api/status` 的 `tun` 与 `runtime` 返回配置、实际方式、准备/启动/就绪/失败阶段及诊断。

`DISABLE_NFTABLES=true` 在自动策略下映射为完整的兼容策略路由，避免只切换到旧 iptables 重定向后，进程虽然运行但流量仍走原路由。明确选择 `nftables` 时，该变量会引发配置冲突提示。Miao 显式控制 sing-box 子进程环境，使运行结果与解析的策略一致。

基础查询通过但所需 nftables 规则明确不受内核支持时，自动策略最多回退一次。配置错误、权限不足、端口冲突、探测超时和节点失联分别报告；节点连通性不决定接管策略。

本次运行已确认缺少规则能力后，后续配置更新继续使用兼容策略。重启 Miao 或显式选择增强模式可以重新检测；增强模式成功后，自动策略也可恢复使用该能力。

## fw3 与进程代理

fw3 环境会在运行期间管理带本实例标记的 INPUT/FORWARD 规则链，允许可信 LAN 与当前 TUN 必需的转发和回包。可信 LAN 默认来自名为 `lan` 的 UCI 防火墙区域；自定义区域请填写 `tun.lan_interfaces`。设备名必须存在，且不能是回环或 TUN 本身。

Miao 每秒检查自己的规则，防火墙重载或规则链被清空后自动补齐；重载期间可能短暂影响经过代理的连接。停止服务、启动失败和内核退出会清理自有规则；下次启动也会清理该运行目录留下的规则。管理器被强制杀死时，残留自有链在下次启动清理，包括改以代理池模式重启的情况。清理失败会报告诊断，不会显示为成功停止。

运行目录的 `network-ownership.json` 记录本次新增的策略规则、nftables 表句柄和进程/启动/网络命名空间身份，用于强制退出后的恢复。启用 TUN 时需要可执行且能成功查询策略规则的 `ip` 命令；无法读取规则时拒绝建立资源归属。已有但没有本实例归属记录的 TUN、策略优先级或 `inet sing-box` 表会引发冲突提示，避免覆盖其他代理。一个网络命名空间只运行一个透明代理实例；嵌入部署须为实例提供独立运行目录。

进程名单适用于路由器本机进程。兼容策略将黑名单的 `bypass` 生成为明确的 direct 出站；增强策略的 bypass 也带 direct 后备，避免缺少预匹配能力时规则被跳过。自定义 bypass 规则保留明确指定的出站，未指定时使用 direct 后备。

路由器的 dnsmasq 可能代其他进程发起 DNS，进程 DNS 归属仍受系统行为限制。当前生成的透明代理配置面向 IPv4；IPv6 不属于这次兼容修复的接管范围。

远端 DNS 通过当前代理使用 TCP，本机和 LAN 仍可通过 UDP 或 TCP 发起 DNS。这样不依赖上游 SOCKS/HTTP 节点的 UDP 转发能力，也能兼容接受 UDP ASSOCIATE 却不回传 DNS 的节点。节点本身的普通 UDP 转发能力仍由上游服务决定；更换 DNS 传输不能为节点补充该能力。直连的本地 DNS 保留 UDP。

## 依赖与缓存

所有实际启用 TUN 的入口都先准备设备与权限。已有 TUN 可以直接使用，不要求找到 apk/opkg；缺少设备时先尝试加载模块，再在 OpenWrt 上安装必要的 `kmod-tun`。增强队列模块不再是兼容模式的启动前提。

安装前核对固件内核依赖，更新索引、检查和安装均有超时，并串行执行。取消启动会停止等待，不会直接中断正在写入包数据库的后台安装事务。安装超时后需检查实际包和模块状态再重试。

例如部分固件标为 OpenWrt 24.10.0，但使用定制的 6.12 内核，而配置的软件源属于官方 6.6 内核。此时应使用固件匹配的软件源；自动策略通常可以直接选择兼容接管。软件包显示已安装，也不代表模块已加载或内核能力可用。

旧版本生成配置缓存会因结构版本或策略不同而重新生成，继续复用本地节点缓存，不主动刷新订阅。运行配置旁的 `routing.json` 绑定配置 SHA256、内核修订与操作编号，防止过期配置被另一个启动任务复用。

## 常见错误

| 错误或现象 | 处理方向 |
| --- | --- |
| `missing nftables support: ... invalid argument` | 旧防火墙或定制内核缺少能力，优先选择 `auto` 或 `policy_route` |
| `NO_NET_ADMIN` | root 运行，或给容器提供网络管理权限与 TUN 设备 |
| `TUN_UNAVAILABLE` / `TUN_LOAD_FAILED` | 检查设备映射、模块是否与运行内核匹配 |
| `KERNEL_ABI_MISMATCH` | 换用当前固件匹配的软件源和模块 |
| `FW3_LAN_UNDETECTED` | 用真实可信 LAN 设备填写 `tun.lan_interfaces` |
| `ROUTING_INSPECTION_FAILED` | 检查 `ip -4 rule show` 是否可执行且成功返回 |
| `FW3_CLEANUP_FAILED` | 检查本实例规则链的引用、iptables 权限和锁竞争 |
| `DEPENDENCY_TIMEOUT` | 检查软件源及安装状态；面板仍可查看状态或取消启动 |
| `START_CANCELLED` | 本次操作已被停止或更新请求取代 |
| `READY_TIMEOUT` | 查看内核启动日志、监听端口、TUN 与路由是否就绪 |
| 本机代理可用但 LAN 不通 | 检查可信 LAN、网关设置、转发与防火墙规则 |

启动成功要求子进程持续存活、本次内核发布完成启动日志、控制接口和 SOCKS 可用，以及 TUN/策略路由满足当前策略。公网可达性通过独立的连通性测试确认。
