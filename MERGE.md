# 上游合并记录

记录每次从上游 [YUxiangLuo/miao](https://github.com/YUxiangLuo/miao) 合并的详情。

---

## 2026-06-23

- **上游分支：** `master`
- **上游 HEAD：** `674a8d8`（`v0.24.2`）
- **共同祖先：** `badd471`（`v0.18.4`）
- **合并提交数：** 49
- **合并提交：** `a58a219`
- **主要变更：**
  - feat(route-mode): session-only 路由模式（`route_mode_override: RwLock<Option<RouteMode>>` 入 AppState），面板切换"分流/全局"不再回写 `config.yaml`；配置文件里的 `route_mode` 被显式忽略并 info 日志提示
  - feat(config-path): 配置路径三级解析（`--config` → 同目录 `config.yaml` → `/etc/miao/config.yaml`），新增 `src/paths.rs`；未找到时只用内存默认配置，不再被动写空文件
  - feat(vps): 自动初始化 Hysteria2 VPS（`src/services/vps.rs`），支持 SSH 部署、远端 config 恢复、Gecko 混淆补写
  - feat(nodes): 新增 vmess/vless/trojan/tuic 出站协议；引入 `build_node_value` + `base_outbound`/`build_tls`/`build_transport` 工厂函数；NodeRequest 扩展 23 字段（uuid/alter_id/transport/reality/alpn/client_fingerprint/flow/packet_encoding/tuic_*/obfs_* 等）
  - feat(clash): 通用 HTTP 反向代理 `/api/clash/{*path}` 与 WebSocket traffic 转发（**未采纳**，见冲突解决）
  - feat(frontend): 协议下拉替代分类 Tab、Skills 模型配置、segmented 路由模式开关、按需 packet_encoding/flow/reality/transport 表单分块、ESLint config + vitest setup（OnboardingScreen.test.jsx / utils.test.js）
  - feat(subscription): 订阅获取错误 + `.error_for_status()` 错误透传；订阅刷新结果 toast；duplicate tag 检测
  - feat(presets): VPS 自动部署 Hysteria2、Gecko 混淆默认值
  - refactor(config): 拆分 `regenerate_and_restart_runtime` → `finalize_started_config` → `update_config_warning` 三段式 + `restore_previous_running_config`/`restart_with_previous_config` 回滚流程
  - refactor(openwrt): 适配 OpenWrt 路径 + apk 探测
- **冲突解决：**
  - `Cargo.toml`：保留本仓 `base64 = "0.22"`（AnyTLS URI / Shadowsocks base64 订阅解析依赖）
  - `README.md`：上下两段冲突均保留**本仓 SOCKS5 入站段 + 订阅缓存段** 并入**上游配置路径段 + 实验性 VPS 段**（顺序：SOCKS 启动参数 → 配置路径 → 进阶手动配置 → SOCKS5 默认行为 → 订阅缓存 → 实验性 VPS）
  - `src/models/config.rs`：`RouteMode` 枚举保留本仓 `Tunnel/Global/Rule`（default = `Tunnel`），并入上游 `derive(Copy)`；`Config` 字段并存本仓 `socks_listen`/`socks_port` 与上游 `vps_ip`；`route_mode` 改为运行时字段（`skip_serializing, skip_deserializing`）—— 保留本仓"配置文件可声明 route_mode"语义但禁用 yaml 序列化，上游"配置中 route_mode 被忽略"语义由此实现
  - `src/models/node.rs`：保留本仓 `AnyTls`/`Shadowsocks`/`HttpProxy`/`SocksProxy` 结构体；`NodeRequest.password` 保持 `Option<String>`（手动 SOCKS/HTTP 节点免认证场景），上游对 `password: String` 的硬性使用统一改为 `non_empty(&req.password).unwrap_or_default()`；并入上游 23 字段扩展 + `Default` derive
  - `src/models/mod.rs`：导出 union（`AnyTls/HttpProxy/Shadowsocks/SocksProxy` + `Hysteria2Obfs` + `RouteModeRequest` + `DEFAULT_SOCKS_LISTEN/DEFAULT_SOCKS_PORT`）
  - `src/main.rs`：采纳上游 `paths::resolve_config_path()` 三级解析 + `config_declares_route_mode` 校验；保留本仓 `--socks-listen` / `--socks-port` CLI 选项与 `apply_cli_overrides`；启动后台任务保留本仓 `restore_config_from_cache` 缓存优先策略（生效时 `config_source = "cache"` + 缓存警告），缓存未匹配时回退到上游 `gen_config` + `save_config_cache(&config)`
  - `src/state.rs`：并存本仓 `config_source: Mutex<Option<String>>` 与上游 `route_mode_override: RwLock<Option<RouteMode>>` / `config_path: PathBuf` / `config_update: Mutex<()>`；测试 fixture 中删除自动合并产生的 `route_mode: None,` 重复字段（与新增 runtime-only `route_mode: RouteMode` 字段冲突）
  - `src/handlers/clash.rs`（add/add 冲突）：保留本仓 `get_proxies` / `switch_proxy` / `test_proxy_delay` / `traffic_ws` 四个具体端点（包含 `save_last_proxy` 持久化副作用），整文件采纳本仓版本，丢弃上游通用 `proxy_clash_http` / `proxy_clash_traffic` 反向代理思路
  - `src/handlers/nodes.rs`：采纳上游 `build_node_value` 工厂函数 + `base_outbound`/`build_tls`/`build_transport` 助手；为其新增 `socks`/`http` 分支（用 `base_outbound` + `non_empty(&req.username)` / `non_empty(&req.password)` 注入可选字段）；`VALID_NODE_TYPES` 并入本仓 socks/http；删除重复的 `non_empty(value: Option<String>) -> Option<String>` 实现，统一用上游 `non_empty(&Option<String>) -> Option<&str>`；移除原 `match` block 对 `AnyTls`/`Shadowsocks` 等结构体的直接构造，统一走 build_node_value
  - `src/handlers/service.rs`：导入 union（本仓 `DEFAULT_SOCKS_LISTEN/DEFAULT_SOCKS_PORT` + 上游 `RouteMode/RouteModeRequest/apply_runtime_config_change`）；`get_status` 同时返回本仓 `config_source` 与上游 `route_mode_override`；测试 fixture 修正 `Config` 字段 + `RouteMode::Tunnel`（替代上游 `Rule`）
  - `src/router.rs`：路由表保留本仓四个具体 clash 端点（`/api/clash/proxies`、`/api/clash/proxies/{group}` PUT、`/api/clash/proxies/{name}/delay`、`/api/clash/traffic`、`/api/last-proxy`），丢弃上游 `/api/clash/{*path}` any + `/api/clash/traffic` ws 通用代理；测试 fixture 删除冗余 `route_mode: None,`，补齐 `route_mode: Default::default()` / `vps_ip: None` 缺失字段
  - `src/services/config.rs`（12 处冲突，最大）：
    - 导入 union（本仓 `sha2`/`DEFAULT_SOCKS_*` 常量 + 上游 `HashSet`/`Path`）
    - 采纳上游 `regenerate_and_restart_runtime` → `finalize_started_config` → `update_config_warning` 三段框架；在 `update_config_warning` 中注入本仓 `config_source = "generated"` 与 `save_config_cache(config)`
    - `apply_config_change` 采纳上游运行时/持久化拆分 + `restore_previous_running_config`/`restart_with_previous_config` 回滚（比 HEAD 备份文件方案更干净），保留本仓 `config_has_no_nodes` 早返回（subs/nodes 都空时停掉 sing-box 并清状态）
    - 并入上游公开 `apply_runtime_config_change`（驱动 `route_mode_override` 会话级切换）
    - `restore_config_from_cache()` 调用统一传入 `&config` 形参（本仓签名需要 fingerprint 校验）
    - `build_sing_box_config`：本仓 SOCKS 入站注入 + 上游 `normalize_outbound_tags` + `apply_route_mode`，`get_config_template` 改签名 `&RouteMode`
    - `apply_route_mode`：删除上游 `RouteMode::Global` 的 `rules.truncate(2)` + `dns_rules.clear()` 分支（与本仓"全局模式稳定 DNS 行为"修复冲突，会清掉模板已建好的 `ip_is_private direct` 与 chinasite local DNS 规则），Global 改为与 `Tunnel` 同走 no-op
    - `get_config_template`：保留本仓 route-mode 感知的 dns_rules / route_rules 构造（Tunnel/Global/Rule 各自三套，`default_domain_resolver` 都设为 `local`）；补齐 `RouteMode::Tunnel` arm
    - 测试 fixture 修正：批量删除冗余 `route_mode: None,`、`Option<RouteMode>` 字面量改为裸 `RouteMode`，删掉 `config_with_route_override_defaults_to_rule_mode`（重命名为 `_defaults_to_tunnel_mode`，断言 `RouteMode::Tunnel`），`build_sing_box_config_merges_nodes_and_valid_custom_rules` 期望 rules.len() 从 7 改为 5（本仓 Rule 模板更简洁，无 hdslb.com / chinaip 单独 entry），`build_sing_box_config_global_mode_removes_split_rules` 改测"Global 模式保留 ip_is_private direct + chinasite local DNS"（rules.len = 3, dns_rules.len = 1）
  - `src/services/node_parser.rs`：导入 union（本仓 `base64` 用于 AnyTLS URI / SS base64 + 上游 `regex` / `Mapping` / `LazyLock`）；丢弃 HEAD 一段被上游重写取代的 ss match arm 碎片；在新 `"ss"` 分支调用本仓 `parse_clash_ss_plugin` 保留 SS obfs 解析能力
  - `src/services/proxy.rs`：last_proxy 持久化路径锁定本仓 `data/cache/last_proxy.json`，丢弃上游 OpenWrt 专属 `is_openwrt_system` / `get_last_proxy_path_for` 分支；删除自动合并出来的重复 `fn get_last_proxy_path` 定义
  - `src/services/subscription.rs`：错误处理合并本仓"脱敏链接 + 错误上下文"与上游 `.error_for_status()` —— 测试期望 "Subscription server returned HTTP error" 文案需后者；订阅刷新 clash-proxies 测试用例并存本仓 4 个 SS obfs 保留场景 + 上游 vmess case（共 5 节点），断言数量同步调整
  - `src/validation.rs`：保留本仓 socks/http `Option<String>` username/password 校验分支；并入上游 vmess/vless/tuic UUID 必填校验 + `node_type()` 检测；`VALID_NODE_TYPES` 加入 socks/http
  - 前端 `frontend/src/utils.js`：`NODE_TYPE_OPTIONS` 并入 socks/http（保留 anytls 在 ss 后、vmess 前）；同时保留本仓 `validateOptionalCredential` 与上游 `validateUuid` / `validateTransport` / `buildTransportPayload` / `validateVlessFlow` / `validateHysteria2Obfs`；表单初始默认值并入 `username: ''` 与 `uuid: '' / alter_id: 0`
  - 前端 `frontend/src/App.jsx`：保留本仓 `useEffect` embed-mode 处理 + `clashApiBase = '/api/clash'`（删除自动合并导致的重复定义）；`handleAddNode` 采纳上游 `requiresPassword`/`requiresUuid`/`supportsTransport` 三态校验框架，叠加本仓 `isSimpleProxy`（socks/http）的可选 username/password 分支；payload 构造按 isSimpleProxy → requiresPassword → requiresUuid 三态分支
  - 前端 `frontend/src/components/modals.jsx`：保留本仓 socks/http username/password 输入块（`{isSimpleProxy && (...)`），其他 UI 全面采纳上游：协议下拉 `<select>` 替代 tab-row、vmess 的 `vmess_cipher`/`alter_id`、`requiresUuid` 的 UUID 输入、vless 的 flow/packet_encoding、vmess 的 packet_encoding、`showsTlsFields` 的 SNI/TLS 指纹/skip_cert_verify、vless 的 Reality 字段、`supportsTransport` 的 transport 块、hysteria2 的 obfs 块、tuic 的拥塞控制/relay/zero_rtt、`requiresPassword` 的通用密码框；`canSubmit` 合并五态校验；按钮文案改为 `添加 {activeLabel} 节点`
  - 前端 `frontend/src/components/StatusCard.jsx`：保留本仓 `sourceText` / `runningText`（"缓存配置"/"最新配置"运行时显示）；并入上游 `onSetRouteMode` / `onOpenConnections` props 与 segmented route mode 控件
  - 前端 `frontend/src/components/NodesCard.jsx`：导入合并 `classNames`（本仓）+ `protocolLabel`（共有）
  - 前端 `frontend/src/hooks/useApi.js`：`useStatus` 初始 state 合并 `route_mode: 'tunnel'`（本仓默认）+ `config_source: null` / `warning: null`；trafficUrl 采纳本仓 `scheme` 命名（语义等价）
  - 前端 `frontend/src/styles.css`：保留本仓 `.commit-badge` 移动断点样式并入上游 `.connection-stat-grid` / `.connections-table-*` / `.connection-detail-panel` 样式
- **附加修复（测试期）：**
  - `src/handlers/nodes.rs` 测试中 TUIC NodeRequest fixture：`password: "...".to_string()` → `Some("...".to_string())`（适配 `Option<String>`）
  - `src/handlers/subs.rs`、`src/services/config.rs`、`src/services/vps.rs`、`src/validation.rs`：批量删除冗余 `route_mode: None,`，补齐 `socks_listen` / `socks_port` / `route_mode` / `vps_ip` 缺失字段；2 个 NodeRequest fixture 改用 `..NodeRequest::default()` 展开避免枚举全部 23 字段
  - `src/models/node.rs` 中 `AnyTls/Shadowsocks/HttpProxy/SocksProxy` 结构体保留但变为 dead-code warning（不再被 handlers/nodes.rs 直接构造，统一走 build_node_value Map 路径），未删除以便未来若需要类型化 API 可直接复用
- **验证：** `cargo check` exit 0（5 条 dead-code warning，含 `AnyTls`/`Shadowsocks`/`HttpProxy`/`SocksProxy` 4 个未构造结构 + 对应 `pub use` 未使用）；`cargo test` 172 个测试全部通过；`npm run build`（frontend / vite）输出 228.70 kB（gzip 68.96 kB）单文件 index.html

---
