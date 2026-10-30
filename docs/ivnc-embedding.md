# iVnc 嵌入接口

iVnc 将 Miao 作为内置后台应用管理，负责进程启停、自动启动、崩溃恢复和配套升级；Miao 继续管理节点、订阅、面板密码与 sing-box 的运行偏好。

独立启动的默认行为不变。只有 `MIAO_EMBEDDED=ivnc` 才启用宿主接口：

| 环境变量 | 作用 |
| --- | --- |
| `MIAO_PORT` | 覆盖本次面板监听端口，不写回用户配置；有效范围 1–65535 |
| `MIAO_RUNTIME_DIR` | 必须是绝对路径，存放当前实例的内核和运行时文件，避免共享 `/tmp/miao-sing-box` |

嵌入模式仅在回环地址监听，关闭首次配置时自动打开浏览器，允许同源 iframe，并拒绝面板自升级。版本信息返回 `managed_by: "ivnc"`。HOME 仍指向原来的用户目录，配置路径选择和持久化约定保持兼容。

`miao-rust --ivnc-integration-version` 无需 root，输出嵌入协议版本（当前为 `1`），在创建配置和启动服务之前退出，供 iVnc 构建流程校验。

`GET /api/auth/status` 保留原认证状态字段，并提供 `service`、`service_pid`、`embedded`、`integration_version`、`initializing`、`proxy_running`、`socks_listen`、`socks_port`。宿主使用进程 PID 和协议版本验证就绪，并读取实际内核状态决定新启动 Chrome 的 SOCKS 地址。此接口不授予管理权限，面板密码、会话、同源校验与 CSRF 校验均继续生效。

发布 iVnc 配套版本时，先发布含此接口的 Miao，再构建 iVnc；本地开发可直接构建两份源码，通过 `IVNC_MIAO_BIN` 传递配套产物。
