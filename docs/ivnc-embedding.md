# iVnc 嵌入接口

iVnc 将 Miao 作为内置后台应用管理，负责进程启停、自动启动、崩溃恢复和配套升级；Miao 继续管理节点、订阅与 sing-box 的运行偏好。iVnc 默认传入 `--nopasswd`，嵌入面板自动进入，外部访问由 iVnc 控制；已有面板密码保留，普通独立启动仍需密码。

独立启动的默认行为不变。只有 `MIAO_EMBEDDED=ivnc` 才启用宿主接口：

| 环境变量 | 作用 |
| --- | --- |
| `MIAO_PORT` | 覆盖本次面板监听端口，不写回用户配置；有效范围 1–65535 |
| `MIAO_RUNTIME_DIR` | 必须是绝对路径，存放当前实例的内核和运行时文件，避免共享 `/tmp/miao-sing-box` |

嵌入模式仅在回环地址监听，关闭首次配置时自动打开浏览器，允许同源 iframe，并拒绝面板自升级。版本信息返回 `managed_by: "ivnc"`。HOME 仍指向原来的用户目录，配置路径选择和持久化约定保持兼容。

`miao-rust --ivnc-integration-version` 无需 root，输出嵌入协议版本（当前为 `2`），在创建配置和启动服务之前退出，供 iVnc 构建流程校验。v2 要求支持 `--nopasswd` 与状态字段 `password_required`，避免宿主打包无法免密码启动的旧产物。

`GET /api/auth/status` 保留原认证状态字段，并提供 `password_required`、`service`、`service_pid`、`embedded`、`integration_version`、`initializing`、`proxy_running`、`socks_listen`、`socks_port`。宿主使用进程 PID、协议版本及 `password_required: false` 验证就绪，并读取实际内核状态决定新启动 Chrome 的 SOCKS 地址。此接口只读且不创建会话；免密码网页通过同源登录接口自动建立会话，Cookie、同源与 CSRF 校验继续生效。

嵌入标记本身不关闭密码验证，必须显式传入 `--nopasswd`。VPS 部署依赖运行环境中的 OpenSSH 客户端，Debian/Ubuntu 镜像须安装 `openssh-client`，可用 `ssh -V` 验证。

发布 iVnc 配套版本时，先发布含此接口的 Miao，再构建 iVnc；本地开发可直接构建两份源码，通过 `IVNC_MIAO_BIN` 传递配套产物。
