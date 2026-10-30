# 面板密码登录

单管理员、仅密码登录。所有管理 API 和流量 WebSocket 均受会话保护，包含 localhost；登录页、图标、最小登录状态和登录接口允许匿名访问。不设默认密码。未设置密码时网页直接显示初始密码和确认密码，设置成功后自动登录进入面板。初始化接口只允许在认证文件不存在时执行，已配置或损坏的认证文件不能通过匿名初始化覆盖。首次开放面板后应及时完成初始化。

## 设置和重置

```bash
miao password set                         # 终端交互输入两次，不回显；完成后退出
miao password set '新密码'                 # 设置/重置，完成后退出
miao --config /etc/miao/config.yaml password set
miao password set '新密码' --config /etc/miao/config.yaml
miao --password '密码'                    # 保存密码并启动
miao --password='密码' --config=/etc/miao/config.yaml
```

保持原有 root 运行要求。无终端时使用显式密码参数；密码以 `-` 开头时使用 `--password='-你的密码'`。只允许一份密码参数，拒绝空密码、控制字符或超过 4096 字节的密码；不修改首尾空格，支持中文和 shell 特殊字符（须正确引用）。错误和调试输出不包含密码值。命令参数仍可能被进程列表或 shell 历史记录，推荐交互设置。

`password set` 在配置加载、提取内核、启动 HTTP 或远程初始化之前执行并退出。不带密码普通启动沿用持久密码。每次显式使用 `--password` 都重设密码，旧会话失效；如果 systemd/Docker 启动命令长期携带旧密码，外部重启时会覆盖网页改密，应改用一次 `password set` 后普通启动。内置升级的 exec 重启移除密码参数，避免升级重放旧密码。

CLI 和网页使用相同的配置路径规则。多实例通过 `--config` 区分，认证文件为配置路径改扩展名 `.auth.json`，如 `/etc/miao/config.auth.json`；锁文件是 `.auth.json.lock`。密码按要求明文存储，仅同一运行账户拥有的普通文件且权限不开放给组/其他用户时允许读取。新文件权限 `0600`，新建父目录权限 `0700`，拒绝符号链接或不安全文件。

所有写入使用跨进程 flock、唯一临时文件、fsync 和原子替换。每次改密更新随机凭据版本；服务端在请求时读取当前版本，CLI 改密无需重启。旧会话立即不能发起新请求；已开始的后台部署/升级继续执行。旧流量连接在一秒内检查到失效并断开。网页最多 15 秒检测会话状态，普通 API 的 401 会立即返回登录页。

认证文件不可读/损坏时管理接口保持锁定，不退回免登录。可用 CLI 修复损坏内容；不安全权限或所有者问题需先由管理员修复。忘记密码用本机 CLI 重置，无需旧密码；网页改密必须提供当前密码。

## 网页与会话

登录后通过右上角修改密码或退出。网页改密填写当前密码、新密码和确认密码，成功后所有会话失效，需要重新登录。取消/关闭清空密码字段。首次设置密码前显示网页初始化表单，不加载管理界面和后台轮询。也可预先用 CLI 设置，网页随后直接显示登录页。多个页面或 CLI 同时设置时在跨进程锁内仲裁；其他页面收到冲突后切换至登录。

会话为 256 位随机值，服务端内存保存，有效期 7 天，最多 256 个活动会话。Cookie 使用 HttpOnly、SameSite=Strict；HTTPS 登录附加 Secure（依据通过同源检查的 Origin，支持 TLS 反向代理）。Cookie 名按配置路径区分实例。重启/升级后会话失效，登录后恢复持久化任务进度。

浏览器不保存密码或会话令牌到 localStorage/sessionStorage，CSRF 凭证仅存在内存。写操作验证 CSRF 和同源 Origin；WebSocket 校验会话和 Origin。反向代理需保留外部 Host（含端口）、Origin 和 Cookie，不能让代理只给后端发送内部 Host。转发头不授予任何免鉴权权限。不支持跨域管理页面。

登录限速按真实连接 IP（不信任 X-Forwarded-For）控制：一分钟最多 10 次尝试，成功登录清除该 IP 的失败计数。反向代理后的用户共享代理 IP 的限速桶。HTTP 能正常使用，但密码、会话 Cookie 和提交的 SSH 凭据均未加密；建议 HTTPS 或 SSH 隧道。

## API

- `GET /api/auth/status`：是否配置、是否登录；有效会话才返回 CSRF 凭证。
- `POST /api/auth/setup`：仅未设置密码时可用，JSON `{ "password": "…", "confirm_password": "…" }`，验证同源 Origin，成功后设置会话 Cookie 并自动登录；已设置返回 409。
- `POST /api/auth/login`：JSON `{ "password": "…" }`，需匹配 Host 的 Origin。
- `POST /api/auth/logout`：会话 Cookie、Origin、`X-Miao-CSRF`。
- `PUT /api/auth/password`：同上，JSON `{ "current_password": "…", "new_password": "…" }`。

其他管理 API 均需 Cookie；写操作另带 Origin 和 `X-Miao-CSRF`。认证响应和管理响应禁止缓存。密码不通过任何 API 返回。旧 `MIAO_VPS_TOKEN` 已无作用，浏览器旧 VPS 令牌记录会清理。
