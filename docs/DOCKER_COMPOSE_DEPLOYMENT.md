# OAuth2ACF Docker Compose 安装与配置手册

本文说明如何在 Debian Linux 上使用 Docker Compose 部署 `OAuth2ACF`，并与
ICChat App 和 `icchat-fcm` 对接。内容以当前仓库中的 `Dockerfile`、
`compose.yaml`、`.env.example` 和 `oauth-clients.example.json` 为准。

最后核对日期：2026-10-20。

## 1. 服务定位

OAuth2ACF 是独立运行的账户授权服务，不是编译进 App 或 `icchat-fcm` 的库。
推荐使用独立域名：

```text
https://accounts.example.com -> OAuth2ACF
https://push.example.com     -> icchat-fcm
```

调用关系：

```text
ICChat App
   |
   | Google/Microsoft access token 或自建 IMAP 账号证明
   v
OAuth2ACF
   |-- 验证账号归属
   |-- 加密保存 refresh token / IMAP 密码
   |-- 签发短期 Ed25519 推送注册 JWT
   |
   +---- HTTPS broker ----> icchat-fcm
                               |
                               +--> FCM / APNs
                               +--> Gmail / Graph / IMAP 监控
```

接口分为三类：

| 类型 | 接口 | 调用方 |
| --- | --- | --- |
| 旧 OAuth 登录流 | `/authorize`、`/callback`、`/get_token` | App 与 OAuth provider |
| 推送账户授权 | `/v1/push/token`、`/v1/push/session` | ICChat App |
| 内部 broker | `/internal/v1/*` | 仅 `icchat-fcm` |

### 1.1 当前运行边界

- 数据库只支持 SQLite；
- Compose 设计为单实例；
- OAuth challenge 和非持久 token 的部分状态在进程内存中；
- 当前不能把多个副本直接放在负载均衡器后；
- SQLite 卷不能放在 NFS/SMB 上供多实例写入；
- OAuth 客户端配置启动时从只读 JSON 导入 SQLite；
- refresh token 和动态 IMAP 密码由 `OAUTH2ACF_TOKEN_KEY` 加密；
- OAuth client secret 同时存在于受保护 JSON 和 SQLite，备份属于敏感凭据。

### 1.2 旧 OAuth 登录流安全说明

`/authorize`、`/callback`、`/get_token` 是兼容接口。当前 state 包含业务
字段，challenge 保存在内存，尚未完成一次性随机 state、PKCE、授权事务到期
和完整并发加固。

正式向不受信任公众开放旧接口前，应完成这些改造和安全审计。新的
`/v1/push/token` 与 broker 使用独立边界，不能用旧 `/get_token` 替代。

## 2. Compose 运行结构

`compose.yaml` 的 `oauth2acf` 服务具备：

- 容器监听 `0.0.0.0:9090`，宿主机只发布 `127.0.0.1:9090`；
- SQLite 使用命名卷 `oauth2acf-data`；
- `./secrets` 只读挂载到 `/run/secrets`；
- 只读根文件系统和禁止执行的 16 MB tmpfs；
- 删除 Linux capabilities，启用 `no-new-privileges`；
- 容器内 UID 10001 非 root 用户；
- 每 30 秒调用 `/readyz`；
- SIGTERM 时执行 HTTP 优雅退出。

推荐拓扑：

```text
Internet -> HTTPS Nginx/Caddy -> 127.0.0.1:9090 -> OAuth2ACF
                                      |
                                      +-> oauth2acf-data
                                      +-> Google/Microsoft/IMAP
                                      +-> icchat-fcm broker
```

## 3. 部署前准备

### 3.1 主机与网络

- Debian 12 或 Debian 13，amd64 或 arm64；
- 建议至少 1 CPU、1 GB 内存和 10 GB 磁盘；
- 独立域名，例如 `accounts.example.com`；
- TCP 443 入站；
- TCP 443 出站到 Google、Microsoft；
- 自建 IMAP 验证需要访问邮箱 993 或 STARTTLS 端口；
- NTP 时间同步正常。

```bash
timedatectl status
```

设置 DNS：

```text
accounts.example.com -> OAuth2ACF 服务器公网地址
```

反向代理必须持有有效 TLS 证书。App 应直接使用最终 HTTPS URL，不能通过
HTTP 或 301/302 跳转传递 Bearer 凭据。

### 3.2 安装 Docker Engine 与 Compose

```bash
sudo apt update
sudo apt install -y ca-certificates curl git openssl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/debian/gpg \
  -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

sudo tee /etc/apt/sources.list.d/docker.sources >/dev/null <<EOF
Types: deb
URIs: https://download.docker.com/linux/debian
Suites: $(. /etc/os-release && echo "$VERSION_CODENAME")
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF

sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
sudo docker run --rm hello-world
sudo docker compose version
```

官方文档：<https://docs.docker.com/engine/install/debian/>

无需在宿主机创建 `oauth2acf` 用户。镜像已创建 UID 10001 用户；宿主机只需
让该 UID 能读取 secrets。

## 4. 获取代码与目录

```bash
sudo install -d -m 0755 /opt/oauth2acf
sudo chown "$USER":"$USER" /opt/oauth2acf
git clone <OAuth2ACF-git-url> /opt/oauth2acf
cd /opt/oauth2acf
git switch main

mkdir -p secrets backups
cp .env.example .env
cp oauth-clients.example.json secrets/oauth-clients.json
chmod 600 .env
```

目录结构：

```text
/opt/oauth2acf/
  Dockerfile
  compose.yaml
  .env
  secrets/
    oauth-clients.json
    legacy-jwt-key
    token-encryption-key
    push-signing-private.pem
    push-broker-key
  backups/
```

`.env`、`secrets/`、`data/`、数据库和构建产物已被 Git 忽略。

## 5. 创建服务密钥

不同用途的密钥不能复用。

### 5.1 旧登录 JWT secret

`OAUTH2ACF_JWT_SECRET` 是旧登录代码使用的 HS256 密钥。Compose 推荐文件
形式：

```bash
openssl rand -hex 32 > secrets/legacy-jwt-key
```

对应变量为 `OAUTH2ACF_JWT_SECRET_FILE`。

### 5.2 Provider 凭据加密密钥

`OAUTH2ACF_TOKEN_KEY` 加密 Google/Microsoft refresh token、自建 IMAP 密码、
旧登录 refresh token，并用于动态 IMAP 配置指纹 HMAC。

```bash
openssl rand -base64 48 > secrets/token-encryption-key
```

对应变量为 `OAUTH2ACF_TOKEN_KEY_FILE`。它必须与 JWT secret 不同、长期
稳定并进入异机加密备份。当前没有旧密钥
keyring；直接更换会让已有密文无法解密。

### 5.3 Ed25519 推送签名密钥

```bash
openssl genpkey -algorithm Ed25519 \
  -out secrets/push-signing-private.pem
openssl pkey -in secrets/push-signing-private.pem -pubout \
  -out account-public.pem
```

- 私钥只部署到 OAuth2ACF；
- `account-public.pem` 部署到 icchat-fcm；
- 私钥不能进入 App、icchat-fcm 或安装包。

配置对应关系：

```text
OAuth2ACF OAUTH2ACF_PUSH_ISSUER   = icchat-accounts
icchat-fcm AUTH_ISSUER            = icchat-accounts
OAuth2ACF OAUTH2ACF_PUSH_AUDIENCE = icchat-push
icchat-fcm AUTH_AUDIENCE           = icchat-push
```

### 5.4 Broker key

```bash
openssl rand -hex 32 > secrets/push-broker-key
```

同一内容复制给 icchat-fcm。App、Webhook 调用方不能获得它。

### 5.5 文件权限

```bash
sudo chown -R 10001:10001 secrets
sudo find secrets -type d -exec chmod 700 {} \;
sudo find secrets -type f -exec chmod 400 {} \;
```

更新文件：

```bash
sudo install -o 10001 -g 10001 -m 0400 new-oauth-clients.json \
  /opt/oauth2acf/secrets/oauth-clients.json
```

## 6. Google OAuth 客户端

在 Google Cloud Console：

1. 选择 ICChat 项目并配置 OAuth consent screen；
2. 创建 Web application 类型的 OAuth Client；
3. 添加 redirect URI `https://accounts.example.com/callback`；
4. 保存 Client ID 和 Client secret；
5. 启用 Gmail API；
6. 配置测试用户或完成发布审核。

推荐 scopes：

```text
openid
email
profile
https://www.googleapis.com/auth/gmail.readonly
```

`gmail.readonly` 属于 restricted scope，生产发布可能需要 OAuth 验证；服务器
存储或传输 restricted scope 数据还可能涉及安全评估。不要无必要地使用权限
更大的 `https://mail.google.com/`。

官方资料：

- <https://developers.google.com/identity/protocols/oauth2/web-server>
- <https://developers.google.com/workspace/gmail/api/auth/scopes>

## 7. Microsoft Entra OAuth 客户端

在 Microsoft Entra admin center：

1. 在 **App registrations** 创建应用；
2. 选择单租户、多租户或个人 Microsoft 账号范围；
3. 添加 Web redirect URI `https://accounts.example.com/callback`；
4. 保存 Application (client) ID；
5. 在 **Certificates & secrets** 创建 secret；
6. 保存 secret 的 **Value**，不是 secret ID；
7. 添加 delegated permissions：`User.Read`、`Mail.Read`。

Scopes：

```text
openid
email
profile
offline_access
User.Read
Mail.Read
```

`Mail.Read` delegated permission读取当前用户邮箱，组织策略可能要求管理员同意。
单组织部署建议使用租户专用 endpoint；示例 `common` endpoint 适合配置为相应
多租户或个人账号范围的应用。

官方资料：

- <https://learn.microsoft.com/entra/identity-platform/quickstart-register-app>
- <https://learn.microsoft.com/entra/identity-platform/how-to-add-redirect-uri>
- <https://learn.microsoft.com/graph/permissions-reference>

## 8. OAuth 客户端 JSON

编辑 `secrets/oauth-clients.json`：

```json
[
  {
    "provider": "google",
    "clientId": "google-client-id",
    "clientSecret": "google-client-secret",
    "redirectUri": "https://accounts.example.com/callback",
    "scopes": "openid,email,profile,https://www.googleapis.com/auth/gmail.readonly",
    "authUrl": "https://accounts.google.com/o/oauth2/v2/auth",
    "tokenUrl": "https://oauth2.googleapis.com/token",
    "refreshClientId": "App实际使用的Google移动端Client ID",
    "refreshTokenUrl": "https://oauth2.googleapis.com/token"
  },
  {
    "provider": "microsoft",
    "clientId": "entra-application-client-id",
    "clientSecret": "entra-client-secret-value",
    "redirectUri": "https://accounts.example.com/callback",
    "scopes": "openid,email,profile,offline_access,User.Read,Mail.Read",
    "authUrl": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    "tokenUrl": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    "refreshClientId": "App实际使用的Microsoft移动端Client ID",
    "refreshTokenUrl": "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"
  }
]
```

校验规则：

- JSON 数组最多 16 个 provider；
- provider 由小写字母、数字、`_`、`-` 组成且不能重复；
- scopes 使用英文逗号分隔；
- auth、token 和生产 redirect URL 必须是 HTTPS；
- 仅 localhost、127.0.0.1、`::1` 的开发 redirect 可用 HTTP；
- 禁止未知字段、URL 用户名密码和 fragment；
- 启动时在事务内 upsert；
- JSON 省略旧 provider 不会删除数据库旧记录；
- 修改后必须重启容器。

`clientId`、`clientSecret`、`redirectUri`、`authUrl` 和 `tokenUrl` 属于
OAuth2ACF 自身的 Web OAuth 流程。`refreshClientId` 和 `refreshTokenUrl`
专门用于刷新 App 上传的移动端 refresh token，必须与 App
登录时使用的 OAuth Client ID 和权限一致。移动端 public client 不填写
`refreshClientSecret`；只有 App 本身使用 confidential client 签发 refresh token
时才填写该字段。`refreshScopes` 可选；默认省略以沿用 refresh token 原授权范围，
只有需要收窄权限时才配置。未配置 `refreshClientId` 的旧安装会继续回退到 Web OAuth
客户端，以保持升级兼容，但移动端和 Web Client ID 不同的部署会继续刷新失败。

## 9. 配置 .env

```dotenv
# Compose 会覆盖以下三个值。
OAUTH2ACF_LISTEN_ADDRESS=127.0.0.1:9090
OAUTH2ACF_DATABASE_PATH=./data/oauth2.db
OAUTH2ACF_CLIENTS_FILE=./secrets/oauth-clients.json

OAUTH2ACF_JWT_SECRET_FILE=/run/secrets/legacy-jwt-key
OAUTH2ACF_TOKEN_KEY_FILE=/run/secrets/token-encryption-key

OAUTH2ACF_PUSH_SIGNING_KEY_FILE=/run/secrets/push-signing-private.pem
OAUTH2ACF_PUSH_ISSUER=icchat-accounts
OAUTH2ACF_PUSH_AUDIENCE=icchat-push
OAUTH2ACF_PUSH_BROKER_KEY_FILE=/run/secrets/push-broker-key
```

| 变量 | 必需条件 | 说明 |
| --- | --- | --- |
| `OAUTH2ACF_LISTEN_ADDRESS` | 始终，由 Compose 覆盖 | 容器监听地址 |
| `OAUTH2ACF_DATABASE_PATH` | 始终，由 Compose 覆盖 | SQLite 路径 |
| `OAUTH2ACF_CLIENTS_FILE` | Compose 始终 | OAuth 客户端 JSON |
| `OAUTH2ACF_JWT_SECRET_FILE` | Compose 始终 | 旧登录 HS256 密钥文件 |
| `OAUTH2ACF_TOKEN_KEY_FILE` | Compose 始终 | 用户凭据加密根密钥文件 |
| `OAUTH2ACF_JWT_SECRET` | 兼容方式 | 与对应 `_FILE` 只能设置一个 |
| `OAUTH2ACF_TOKEN_KEY` | 兼容方式 | 与对应 `_FILE` 只能设置一个 |
| `OAUTH2ACF_PUSH_SIGNING_KEY_FILE` | 推送授权 | Ed25519 私钥 |
| `OAUTH2ACF_PUSH_ISSUER` | 推送授权 | 与 icchat-fcm 一致 |
| `OAUTH2ACF_PUSH_AUDIENCE` | 推送授权 | 与 icchat-fcm 一致 |
| `OAUTH2ACF_PUSH_BROKER_KEY_FILE` | 推送授权 | 与 icchat-fcm 共享 |

四个 `OAUTH2ACF_PUSH_*` 变量要么全部关闭，要么全部设置。正式 ICChat 部署应
全部启用。

## 10. 校验与构建

```bash
cd /opt/oauth2acf
test -s .env
test -s secrets/oauth-clients.json
test -s secrets/legacy-jwt-key
test -s secrets/token-encryption-key
test -s secrets/push-signing-private.pem
test -s secrets/push-broker-key
openssl pkey -in secrets/push-signing-private.pem -text -noout
python3 -m json.tool secrets/oauth-clients.json >/dev/null
sudo docker compose config --quiet
sudo docker compose build --pull
```

`docker compose config` 展开结果包含环境变量，不要上传完整输出。镜像使用
Go Alpine builder 编译 CGO SQLite 驱动，运行层只包含 Alpine、CA 根证书、
时区数据和二进制。

## 11. 首次启动

```bash
cd /opt/oauth2acf
sudo docker compose up -d --build
sudo docker compose ps
sudo docker compose logs --tail=100 oauth2acf
```

正常日志包括：

```text
OAuth client configuration imported
Version: compose
Server listening at 0.0.0.0:9090
```

查看健康详情：

```bash
sudo docker inspect \
  --format '{{json .State.Health}}' \
  "$(sudo docker compose ps -q oauth2acf)"
```

## 12. 健康检查

```bash
curl --fail --silent http://127.0.0.1:9090/healthz
curl --fail --silent http://127.0.0.1:9090/readyz
```

预期：

```json
{"status":"ok"}
{"status":"ready"}
```

`/healthz` 检查 HTTP 进程；`/readyz` 在两秒超时内 ping SQLite。两个响应都
设置 `Cache-Control: no-store`。

## 13. Nginx 反向代理

将 `10.20.0.0/16` 替换为 icchat-fcm 的真实网段：

```nginx
server {
    listen 443 ssl http2;
    server_name accounts.example.com;

    ssl_certificate     /etc/letsencrypt/live/accounts.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/accounts.example.com/privkey.pem;
    client_max_body_size 128k;

    location = /healthz {
        proxy_pass http://127.0.0.1:9090;
    }

    location = /readyz {
        allow 127.0.0.1;
        allow 10.20.0.0/16;
        deny all;
        proxy_pass http://127.0.0.1:9090;
    }

    location ^~ /internal/v1/ {
        allow 10.20.0.0/16;
        deny all;
        proxy_pass http://127.0.0.1:9090;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
    }

    location / {
        proxy_pass http://127.0.0.1:9090;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_connect_timeout 5s;
        proxy_read_timeout 35s;
    }
}
```

应用日志只记录 URL path，不记录 query string，避免 OAuth code 或 challenge
进入日志。反向代理也应配置不记录查询字符串。不要把 9090 直接发布到公网。

## 14. 对接 icchat-fcm

复制公钥和 broker key：

```bash
sudo install -o 10001 -g 10001 -m 0400 account-public.pem \
  /opt/icchat-fcm/secrets/account-public.pem
sudo install -o 10001 -g 10001 -m 0400 secrets/push-broker-key \
  /opt/icchat-fcm/secrets/push-broker-key
```

`icchat-fcm/.env`：

```dotenv
AUTH_PUBLIC_KEY_FILE=/run/secrets/account-public.pem
AUTH_ISSUER=icchat-accounts
AUTH_AUDIENCE=icchat-push

ACCOUNT_BROKER_URL=https://accounts.example.com
ACCOUNT_BROKER_KEY_FILE=/run/secrets/push-broker-key
```

内部 broker 接口：

```text
GET  /internal/v1/provider-connections
POST /internal/v1/provider-token
GET  /internal/v1/imap-connections
POST /internal/v1/imap-password
```

OAuth2ACF 与 icchat-fcm 之间必须使用 HTTPS。推荐顺序：

1. 启动 OAuth2ACF 并确认 `/readyz`；
2. 配置并启动 icchat-fcm；
3. 确认 icchat-fcm 能枚举空连接清单；
4. 发布带生产 URL 的 App。

## 15. 对接 ICChat App

生产构建：

```bash
flutter build apk \
  --dart-define=ICCHAT_PUSH_REGISTRATION_URL=https://push.example.com/v1/push/registrations \
  --dart-define=ICCHAT_PUSH_TOKEN_URL=https://accounts.example.com/v1/push/token
```

- registration URL 指向 icchat-fcm；
- token URL 指向 OAuth2ACF；
- 两个值必须同时设置；
- App 不持有私钥、broker key 或 `OAUTH2ACF_TOKEN_KEY`；
- App 将不透明会话保存在系统安全存储；
- 最后一个推送注册注销后，App 调用 `/v1/push/session`。

自建邮箱仅在密码认证、非 JMAP、IMAP TLS/STARTTLS 且实际只读登录成功时进入
远程监听。明文 IMAP、OIDC 和 JMAP 继续由 App 本地处理。

## 16. 接口访问边界

### 16.1 App 接口

```text
POST   /v1/push/token
DELETE /v1/push/session
```

`/v1/push/token` 验证 Google/Microsoft access token 或自建 IMAP 证明，然后：

- 加密保存 refresh token 或 IMAP 密码；
- 轮换不透明 session token；
- 返回十分钟有效 Ed25519 JWT；
- JWT `accountIds` 只包含已验证账号。

### 16.2 内部接口

```text
GET  /internal/v1/provider-connections
POST /internal/v1/provider-token
GET  /internal/v1/imap-connections
POST /internal/v1/imap-password
```

列表不返回 refresh token 或 IMAP 密码；密码只在 watcher 启动时按账号获取。
必须同时使用 broker key、HTTPS 和来源网络限制。

### 16.3 旧登录接口

```text
GET /authorize
GET /callback
GET /get_token
```

只有兼容客户端才需要。正式公网使用前必须评估第 1.2 节的限制。

## 17. 验收

### 17.1 HTTPS 与未授权边界

```bash
curl --fail --silent https://accounts.example.com/healthz
curl -i https://accounts.example.com/internal/v1/provider-connections
```

未授权 broker 请求应由 Nginx 返回 403，或由 OAuth2ACF 返回 401。

### 17.2 从 icchat-fcm 网络验证 broker

```bash
BROKER_KEY=$(sudo cat /opt/icchat-fcm/secrets/push-broker-key)
curl --fail --silent \
  -H "Authorization: Bearer $BROKER_KEY" \
  https://accounts.example.com/internal/v1/provider-connections
curl --fail --silent \
  -H "Authorization: Bearer $BROKER_KEY" \
  https://accounts.example.com/internal/v1/imap-connections
unset BROKER_KEY
```

新部署通常返回 `{"connections":[]}`。

### 17.3 真实账号验收

至少验证：

1. Google 登录和账号归属；
2. Microsoft 登录和 Graph `/me` 账号归属；
3. refresh token 可由 icchat-fcm 按需刷新；
4. 自建 TLS IMAP 登录、错误密码和证书错误；
5. App 增减账号时 JWT `accountIds` 和 broker 清单变化；
6. 撤销最后一个会话后连接记录删除；
7. OAuth client secret 更新后重启成功导入；
8. OAuth2ACF 重启后持久化会话仍可使用；
9. 日志没有 access token、refresh token、IMAP 密码或 OAuth code。

## 18. 日志与监控

```bash
sudo docker compose logs -f --tail=100 oauth2acf
```

应用日志记录 HTTP 方法、URL path、状态码、耗时和远端地址，不记录 query
string 或请求正文。

建议监控：

- Docker health 和 `/readyz`；
- HTTP 4xx/5xx 比例；
- provider userinfo、token refresh 与 IMAP 验证失败；
- SQLite 文件大小和磁盘空间；
- OAuth client secret、Ed25519 key、broker key 的轮换计划。

当前没有 Prometheus `/metrics`，可以从代理指标、容器健康和日志开始。

## 19. SQLite 备份

数据库包含 OAuth client secret、加密用户凭据、push session 和动态 IMAP
配置。备份必须加密并限制访问。

短暂停机后备份整个卷：

```bash
cd /opt/oauth2acf
mkdir -p backups
sudo docker compose stop oauth2acf
sudo docker run --rm \
  -v oauth2acf-data:/data:ro \
  -v "$PWD/backups:/backup" \
  alpine:3.23 \
  sh -c 'tar -czf /backup/oauth2acf-$(date -u +%Y%m%dT%H%M%SZ).tgz -C /data .'
sudo docker compose start oauth2acf

find backups -maxdepth 1 -name 'oauth2acf-*.tgz' -size +0 -ls
```

还必须备份：

- `token-encryption-key`；
- `push-signing-private.pem`；
- `push-broker-key`；
- `oauth-clients.json`；
- icchat-fcm 对应公钥。

只备份数据库但丢失加密根密钥，无法恢复 refresh token 和 IMAP 密码。

## 20. SQLite 恢复

先在隔离环境验证。正式恢复会覆盖数据卷：

```bash
cd /opt/oauth2acf
sudo docker compose down
sudo docker run --rm \
  -v oauth2acf-data:/data \
  -v "$PWD/backups:/backup:ro" \
  alpine:3.23 \
  sh -c '
    find /data -mindepth 1 -maxdepth 1 -delete &&
    tar -xzf /backup/<backup-file>.tgz -C /data &&
    chown -R 10001:10001 /data &&
    chmod 700 /data
  '
sudo docker compose up -d
curl --fail --silent http://127.0.0.1:9090/readyz
```

恢复必须使用备份对应的 `token-encryption-key`。错误密钥可能不影响启动，但
读取已有加密凭据会失败。

## 21. 升级

升级前备份数据库与 secrets：

```bash
cd /opt/oauth2acf
git status --short
git fetch origin
git log --oneline HEAD..origin/main
```

确认配置没有误放入版本控制文件，然后：

```bash
git pull --ff-only
sudo docker compose build --pull
sudo docker compose up -d
sudo docker compose ps
sudo docker compose logs --tail=100 oauth2acf
curl --fail --silent http://127.0.0.1:9090/readyz
```

表结构在启动时初始化。升级前仍需备份，因为未来 schema 不保证旧二进制可读。

## 22. 密钥轮换

### 22.1 OAuth client secret

1. 在 provider 控制台创建新 secret；
2. 更新 `secrets/oauth-clients.json`；
3. 保持 UID 10001、权限 0400；
4. 执行 `docker compose restart oauth2acf`；
5. 验证导入和 token refresh；
6. 撤销旧 secret。

### 22.2 Broker key

当前只接受一个 broker key，需要协调：

1. 生成新 key；
2. 更新 OAuth2ACF 与 icchat-fcm；
3. 停止 icchat-fcm monitor；
4. 重启 OAuth2ACF；
5. 启动 icchat-fcm；
6. 验证内部列表与 token 获取。

### 22.3 Ed25519 签名密钥

当前 icchat-fcm 只配置一个公钥：

1. 生成新私钥和公钥；
2. 短暂停止新注册流量；
3. 更新 OAuth2ACF 私钥和 icchat-fcm 公钥；
4. 重启两端；
5. App 在旧十分钟 JWT 到期后重新获取；
6. 验证注册和注销。

### 22.4 OAUTH2ACF_TOKEN_KEY

当前没有无缝轮换。不要直接修改。必须先实现双密钥解密和重加密迁移，或者
撤销并删除现有加密凭据、要求用户重新授权。

## 23. 常见故障

### 23.1 容器不断重启

```bash
sudo docker compose ps -a
sudo docker compose logs --tail=200 oauth2acf
```

常见原因：

- `legacy-jwt-key` 不存在，或 `_FILE` 路径错误；
- `oauth-clients.json` 不存在或错误；
- secrets 对 UID 10001 不可读；
- Ed25519 私钥不是 PKCS#8；
- broker key 少于 32 字符；
- 数据卷不可写。

### 23.2 invalid OAuth client configuration

```bash
python3 -m json.tool secrets/oauth-clients.json
```

检查未知字段、尾随逗号、重复 provider、空 scope 和非 HTTPS 生产 URL。服务
不会在日志中输出 client ID 或 secret。

### 23.3 Google redirect_uri_mismatch

Google 控制台和 JSON 必须完全匹配：

```text
https://accounts.example.com/callback
```

协议、域名、端口、路径和尾部斜杠都参与匹配。

### 23.4 Microsoft redirect 或 consent 错误

确认：

- 平台类型为 Web；
- redirect URI 完全匹配；
- 使用 secret Value 而不是 ID；
- account types 与 `common` 或租户 endpoint 相符；
- delegated permissions 包含 `User.Read`、`Mail.Read`；
- 需要时已获得 admin consent。

### 23.5 push signing key unavailable

```bash
sudo ls -l secrets/push-signing-private.pem
openssl pkey -in secrets/push-signing-private.pem -text -noout
```

确认 UID 10001 可读，并挂载到 `/run/secrets`。

### 23.6 icchat-fcm broker 未授权

比较哈希，不输出原文：

```bash
sudo sha256sum \
  /opt/oauth2acf/secrets/push-broker-key \
  /opt/icchat-fcm/secrets/push-broker-key
```

哈希应一致。还要检查 Nginx allow list。

### 23.7 动态 IMAP 验证失败

检查：

- 密码认证而非 OIDC；
- TLS 或 STARTTLS，不能明文；
- 主机解析到公网地址；
- 证书链与主机名有效；
- 用户名、密码和 INBOX 权限正确；
- 容器能访问 IMAP 端口。

为阻止 SSRF 和 DNS rebinding，动态 IMAP 拒绝内网、环回、链路本地和运营商
NAT 地址，连接已验证公网 IP，并保留原主机名做 TLS SNI。

### 23.8 readyz 失败

```bash
sudo docker compose logs --tail=100 oauth2acf
sudo docker run --rm -v oauth2acf-data:/data:ro alpine:3.23 ls -la /data
```

检查磁盘、数据卷权限和 SQLite 文件。不要在服务运行时用外部 SQLite 工具修改
数据库。

### 23.9 修改 JSON 后没有生效

```bash
sudo docker compose restart oauth2acf
sudo docker compose logs --tail=50 oauth2acf
```

配置只在启动时导入；JSON 省略 provider 不会删除旧记录。完全移除 provider
需要停服、备份，再做受控数据库维护。

### 23.10 Docker health 为 unhealthy

```bash
sudo docker inspect \
  --format '{{range .State.Health.Log}}{{println .Output}}{{end}}' \
  "$(sudo docker compose ps -q oauth2acf)"
curl -i http://127.0.0.1:9090/readyz
```

确认进程仍监听 `0.0.0.0:9090`。

## 24. 停止与卸载

停止并保留数据卷：

```bash
sudo docker compose down
sudo docker volume inspect oauth2acf-data
```

不要在生产环境随意执行：

```text
docker compose down -v
docker volume rm oauth2acf-data
```

这些命令会删除数据库。卸载前必须完成并验证备份。

## 25. 上线检查表

- [ ] 使用独立 HTTPS 域名；
- [ ] 9090 只绑定 `127.0.0.1`；
- [ ] `/internal/v1/` 只允许 icchat-fcm 来源；
- [ ] 未提交 `.env`、OAuth secret、Ed25519 私钥或 broker key；
- [ ] UID 10001 能读取 secrets；
- [ ] JWT secret 与 Token key 不相同；
- [ ] Token key 已进入异机加密备份；
- [ ] 公私钥、issuer、audience 与 icchat-fcm 对齐；
- [ ] broker key 哈希一致；
- [ ] Google/Entra redirect URI 完全匹配；
- [ ] Gmail restricted scope 已完成审核或限制测试用户；
- [ ] Microsoft permissions 与 consent 已配置；
- [ ] healthz、readyz 与 Docker health 正常；
- [ ] 日志不包含 query、token、密码或 OAuth code；
- [ ] 完成数据库与 secrets 恢复演练；
- [ ] 完成真实 Google、Microsoft、自建 IMAP 和 App 真机验收；
- [ ] 已评估旧 OAuth 流安全限制；
- [ ] 保持单实例；
- [ ] 系统时间同步正常。

## 26. 相关文件

- [`.env.example`](../.env.example)：环境变量模板；
- [`oauth-clients.example.json`](../oauth-clients.example.json)：OAuth 客户端模板；
- [`compose.yaml`](../compose.yaml)：Docker Compose；
- [`Dockerfile`](../Dockerfile)：多阶段构建；
- [`README.md`](../README.md)：接口概览。
