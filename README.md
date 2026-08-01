# simple-proxy

一个只使用 Go 标准库实现的简单代理服务器：

- SOCKS5 代理：默认 `127.0.0.1:1080`
- HTTP/HTTPS 代理：默认 `127.0.0.1:8080`
- 可选的用户名/密码鉴权，同时用于 SOCKS5 和 HTTP/HTTPS 代理
- SOCKS5 仅支持 CONNECT
- HTTPS 通过 HTTP CONNECT 隧道转发，不解密 TLS

## 启动

```bash
go run .
```

或者：

```bash
go build -o simple-proxy .
./simple-proxy
```

## 自定义监听地址

```bash
./simple-proxy \
  -socks 127.0.0.1:1080 \
  -http 127.0.0.1:8080
```

禁用其中一种代理：

```bash
./simple-proxy -socks ""
./simple-proxy -http ""
```

## 启用鉴权

用户名和密码必须同时配置。推荐通过环境变量传入，避免密码出现在进程参数中：

```bash
SIMPLE_PROXY_USER=alice \
SIMPLE_PROXY_PASSWORD='change-me' \
./simple-proxy
```

也可以使用命令行参数：

```bash
./simple-proxy -auth-user alice -auth-password 'change-me'
```

两项都未配置时不启用鉴权，以保持默认的本机免认证用法。

## 测试

SOCKS5：

```bash
curl --proxy socks5h://127.0.0.1:1080 https://example.com
```

启用鉴权后：

```bash
curl --proxy socks5h://127.0.0.1:1080 --proxy-user 'alice:change-me' https://example.com
```

HTTP：

```bash
curl --proxy http://127.0.0.1:8080 http://example.com
```

HTTPS：

```bash
curl --proxy http://127.0.0.1:8080 https://example.com
```

HTTP 和 HTTPS 启用鉴权后的用法相同：

```bash
curl --proxy http://127.0.0.1:8080 --proxy-user 'alice:change-me' https://example.com
```

## GitHub Actions 构建

`.github/workflows/build.yml` 会在推送到 `main`、推送 `v*` 标签、Pull Request 或手动触发时运行测试，并构建以下二进制归档：

- Linux：amd64、arm64
- macOS：amd64、arm64
- Windows：amd64、arm64

构建结果可从对应 GitHub Actions 运行记录的 Artifacts 中下载。

## 安全说明

默认仅监听本机地址。HTTP Basic 和 SOCKS5 用户名/密码认证都不会加密客户端到代理之间的凭据和流量；如需远程使用，应放在可信网络、VPN 或 TLS 隧道内。该项目没有流量限制和审计能力，不要仅凭这层简单鉴权直接暴露到公网。
