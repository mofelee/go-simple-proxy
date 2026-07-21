# simple-proxy

一个只使用 Go 标准库实现的简单代理服务器：

- SOCKS5 代理：默认 `127.0.0.1:1080`
- HTTP/HTTPS 代理：默认 `127.0.0.1:8080`
- SOCKS5 仅支持 CONNECT，无认证
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

## 测试

SOCKS5：

```bash
curl --proxy socks5h://127.0.0.1:1080 https://example.com
```

HTTP：

```bash
curl --proxy http://127.0.0.1:8080 http://example.com
```

HTTPS：

```bash
curl --proxy http://127.0.0.1:8080 https://example.com
```

## 安全说明

默认仅监听本机地址。该示例没有身份验证、访问控制、流量限制和审计能力，不要直接绑定到公网地址。
