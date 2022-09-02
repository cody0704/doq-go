# doq-go

This is a simple DoQ (DNS over QUIC) Proxy to DNS Server

## Env

- Go: v1.19

## Test

### Server

```bash
go run main.go
```

### Client

- kdig: v3.2.0

```bash
kdig @127.0.0.1:853 +quic www.google.com
```
