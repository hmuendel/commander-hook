# commander-hook

Is a very simple tool that lets you execute local command via an https webhook.

## Quickstart

All we need is a tls cert and key. We could get a self signed one like this
```bash
openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout key.pem -out cert.pem
```

Then we start commander-hook
```bash
commander-hook ls

Using cert at:    ./cert.pem,                        set CMD_HOOK_CERT to change
Using key at:     ./key.pem,                         set CMD_HOOK_KEY to change
Using auth secret: eGgbS2FO1DipFwIH85GDmfTzNOGI7tst, set CMD_HOOK_SECRET to change
Using host:        localhost,                        set CMD_HOOK_HOST to change
Using port:        8080,                             set CMD_HOOK_PORT to change
```

And then we can let the commander do it's work

```bash
curl https://localhost:8080 -kH authorization:eGgbS2FO1DipFwIH85GDmfTzNOGI7tst

Cargo.lock
Cargo.toml
cert.pem
key.pem
README.md
src
target
```
