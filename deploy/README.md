# Deployment

## Docker

The Dockerfile defines two final targets sharing the same dependency cache:

- `node` — the storage server (`ferriskv-node`)
- `cli`  — the client (`ferriskv`)

Build whichever you need:

```sh
docker build --target node -t ferriskv-node:latest .
docker build --target cli  -t ferriskv-cli:latest  .
```

Run the server with a mounted config and a named data volume:

```sh
docker run --rm \
  -p 7100:7100 -p 7101:7101 \
  -v ferriskv-data:/var/lib/ferriskv \
  -v "$PWD/config/node.toml:/etc/ferriskv/node.toml:ro" \
  ferriskv-node:latest
```

Run the CLI against a running server (host networking, or pass `--endpoint`):

```sh
docker run --rm --network host ferriskv-cli:latest \
  --endpoint http://127.0.0.1:7100 --tenant alice get hello
```

The container runs as a non-root user (`ferriskv`, uid 10001) and expects:

- Config at `/etc/ferriskv/node.toml`
- Data under `/var/lib/ferriskv` (`data_dir` in the config should point here)
- gRPC on port `7100`, admin HTTP (`/healthz`, `/readyz`, `/metrics`) on `7101`
  when `admin_listen = "0.0.0.0:7101"` is set in the config

A typical container-friendly config:

```toml
node_id = "node-0"
listen = "0.0.0.0:7100"
admin_listen = "0.0.0.0:7101"
data_dir = "/var/lib/ferriskv"
backend = "fjall"
ttl_sweep_interval_secs = 60
shutdown_timeout_secs = 30
```

## systemd

Install the binary and unit:

```sh
sudo install -Dm0755 target/release/ferriskv-node /usr/local/bin/ferriskv-node
sudo install -Dm0644 deploy/systemd/ferriskv-node.service /etc/systemd/system/ferriskv-node.service
sudo useradd --system --no-create-home --shell /usr/sbin/nologin ferriskv
sudo install -Dm0640 -o ferriskv -g ferriskv config/node.toml /etc/ferriskv/node.toml
sudo systemctl daemon-reload
sudo systemctl enable --now ferriskv-node
```

The unit creates `/var/lib/ferriskv` (state) and `/etc/ferriskv` (config) with
the right ownership via `StateDirectory` / `ConfigurationDirectory`. Point
`data_dir` in `node.toml` at `/var/lib/ferriskv`.

Logs go to the journal:

```sh
journalctl -u ferriskv-node -f
```

The unit applies a strict sandbox (`ProtectSystem=strict`, `NoNewPrivileges`,
read-only root, no devices, restricted syscalls). If you add a new feature that
needs broader access (e.g. raw sockets, debug syscalls), loosen the filters
explicitly rather than disabling them wholesale.
