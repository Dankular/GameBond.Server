# GameBond.Server

The GameBond edge server: the `cmd/edge` binary, its container image, and the update probe.

- Image: built by GitHub Actions on every push to `main` and published as
  `ghcr.io/dankular/gamebond-server:<commit>` (the commit is also what the server reports to clients).
- `tools/server-probe.sh` + `tools/gamebond-probe.service`: run on the VPS; watch this repo's
  `server-image` workflow and, on a new successful build, pull the image, recreate the container,
  wait for readiness and roll back if it does not come up.
- Shared protocol code lives in [GameBond.Core](https://github.com/Dankular/GameBond.Core);
  the client is [GameBond.Client](https://github.com/Dankular/GameBond.Client).

## Operations notes

Environment variables read by the edge (all optional):

| Variable | Effect |
| --- | --- |
| `GAMEBOND_STREAM=0` | do not start the TCP stream gateway |
| `GAMEBOND_STREAM_ALLOW_PRIVATE=1` | let the gateway connect to private/loopback/reserved addresses (refused by default) |
| `GAMEBOND_STREAM_LOG_INTERVAL` | how often an active stream logs its counters (Go duration, default `10s`, minimum `1s`) |
| `GAMEBOND_METRICS_ADDR` | serve Prometheus metrics on this **loopback IPv4** `host:port` (e.g. `127.0.0.1:9100`); reach it with `docker exec` or publish it deliberately |

Container entrypoint: `GAMEBOND_ALLOW_PRIVATE_FORWARD=1` disables the forward filter that stops tunnel
clients reaching private ranges (the container bridge, the Docker host, RFC 1918, ...) through the server.
Traffic between tunnel addresses is still forwarded.

Probe watchdog: while watching, `tools/server-probe.sh` recreates the container after
`GAMEBOND_WATCHDOG_STRIKES` (3) consecutive polls where it is exited, missing or unhealthy, at most
`GAMEBOND_WATCHDOG_MAX_RESTARTS` (3) times per `GAMEBOND_WATCHDOG_WINDOW` (600 s). It does nothing during an
update. `touch /var/lib/gamebond-probe/hold` pauses it, for example while you stop the container on purpose.

Tests: `go test ./...` (CI also runs `go vet`, `gofmt -l`, `-race`), `bash tools/test-probe.sh` (watchdog and
update lock against a fake `docker`), and `sudo bash tools/test-forward-filter.sh` (forward filter in network
namespaces; needs root, `ip`, `nft`, `ping`).

**CI gate (needs one manual step):** the probe deploys whatever `main` publishes, and the live
`.github/workflows/server-image.yml` builds and pushes the image without running any tests.
`tools/ci/server-image.yml` is the replacement: it adds a `test` job (gofmt, vet, build, `go test -race`, the shell
tests) that the `image` job needs, and also runs on pull requests. It is kept here because the automation that
prepared it could not push to `.github/workflows/` (the token lacks the `workflow` scope). Install it with:

```bash
cp tools/ci/server-image.yml .github/workflows/server-image.yml
```
