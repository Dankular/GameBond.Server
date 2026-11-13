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

## Changelog

Newest first. The server has no version tags: a release is a commit on `main`, built into
`ghcr.io/dankular/gamebond-server:<commit>`, and that commit is what the server reports to clients. Each entry was
written from the diff of that commit. Add an entry under **Unreleased** with every change that alters behaviour and
give it the commit once it is pushed. Most commits here only move the [GameBond.Core](https://github.com/Dankular/GameBond.Core)
pin; the Core changelog has the detail, summarised below.

### Unreleased
- Nothing yet.

### 2026-11-12, Core v0.1.5 to v0.1.17
- `1df93fe` Core v0.1.17: a line is no longer declared down because BFD frames were lost while data still arrives.
- `dbc77fe` Core v0.1.16: loss feedback is sent the moment a gap shows, supervision frames keep their cadence through bursts.
- `d09cb1f` Core v0.1.15: receiver feedback now carries the selective-ack bitmap (it was never filled in).
- `c61794a` Core v0.1.14: redundancy copies still go to a BFD-down line, so a false failure cannot leave one copy.
- `b880fff` Core v0.1.13: stream acks no longer walk the whole connection history (this skips v0.1.12, which only added drop counters).
- `3527a44` Core v0.1.11: gentler stream delay shrink, 4 MiB windows.
- `11418f1` Core v0.1.10: striping only while every path is calm.
- `b91d10d` Core v0.1.9: striped flows protected by adaptive parity.
- `7369d12` Core v0.1.8 and **new config key `stripe_above_mbps`** (0 to 1000, 0 keeps every flow duplicated): a bulk flow above
  this sustained rate is split across the paths instead of duplicated. Out-of-range values are rejected at load.
- `fce91f3` Core v0.1.7: bonded TCP is delivered on first arrival.
- `66e74fc` Core v0.1.6: IEC 62439-3 / 802.1CB elimination window, UDP first-arrival, supervision frames.
- `41142b6` **stream moved to Core v0.1.5**: 1,889 lines (`stream/conn.go`, `endpoint.go`, `gateway.go`) removed from this
  repo; `cmd/edge` imports Core's `stream`.
- `ec1abdc` Core v0.1.4 and **CAKE egress queue.** `tools/container-entrypoint.sh` sets CAKE with `diffserv4 flows ecn` on the WAN
  device and `gamebond0` (falls back to `fq_codel ecn`, then continues without). Set `GAMEBOND_EGRESS_MBIT` to shape to a known
  uplink; unset leaves it unshaped.
- `5c5f826` Core v0.1.3: assertive delay floor 40 ms, copy-carrying paths can grow.
- `f1af690` Core v0.1.2: fixed 10% delay back-off, deeper bulk queue.

### 2026-11-12, hardening (merge of PR #1, `c5efc5e`)
- `b2f8215` **stream: acknowledge only stored data.** An ack for data that was discarded made the sender drop it from its
  retransmission state and the stream stalled. Reaped or failed streams now release the upstream socket, and the gateway
  refuses destinations that are not globally routable unicast IPv4 (loopback, RFC 1918, link-local, CGNAT, multicast,
  reserved), checked on the address actually connected to.
  `GAMEBOND_STREAM_ALLOW_PRIVATE=1` turns it off; `GAMEBOND_STREAM_LOG_INTERVAL` sets how often a stream logs (default 10 s).
- `3e24644` **adminportal:** password hashing is bounded (scrypt needs about 32 MiB each, so a parallel burst of logins could exhaust the
  container); a config save is read back and the old text restored if it differs, so a short write cannot leave a file the
  entrypoint refuses to start from.
- `6ec3098` **edge:** transient receive errors (buffer or memory pressure, ICMP surfaced on read) no longer stop the server;
  opt-in Prometheus metrics with `GAMEBOND_METRICS_ADDR`, loopback IPv4 only because the endpoint has no authentication.
- `01963b9` **deploy:** the update probe doubles as a watchdog (recreates the container after 3 bad polls, at most 3 times per 600 s,
  never during an update, paused by a `hold` file); the container entrypoint filters forwarded traffic so tunnel clients cannot
  reach the container bridge, the Docker host or private ranges (`GAMEBOND_ALLOW_PRIVATE_FORWARD=1` turns it off); the probe's
  update lock is released after each update (it used to stay held); a proposed CI workflow adds a test gate in `tools/ci/`.

### 2026-11-12, Core v0.1.0 and v0.1.1
- `24b7f2c` Core v0.1.1: rate controller ramps through random loss, CoDel sized for LEO paths.
- `66f4fb7` Depends on the published GameBond.Core v0.1.0; builds with Go 1.26.
- `cb040c5` Initial import of the server from GameBond.Client: `cmd/edge`, `edge`, `adminportal`, `adminauth`, `stream`, `tools`
  (entrypoint, probe, systemd unit), Dockerfile and the image workflow (38 files, 5,247 lines).
