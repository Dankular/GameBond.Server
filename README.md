# GameBond.Server

The GameBond edge server: the `cmd/edge` binary, its container image, and the update probe.

- Image: built by GitHub Actions on every push to `main` and published as
  `ghcr.io/dankular/gamebond-server:<commit>` (the commit is also what the server reports to clients).
- `tools/server-probe.sh` + `tools/gamebond-probe.service`: run on the VPS; watch this repo's
  `server-image` workflow and, on a new successful build, pull the image, recreate the container,
  wait for readiness and roll back if it does not come up.
- Shared protocol code lives in [GameBond.Core](https://github.com/Dankular/GameBond.Core);
  the client is [GameBond.Client](https://github.com/Dankular/GameBond.Client).
