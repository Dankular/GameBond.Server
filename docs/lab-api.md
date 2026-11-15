# Lab REST API

The Server admin portal exposes the single-host lab manager as a same-origin JSON API. The Speedify
dashboard uses this API through its certificate-pinned Server admin client; Ansible and Python can use
the same endpoints directly.

## Login

Send `POST /api/login` with `{"username":"...","password":"..."}`. Keep the returned
`gb_session` cookie and the `csrf` value in the JSON response. Send both on later requests, with
`X-CSRF-Token: <csrf>` on every POST. The legacy one-password configuration accepts username `admin`.

## Topologies

- `GET /api/labs/topologies` lists definitions saved for the authenticated user's team.
- `POST /api/labs/topologies` with `{"topology": <Topology>}` validates and saves a definition.
- `POST /api/labs/apply` with `{"topology": <Topology>}` stages and applies a new runtime generation.
- `GET /api/labs/status` returns per-node and per-link state and telemetry.
- `POST /api/labs/action` accepts an action and its arguments:
  - `pause`, `resume`, `rollback`
  - `restart-node` with `node`
  - `link-down`, `link-up` with `link`
  - `link-flap` with `link` and `duration_ms`
  - `set-impairment` with `link` and `impairment`
  - `interface-errors` with `node`, `interface`, and `impairment` containing `loss_pct` and/or `corrupt_pct`
- `POST /api/labs/check` runs the topology's declared assertions.
- `POST /api/labs/capture` with `link` and `duration_ms` returns a bounded `pcap_base64` capture.
- `GET /api/labs/console?node=<id>` upgrades to a same-origin WebSocket terminal for an editor or admin.
- `GET /api/labs/users?team=<id>` lists account names and roles for a team admin; system admins may
  choose any configured team.
- `POST /api/labs/users` with `action: create|delete`, `username`, `password` (create), and `role`
  manages team members. Team admins may create editors/viewers. System admins may also create a
  team-admin for a team. The target `team` is optional for the caller's own team.
- `POST /api/account/password` with `current` and `new` changes the signed-in account password.

Topology JSON uses version 1. Nodes declare roles (`host`, `router`, `switch`), interfaces and optional
daemon configs. Links connect one unused interface on each endpoint and can declare latency, jitter,
loss, corruption and bandwidth. The Go schema in `lab/topology.go` is authoritative and rejects
unknown fields, invalid references, duplicate addresses/endpoints, and out-of-range impairment values.
Available node daemons are `frr`, `mstpd`, `keepalived`, `hostapd`, `wpa_supplicant`, `snmpd`, and
`sflow`. `snmpd` requires explicit Net-SNMP configuration in `daemon_config.snmpd` so the lab author
chooses its access policy. `sflow` requires JSON in `daemon_config.sflow`, for example
`{"collector":"192.0.2.10:6343","agent_ip":"192.0.2.1","polling_seconds":30}`; it sends sFlow v5
generic interface counter samples for the node's interfaces. Configure the collector as a reachable
node in the topology; `agent_ip` is required when the first interface has no IPv4 address.

## Python example

```python
import http.cookiejar
import json
import urllib.request

base = "https://gamebond.example:8443"
cookies = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies))

def request(path, body=None, csrf=None):
    data = None if body is None else json.dumps(body).encode()
    headers = {"Content-Type": "application/json"}
    if csrf:
        headers["X-CSRF-Token"] = csrf
    req = urllib.request.Request(base + path, data=data, headers=headers)
    with opener.open(req) as response:
        return json.load(response)

identity = request("/api/login", {"username": "lab-editor", "password": "replace-me"})
csrf = identity["csrf"]
topology = {
    "version": 1,
    "id": "two-hosts",
    "name": "Two hosts",
    "nodes": [
        {"id": "left", "name": "Left host", "role": "host", "interfaces": [{"id": "eth0", "addresses": ["192.0.2.1/24"]}]},
        {"id": "right", "name": "Right host", "role": "host", "interfaces": [{"id": "eth0", "addresses": ["192.0.2.2/24"]}]},
    ],
    "links": [
        {"id": "wire", "a": {"node": "left", "interface": "eth0"}, "b": {"node": "right", "interface": "eth0"}, "impairment": {"latency_ms": 15, "loss_pct": 0.5}},
    ],
}
request("/api/labs/topologies", {"topology": topology}, csrf)
request("/api/labs/apply", {"topology": topology}, csrf)
print(request("/api/labs/status"))
```

Use a certificate-verifying TLS context for production automation; the example leaves Python's default
certificate verification enabled. Viewer users may list/status, capture packets, and run checks.
Editors may change their team's topology and operate its runtime. Team admins can manage editor/viewer
accounts in the Labs page. No lab endpoint accepts a command string; node shell access is provided only
through the authenticated interactive console.
