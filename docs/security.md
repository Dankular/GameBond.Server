# Security: firewall, DNS filter, intrusion detection

Everything here runs in the server process and is managed from the client's GUI (Network Scanner, Security) through
the admin portal. Settings live in the `security` key of the server config. Saving from the portal applies them
live and then stores them, keeping the other keys and their order; a configuration that does not validate, or that
nftables refuses, changes nothing (all of it applies or none of it does).

```json
"security": {
  "firewall":   { "enabled": true, "default_outbound": "allow", "default_inbound": "allow",
                  "block_dot": false, "force_dns": false,
                  "segmentation": { "isolate_devices": false, "allow": [{ "from": "gaming", "to": "lab" }] },
                  "zones": [{ "name": "gaming", "members": ["10.77.0.3"] }],
                  "rules": [{ "id": "no-telnet", "enabled": true, "action": "deny", "direction": "outbound",
                              "source": "any", "dest": "any", "proto": "tcp", "ports": ["23"], "comment": "" }],
                  "countries": { "mode": "off", "codes": [], "direction": "outbound" } },
  "dns_filter": { "enabled": true, "categories": ["ads", "trackers", "malware"], "enable_lists": [], "disable_lists": [],
                  "custom_lists": [], "block": [], "allow": [], "exempt": [], "block_mode": "nxdomain",
                  "upstreams": ["1.1.1.1:53", "9.9.9.9:53"], "refresh_hours": 12 },
  "ids":        { "mode": "detect", "sensitivity": "medium", "block_minutes": 10, "never_block": [], "detectors": {} }
}
```

Unknown keys are refused, so a typo cannot leave a protection silently off.

## Firewall (`firewall/`)

One nftables table, `gamebond_fw`, replaced atomically. A forwarded packet meets, in order: invalid state (drop),
addresses blocked by intrusion prevention (drop, even on open connections), blocked countries (drop),
established/related (accept: replies need no rule), DNS-over-TLS block, your rules (new connections only, first match
wins), segmentation exceptions, device isolation, then the default policy. The server itself is protected from the
tunnel network except for the bond port, DNS (tcp/udp 53 to 10.77.0.1) and ping. Changing a rule does not end a
connection that is already open; the GUI offers "End open connections" (conntrack).

Tested in real network namespaces (`firewall/ns_test.go`, needs root, ip, nft, python3): rule order and counters,
default deny, segmentation one way, country block and allow-only, prevention block surviving a rule change and
lifting, DoT, inbound default deny, forced DNS reaching a listener on 10.77.0.1:53, and removal when switched off.

Limits: 200 rules, 32 zones. Zone members must be 10.77.0.2 to 10.77.0.254 (10.77.0.2 is the client PC).
DNS over HTTPS cannot be blocked by port and is not.

## Country filter (`geoip/`)

Aggregated per-country lists from ipdeny.com, fetched over https, cached under `/tmp/gamebond-geo` (tmpfs), refreshed
daily, stale data kept on failure. Allow-only mode with no data loaded is skipped with a warning rather than
black-holing the tunnel. Accuracy is that of the lists.

## DNS filter (`dnsfilter/`)

A DNS server on 10.77.0.1:53 forwards to `upstreams` and answers NXDOMAIN (or 0.0.0.0/::) for names on the active
lists. Devices use it when their DNS is 10.77.0.1, or all devices do with `firewall.force_dns` (redirects port 53).
Lists are fetched at runtime and never copied into this repository; each is conditional-GET refreshed
(`refresh_hours`), stale data is kept on failure, and only https URLs that do not resolve to private addresses are
fetched. Domains are held as 64-bit hashes (about 8 bytes each, capped at 8 million active). One tolerant parser
reads hosts files, plain domain lists, wildcard lists and the domain rules of ad-block lists (`||host^`); cosmetic
rules, paths, patterns, browser-only options and `@@` exceptions are skipped. A domain on several lists is counted
once and credited to the first.

| Project | Licence (as checked) | Used as |
|---|---|---|
| StevenBlack/hosts | MIT | unified hosts and extensions |
| hagezi/dns-blocklists | GPL-3.0 | wildcard lists via jsDelivr |
| AdguardTeam/AdGuardSDNSFilter | GPL-3.0 | filter.txt |
| blocklistproject/Lists | Unlicense | per-category lists |
| easylist/easylist | not verified | EasyList/EasyPrivacy, DNS-expressible rules only |
| badmojr/1Hosts | MPL-2.0 | Lite and Xtra |
| Perflyst/PiHoleBlocklist | MIT | smart TV and Android lists |
| sjhgvr/oisd | unconfirmed | domainswild2 |
| AdAway | GPLv3+ (project) | hosts file |
| mullvad/dns-blocklists | not verified | reference only: no downloadable list could be verified |

Because the lists are fetched from their publishers at runtime, nothing here redistributes them; they stay under
their authors' licences. Regex lists are not supported. With every default list of all twelve categories enabled the
process peaked near 95 MB resident in a test (container limit 256 MB); a very large custom selection will use more.

## Intrusion detection and prevention (`ids/`)

Follows the vocabulary of NIST SP 800-94: this is network behaviour analysis (flow and header behaviour, plus
DNS questions), not payload inspection, so it cannot recognise a specific exploit. Ten detectors (port scan, SYN
flood, UDP flood, ICMP flood, brute force, risky port, inbound scan, inbound flood, DNS anomaly, upload anomaly), each
with an action (alert or block) and threshold; `sensitivity` scales every threshold. Modes: `off`, `detect`,
`prevent`. Prevention adds the address to a timed block set in the firewall, longer each repeat within 24 h (cap 24 h).
10.77.0.1, 10.77.0.2 and `never_block` are never blocked. Blocking needs the firewall to be on.

## Container

`compose.yaml` adds `NET_BIND_SERVICE` (all capabilities are otherwise dropped) so the filter can bind port 53;
`conntrack` is in the image. Not verified: running the full container end to end with the filter bound to 10.77.0.1:53
on real hardware, and a real client's LAN devices using 10.77.0.1 as DNS through the client's gateway.
