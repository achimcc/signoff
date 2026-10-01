# signoff

Is the service really done?

A service that is deployed, green in `systemctl` and answering on its own
port can still be unusable: its name resolves to the CDN's wildcard instead
of the VPS, the VPS's SNI map does not know it, the reverse proxy cannot
reach its backend across a zone edge, the identity provider's outpost does
not carry its provider, no backup snapshot exists yet, or the vendor's
default account still logs in. Each of these has happened here, each with a
green deploy. `signoff check <service>` asks these questions live, in one
call, with one verdict per question.

## Usage

```
usage: signoff [--config /etc/signoff.toml] check (<service>… | --all)
       signoff [--config …] plan  (<service>… | --all)
       signoff rules
       signoff --help | --version

Runs on the host as root. Exit 0: everything measured, everything ok.
Exit 1: at least one `failed`. Exit 2: a control or a measurement could not
be taken — the run says nothing complete.
```

`check` runs the measurements for real, against the live host. `plan` prints
the command (or the `n/a`/`undeclared` reason) for each measurement without
running anything — useful to see what `check` is about to do, or to debug a
declaration in `/etc/signoff.toml`. `--config` points at the rendered
configuration; it defaults to `/etc/signoff.toml`. `check` and `plan` both
need either one or more service keys or `--all`, never both.

## The seven measurements

| Check | How | Only when |
|---|---|---|
| `dns-a`, `dns-aaaa` | `dig @<resolver>`: the name must resolve to the VPS — the zone carries a wildcard, so "some record" proves nothing | `public` |
| `public-path` | `curl --resolve <host>:443:<vps>`: any HTTP status is ok, the home proxy answered; curl exit 35 "unrecognized name" means the VPS's default vhost refused — the name is not in the SNI map; curl exit 60/51 (certificate not verifiable, host not in the certificate) is a finding too, not `cannot measure` | `public` |
| `backend` | `vantage probe --from <proxy guest> <guest>:<port>`: `answered` is ok; `refused` / `dropped at zone edge` / `dropped elsewhere` are findings | a `backend` and `backend_guest` are declared |
| `outpost` | a proxy provider with `external_host https://<host>` exists and the embedded outpost carries it | `forward_auth` |
| `backup` | the newest rustic snapshot for the guest's dataset is younger than `snapshot_max_age_hours` | always |
| `factory-login` | the declared vendor default account is tried against the backend and must be rejected — with the HOST's `curl`, in the guest's network namespace (`nsenter -t <leader> -n`), so a taken-over guest cannot fake the verdict with its own `curl`. With `reject_body`, a status in `reject` only counts as a rejection when the body contains that text (a service that answers a wrong login with HTTP 200). `no_factory_login = "<reason>"` instead of a probe → `n/a: <reason>`; neither of the two → `undeclared` | `factory_login` is declared |

### Verdicts

- `ok` — measured, as expected.
- `failed` — measured, not as expected: a finding (exit 1).
- `cannot measure` — the path to the answer did not carry (exit 2).
- `n/a: <why>` — not applicable to this service (not public, no backend, no
  `forward_auth`, or a `no_factory_login` reason — then `<why>` is that
  reason); never changes the exit code.
- `undeclared` — `factory-login` only: neither a probe nor a
  `no_factory_login` reason is declared — a hint, not green. With
  `undeclared_is_failure = true` the line reads `failed` instead and the
  run exits 1.

## Example output

```
$ signoff check ghostfolio
ghostfolio      dns-a           ok               77.42.71.141
ghostfolio      dns-aaaa        ok               2a01:4f9:c013:5ee7::1
ghostfolio      public-path     ok               HTTP 302 via 77.42.71.141
ghostfolio      backend         ok               answered 301 (infra-01 -> fin-01:3333)
ghostfolio      outpost         ok               provider 126 "Ghostfolio (Forward-Auth)" attached to authentik Embedded Outpost
ghostfolio      backup          ok               newest 2026-09-23T04:40:35.297023632+02:00, 5 h old (2 snapshots)
ghostfolio      factory-login   ok               HTTP 401: factory account rejected
7 ok, 0 failed, 0 n/a, 0 undeclared, 0 cannot measure
```

One line per service and measurement, then a summary line. A service that is
not public and has no `forward_auth` (e.g. `radarr` in the example
configuration below) prints `n/a` for `dns-a`, `dns-aaaa`, `public-path` and
`outpost`, and `undeclared` for `factory-login` unless a probe or a
`no_factory_login` reason is declared —
`backend` and `backup` still run, because those apply regardless of whether
the service is public.

## Configuration

`signoff` reads a TOML file, normally rendered by the host's Nix
configuration to `/etc/signoff.toml`. Top-level fields:

```toml
zone = "rusty-vault.de"
resolver = "1.1.1.1"
vps_v4 = "77.42.71.141"
vps_v6 = "2a01:4f9:c013:5ee7::1"
caddy_guest = "infra-01"
auth_guest = "auth-01"
auth_api = "http://127.0.0.1:9000/api/v3"
outpost = "authentik Embedded Outpost"
rustic_profile = "/etc/rustic/rustic"
snapshot_max_age_hours = 48

[[service]]
key = "ghostfolio"
host = "ghostfolio.rusty-vault.de"
guest = "fin-01"
public = true
backend = "10.0.190.10:3333"
backend_guest = "fin-01"
forward_auth = true
dataset = "rpool/guests/fin-01"

[service.factory_login]
method = "POST"
path = "/api/auth/token"
content_type = "application/x-www-form-urlencoded"
body = "username=changeme%40example.com&password=MyPassword"
reject = [401, 403]

[[service]]
key = "radarr"
host = "radarr.rusty-vault.de"
guest = "media-01"
public = false
backend = "10.0.10.10:7878"
backend_guest = "media-01"
forward_auth = false
dataset = "rpool/guests/media-01"

[[service]]
key = "start"
host = "rusty-vault.de"
guest = "infra-01"
public = true
forward_auth = true
dataset = "rpool/guests/infra-01"
```

(This is the full `tests/answers/signoff.toml` fixture the test suite uses,
shown here so every service referenced elsewhere in this README —
`ghostfolio`, `radarr`, `start` — resolves to a real block. `radarr` shows
an internal-only service with a backend but neither a `factory_login` nor
a `no_factory_login`; `start`
shows a public, forward-auth service with no `backend` at all.)

- `zone` — the DNS zone the service names live under; also the domain
  `public-path`'s canary invents a name in.
- `resolver` — the recursive resolver `dig` asks, so the answer comes from
  outside, not from a split-horizon view on the host itself.
- `vps_v4` / `vps_v6` — the VPS's public addresses; `dns-a`/`dns-aaaa` must
  resolve to exactly these.
- `caddy_guest` — the guest that runs the reverse proxy; `backend` probes
  *from* here.
- `auth_guest` — the guest that runs the identity provider; the Authentik
  token is minted and the API is called from inside it.
- `auth_api` — the identity provider's API base URL, reached from inside
  `auth_guest`.
- `outpost` — the name of the embedded outpost that must carry each
  forward-auth service's proxy provider.
- `rustic_profile` — the rustic profile (`-P`) used for the backup control
  and the per-service `backup` check.
- `snapshot_max_age_hours` — how old the newest snapshot may be before
  `backup` turns into a finding.
- `undeclared_is_failure` — optional, default `false`. `true` is strict
  mode: a service with neither a `[service.factory_login]` probe nor a
  `no_factory_login` reason is `failed` (exit 1) instead of `undeclared`.
- `[[service]]` — one entry per service:
  - `key` — the name used on the command line and in the output.
  - `host` — the public DNS name (also used for `dig` and `curl` even when
    `public = false`, so a declaration stays meaningful if that ever flips).
  - `guest` — the guest the service itself runs in; `factory-login` runs
    in its network namespace (not with its programs).
  - `public` — whether `dns-a`, `dns-aaaa` and `public-path` apply.
  - `backend` — the service's `ip:port` behind the reverse proxy, or absent
    if there is none (then `backend` is `n/a`).
  - `backend_guest` — the guest that IP belongs to, so `vantage probe` can
    name a source and a target guest.
  - `forward_auth` — whether the service sits behind the identity
    provider's forward-auth, so `outpost` applies.
  - `dataset` — the ZFS dataset backed up for this guest, used to filter
    `rustic snapshots`.
  - `[service.factory_login]` — optional: the vendor default login attempt.
    `method` defaults to `GET`. Either `body` (with `content_type`) or
    `user`/`password` (HTTP basic auth), never both. `reject` lists the HTTP
    status codes that mean the account was correctly refused.
    `reject_body` — optional, a non-empty substring: when set, a response
    counts as rejected only if its status is in `reject` AND its body
    contains the substring. A status in `reject` without the text is
    `failed` — the door may be open.
  - `no_factory_login` — optional, a non-empty reason: the service ships
    without a factory account, or its local login is switched off, and
    somebody wrote down why. `factory-login` is then `n/a: <reason>` and
    nothing is tried. Declaring it next to `[service.factory_login]` is a
    configuration error, and so is an empty or whitespace-only reason.

### Factory login: probe, exception, strict

A service that rejects a wrong login with a status code needs nothing but
`reject`. Some answer HTTP 200 either way and say it in the body —
qBittorrent answers `Fails.` to a wrong login and `Ok.` to a right one:

```toml
[[service]]
key = "qbittorrent"
# …

[service.factory_login]
method = "POST"
path = "/api/v2/auth/login"
content_type = "application/x-www-form-urlencoded"
body = "username=admin&password=adminadmin"
reject = [200]
reject_body = "Fails."
```

```
qbittorrent     factory-login   ok               HTTP 200 with the expected rejection text: factory account rejected
qbittorrent     factory-login   failed           HTTP 200, but the body (28 bytes) lacks the expected rejection text — the door may be open
```

The body itself is never printed, only its length: the answer to an
ACCEPTED login is a session token, and the report ends up in a terminal,
the journal and an alert mail. The body is read under the limit for
everything a guest answers (1 MiB, see below); a longer one is `cannot
measure`. Without `reject_body` curl discards the body as before.

A service with no factory account at all gets a reason instead of a probe:

```toml
[[service]]
key = "radarr"
# …
no_factory_login = "authentication is external, there is no local account"
```

```
radarr          factory-login   n/a              authentication is external, there is no local account
```

And once every service carries one of the two, the top-level switch keeps
it that way — a new service without either turns the run red:

```toml
undeclared_is_failure = true
```

```
radarr          factory-login   failed           neither a factory_login probe nor a no_factory_login reason is declared (undeclared_is_failure)
```

## Controls

Before any per-service measurement, `check` runs three controls once per
invocation (a fourth follows at the first forward-auth service, see below). If any of them fails, `check` prints `signoff: control failed:
…` to stderr, returns exit 2, and takes no measurement at all — a red
`dig`/`curl`/`rustic` run for one service would otherwise look like a
finding about the network, not about the service.

1. **SOA** — the resolver answers `SOA` for the zone at all. Otherwise "no
   A record" would be a statement about the resolver, not the zone.
2. **Canary** — an invented, never-declared name under the zone must be
   *refused* by the VPS (curl exit 35, "unrecognized name"). If it is not,
   a `200` for a real service proves nothing: the VPS could be answering
   for anything.
3. **Repository** — `rustic snapshots` lists something at all, for any
   dataset. Otherwise "no snapshot for `<dataset>`" would be a statement
   about a broken repository, not about that one guest.
4. **Proxy providers** — Authentik lists at least one proxy provider.
   Authentik filters every list by the token's object permissions: a
   token that may see none gets an empty list with HTTP 200, and without
   this control every forward-auth service would read `failed: no proxy
   provider` — a finding about the services that is really one about the
   token. This control runs late, at the first service with
   `forward_auth` (a run without one never fetches a token), but ends the
   run the same way: `signoff: control failed: authentik lists no proxy
   providers at all (permissions of the token?)`, exit 2. Lines already
   printed stay; no summary follows. Providers and outposts are fetched
   once per run, not once per service.

## Exit codes

- **0** — every measurement ran, every verdict was `ok`, `n/a` or
  `undeclared` (the last only without `undeclared_is_failure`).
- **1** — every measurement ran, at least one was `failed` — with
  `undeclared_is_failure = true` that includes a service with neither a
  `factory_login` probe nor a `no_factory_login` reason.
- **2** — a control failed, or at least one measurement could not be taken
  (`cannot measure`) — the run says nothing complete. Also used for a
  command-line error, a config that fails to load, or an unknown service
  name.

## Limits and privileges

- **Every command has a limit of its own, set per call**: what a guest
  answers (`systemd-run --machine`, `nsenter -n … curl`, `vantage`) 120 s
  and at most 1 MiB per stream (stdout, stderr); the host's own tools
  (`dig`, `curl` of `public-path`, `machinectl`) 120 s and 64 MiB; `rustic`
  600 s and 64 MiB (it lists the whole repository). A command that runs
  longer or writes more is killed and its output discarded; the
  measurement reads `cannot measure`.
  A guest cannot hold the run or fill the host's memory — `max-time` in a
  curl config would only bind a `curl` that honours it.
- **Every detail is made visible before it is printed**: control
  characters (and bidi overrides) are written as `\x1b`, `\u{202e}`, a
  newline as `\x0a`, and a detail is cut after 300 characters. A detail
  often carries what a guest produced (the first stderr line of a `curl`,
  names from Authentik); raw, an `ESC ] 52` would write the clipboard of
  the terminal that reads the report.
- **Privileges**: `systemd-run --machine` for the auth guest, `machinectl`
  and `nsenter -n` for `factory-login` — the last needs `CAP_SYS_ADMIN`
  (setns) and `CAP_SYS_PTRACE` (the leader's namespace file).

## What it does not do

- **No sensor.** `signoff` runs once, on demand, from the command line; it
  is not a daemon and does not export metrics. Continuous checks belong to
  `groundtruth` and the alert rules, not here.
- **No DNS client of its own.** Every `dns-a`/`dns-aaaa` answer comes from
  `dig` against the configured `resolver`; `signoff` does not speak the DNS
  wire protocol.
- **No reading of the VPS's configuration.** `public-path` and the canary
  control only ever observe the VPS's *behaviour* over the network
  (`curl --resolve`); `signoff` never reads `hosts/vps/ingress.nix` or logs
  in anywhere to inspect the SNI map directly.

## License

AGPL-3.0-only.
