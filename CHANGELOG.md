# Changelog

## [1.7.2](https://github.com/solisoft/soli-proxy/compare/v1.7.1...v1.7.2) (2026-10-06)

### Bug Fixes

* **apps: `TZ` and `LANG` are left unset when the proxy has none.** Apps got them empty whenever
  the proxy ran without them, which under systemd is always. An empty `TZ` is UTC, and soli does
  not override a variable already set with its `.env`, so an app could not set its time zone
  there and had to start with `env TZ=Europe/Paris soli serve …`. `TZ=Europe/Paris` in the app's
  `.env` now works. Apps already running are adopted as before, not restarted for this.

## [1.7.1](https://github.com/solisoft/soli-proxy/compare/v1.7.0...v1.7.1) (2026-10-06)

### Bug Fixes

* **apps: an app started through a wrapper is not redeployed at every restart.** 1.6's check for
  an upgraded binary compared the running one with the start command's program, which for
  `env TZ=Europe/Paris soli serve …` is `env`: such an app was redeployed (blue-green, so without
  downtime, but for nothing) on each restart. A binary now counts as replaced when the file it
  runs was deleted or its path names another file.
* **docs: moving a running host onto `soli-proxy.socket` takes one stop/start.** systemd refuses
  to start a socket while its service runs, so the `ReusePort=yes` switch-over 1.7.0 described
  does not exist; the unit no longer sets it.

## [1.7.0](https://github.com/solisoft/soli-proxy/compare/v1.6.1...v1.7.0) (2026-10-06)

### Features

* **systemd: restarts that refuse no connection.** With the new `scripts/soli-proxy.socket`,
  systemd binds `:80` and `:443` and hands them to the service (socket activation); the proxy
  serves on them instead of binding its own. They stay open while the service restarts, so a
  connection arriving then waits in the kernel's queue and is answered by the new proxy instead
  of being refused — behind Cloudflare, no more 521 during an upgrade. The sockets are
  close-on-exec, so no app inherits them.

### Bug Fixes

* **bots: no WordPress paths among the default traps.** A site migrated from WordPress gets real
  requests for `/wp-admin/`, `/wp-content/` and `/wp-login.php` (its editors' bookmarks, old
  links), and 1.4 banned a newsroom's own staff for one. The default traps are now secrets, VCS
  files and tools no visitor asks for (`/.env*`, `/.git/*`, `/.aws/*`, `/.ssh/*`,
  `/wp-config.php*`, `/phpmyadmin*`, `/vendor/phpunit/*`…).
* **bots: a ban is on the exact address.** IPv6 bans covered the /64, which hosting providers
  share between customers: a scanner's neighbour was banned with it.
* **bots: every refusal is in the request log.** Responses given before routing — a `[bots]`
  refusal, a maintenance page — now have their `log_endpoints` line, with `"answered_by"`, and
  a ban's reason carries the user agent, so a client's `403` can be traced.

## [1.6.1](https://github.com/solisoft/soli-proxy/compare/v1.6.0...v1.6.1) (2026-10-06)

1.6.0 was tagged, but its release build failed on a test that raced with another one's
`fork` (`Text file busy`), so no 1.6.0 binaries were published. 1.6.1 is the first release
with 1.6.0's changes; the test now retries.

## [1.6.0](https://github.com/solisoft/soli-proxy/compare/v1.5.0...v1.6.0) (2026-10-06)

### Features

* **apps: an upgraded `soli` reaches running apps on restart.** A process keeps the binary it
  started from, so after an upgrade an app ran the old version until someone restarted it. An
  adopted app whose binary was replaced since it started (compared by file identity with what
  its start command resolves to now) keeps serving, then is deployed blue-green onto the new
  binary, four apps at a time, after the apps that were down.
* **systemd: a warning when the unit would kill the apps.** With a `KillMode` other than
  `process`, stopping the unit kills every app with the proxy (`mixed` with SIGKILL), so the
  next proxy has nothing to adopt and every site starts cold. A proxy that is a unit's main
  process now logs this at startup, with the fix.

### Bug Fixes

* **apps: an app that was up is never put to sleep by a restart.** 1.5.0 left asleep an app
  found running but not adoptable (its launch changed, an unhealthy process, a pre-1.0
  leftover) after stopping it; it is started again at once, as before. Only apps with nothing
  running at all wait for their first request.

## [1.5.0](https://github.com/solisoft/soli-proxy/compare/v1.4.0...v1.5.0) (2026-10-06)

### Features

* **apps: apps stay asleep at startup until their first request.** The proxy still adopts what
  is running; an app that was not running and may sleep is no longer started with all the
  others but left asleep, and its first request wakes it (`N app(s) left asleep until their
  first request: …` in the log). After a reboot only the visited sites start. Apps that never
  sleep (`idle_timeout = 0`, `_admin`) start right away, and a site added while the proxy runs
  is started as before.

### Bug Fixes

* **dev: the fallback certificate covers sleeping apps.** It listed only running apps' `.test`
  hosts, so a sleeping app's first request failed its TLS handshake before it could wake it.

## [1.4.0](https://github.com/solisoft/soli-proxy/compare/v1.3.0...v1.4.0) (2026-10-06)

### Features

* **bots: refuse crawlers by user agent.** `[bots] block_agents` answers a `403` to a
  `User-Agent` containing one of its entries, compared without case: presets `ai-training`
  (GPTBot, ClaudeBot, CCBot, Bytespider…), `ai-assistants` (ChatGPT-User, PerplexityBot,
  Amazonbot…), `seo` (AhrefsBot, SemrushBot…) and `scanners` (zgrab, Nuclei, sqlmap…), or
  substrings. Search engines' crawlers are in no preset.
* **bots: ban scanners.** `traps = true` bans, for `ban_secs` (an hour by default), a client that
  asks for `/.env*`, `/.git/*`, `/wp-login.php`, `/wp-admin/*`, `/xmlrpc.php`, `/phpmyadmin*`…
  (or `trap_paths`), and `max_404_per_minute` one past that many 404s: a banned client gets a
  `403` on every site until the ban ends. IPv6 clients are banned by /64. Requests a page made a
  browser send (a `Sec-Fetch-Site` other than `none`) never ban, so no site can get your
  visitors banned with an `<img src="/.env">`; `allow_ips`, loopback and the `trusted_proxies`
  are never refused.
* **bots: on and off, globally or per site.** `[bots] enabled` is the master switch, and a site's
  `[bots] enabled` in its `app.infos` wins over it both ways; `traps = false` (a WordPress) and
  `block_agents` there adjust it for that site.
* **bots: see and lift bans.** Each ban is logged once and shows in the TUI's journal;
  `soli-proxy bots` lists the bans and the user agents refused, `soli-proxy bots unban <ip>`
  lifts one (`GET /api/v1/bots`, `DELETE /api/v1/bots/bans/{ip}` on the admin API).
* **logging: the user agent of each request.** `log_endpoints` lines carry `user_agent` (clipped
  to 256 characters), shown in the TUI's error detail.

## [1.3.0](https://github.com/solisoft/soli-proxy/compare/v1.2.2...v1.3.0) (2026-10-06)

### Features

* **maintenance: windows with an end.** `for_secs` or `until` (RFC 3339) on the admin API's
  toggles, at most a week ahead. The proxy reopens the site by itself when the end passes
  (checked every five seconds, logged), and `Retry-After` counts down to it. Windows are
  persisted to `run/maintenance.json` with their end, so a restart keeps it.
* **maintenance: `soli-proxy maintenance on <app>|all [--for 30m | --until <time>] [-m
  <message>]`, `off` and `status`.** It goes through the running daemon's admin API, with the
  address and credentials from `config.toml`; `--for` takes `90s`, `30m`, `2h`, `1h30m`, `1d`.
* **maintenance: a built-in page worth showing.** It names the app (`display_name`, a new
  `app.infos` key, else the host), shows the message and when the site is back in the visitor's
  time zone ("back around 14:00 · in about 25 min"), is in French or English after the browser's
  `Accept-Language` (`[maintenance] language = "auto" | "fr" | "en"`), light or dark, and
  reloads itself once the site answers again. Under 6 KiB, with no external resource.
* **maintenance: an app's own page.** `<site>/public/maintenance.html` is used when the app has
  no `error_pages/maintenance.html`, and while the app is closed the proxy serves the files of
  `<site>/public/maintenance/` at `/maintenance/<file>` — stylesheet, logo, fonts — even though
  the app behind it is stopped (plain names, 1 MiB each, a fixed list of types, `nosniff`, no
  symlinks in multi-tenant mode). Templates also get `{{app}}`, `{{since}}` and `{{until}}`.
* **tui: maintenance.** `M` on an app in the Apps screen asks for a duration (default `30m`,
  empty for no end) and a message and closes it; `M` again reopens it. Closed apps show
  `◆ maintenance` with their end time in the dashboard and the Apps screen, and the journal
  records each opening and closing.

### Bug Fixes

* **cli: `-c` and `--sites-dir` given before a subcommand are no longer dropped.** Each
  subcommand has its own, defaulting to `./proxy.conf` and `./sites`, which silently won:
  `soli-proxy -c /etc/soli-proxy/proxy.conf deploy shop` read `./proxy.conf`. One given after
  the subcommand still wins.

## [1.2.2](https://github.com/solisoft/soli-proxy/compare/v1.2.1...v1.2.2) (2026-10-06)

### Bug Fixes

* **tui: the errors screen shows errors older than the last 256 KB of the log.** It re-read
  only that much of `proxy.log` every tick. A dev proxy logs a line per request, livereload
  sockets included, so the window held a few hundred lines: on one machine it had 3 of the
  log's 109 404s and none of its 520 5xx, while the header counted them. The TUI now scans the
  last 16 MB once, then follows what is appended (a line cut between two reads, rotation and
  truncation included), skipping lines that cannot be failures before any JSON parsing.

## [1.2.1](https://github.com/solisoft/soli-proxy/compare/v1.2.0...v1.2.1) (2026-10-06)

### Features

* **tui: memory on the dashboard.** What the apps hold in memory — the resident memory of every
  app process, both slots counted while one deploys — and the host's used, total and available
  memory from `/proc/meminfo`, in the strip and in a panel of the right-hand column: a bar of
  the apps, the rest of the system and what is available (amber under 20 % available, red under
  10 %), then the figures; one line under the traffic panel on a narrow terminal. The apps
  screen's header shows the total too. Linux only for the host's figures.
* **tui: the dashboard's error rate is the share of 5xx responses.** It divided `errors_total`,
  which mostly counts the proxy's own refusals (421, failed auth), by the request count.
* **tui: 404s on the errors screen.** They are listed next to the 5xx and failed requests; `f`
  shows all of them, the 5xx only or the 404s only, and in 404 mode the top panel ranks the
  missing URLs asked for most — a broken link reads differently from a scanner. 404s stay out
  of the 5xx counts and off the dashboard's journal. (The rows need `[logging] log_endpoints =
  true`.)
* **tui: time since each app's last request.** A `last` column in the apps list, next to `up`
  (green under a minute, `—` when the app has had none since the daemon started), and in the
  detail panel.
* **apps: apps sleep after an hour by default under `--dev`.** 1.2.0 left `[apps]
  idle_timeout` at `0` under `--dev`, so a laptop running a dozen apps kept every one of them
  in memory; unset, it is now 3600 there (900 otherwise, unchanged).

## [1.2.0](https://github.com/solisoft/soli-proxy/compare/v1.1.0...v1.2.0) (2026-10-06)

**Upgrading:** apps without an `idle_timeout` now sleep after 15 minutes without a request.
Pin the ones that run cron jobs or background workers with `idle_timeout = 0` in their
`app.infos` first, or keep the old behaviour fleet-wide with `[apps] idle_timeout = 0`.

### Features

* **apps: put apps to sleep after 15 minutes idle by default.** `[apps] idle_timeout` defaults
  to 900 seconds instead of `0` (never), and stays `0` under `--dev`; an explicit value in
  `config.toml` or `app.infos` still wins. An app with a request still open is never idle: the
  proxy holds a token for as long as a response body streams (server-sent events, a large
  download) or a WebSocket tunnel stays up, the reaper skips an app holding one, and the idle
  clock starts when the last one ends — so a chat or an event stream is not cut after 15
  minutes. Measured: a 60-second download through an app set to 30 s runs to the end, and the
  app sleeps after it.

### Bug Fixes

* **server: a response is read only as fast as the client takes it.** The HTTP/1 server was
  built with hyper's experimental `pipeline_flush`, which makes its write buffer report room at
  all times: a response body was read from the backend as fast as the backend sent it, whatever
  the client's speed. A 120 MB download to a slow client sat in the proxy's memory within a
  second (+80 MB RSS in 6 s at 1 MB/s), on every path, static routes included, and the backend's
  request was over long before the client's. Without it hyper stops reading once about 400 KB
  wait to be written: +3.7 MB measured, and a fast client still gets 2.7 GB/s.

## [1.1.0](https://github.com/solisoft/soli-proxy/compare/v1.0.6...v1.1.0) (2026-10-05)

### Features

* **tui: the proxy at work, with motion.** The dashboard opens on a strip of figures, then the
  traffic panel: each active app is a branch of the proxy, with packets travelling down it as
  densely as it receives requests, red ones for 5xx, a still dotted line when it is asleep or
  stopped; idle apps are summed up on one line. A deploy unrolls its stages under its app
  (`start › health › switch › drain`, the drain counting down, then "live on green in 4.1 s"),
  a wake-up reads "waking", then "awake in 1.0 s", and a journal on the right lists deploys,
  traffic switches, sleeps, wake-ups and new request failures, each lit up as it arrives. The
  apps screen sorts by smoothed traffic (`s` cycles traffic, name, memory, errors; the cursor
  follows its app), shows a minute of traffic per app, flags a process still running a replaced
  Soli binary with `↻ restart`, and draws the selected app's two slots: packets flow to the one
  that serves, the other reads `starting…`, `health check…`, `draining 7s` or `free`, under the
  deploy stepper and next to CPU and memory bars. `D`, `R` and `L` deploy, restart and open the
  logs. The errors screen shows 5xx per minute per app (daemon counters, no setting needed) and
  per route host (from the log), then the failures newest first with cause and duration; a new
  one lights up and fades. Numbers glide to their new value. Motion is computed from the clock
  and repaints at 15 frames a second only while something moves — 0.2 % of a core idle, 0.6 %
  animating — and `m` or `NO_MOTION=1` turn it off. Below 140 columns the screens are tabs on the
  top line instead of a sidebar, and every screen fits 80×24.
* **apps: deploy stages, sleeps and wake-ups on the event stream.** `/api/v1/events/apps` said
  nothing until a deploy had finished. It now emits `DeployStage` at each step as it happens
  (`start`, `health`, `switch`, `drain` with its delay in `detail`, then `done` or `failed` with
  why), `Asleep` when the idle reaper stops an app (`idle_secs`), and `Waking`, once, when a
  request starts a sleeping one. Existing clients only see new event types.
* **cli: no second proxy next to a systemd one.** The listeners use `SO_REUSEPORT`, so a proxy
  started by hand where systemd runs one did not fail to bind: it silently shared :80 and :443
  and both supervised the same apps, and `-d` first stopped whatever `proxy.pid` named.
  `soli-proxy` (foreground or `-d`) now exits 1 with the unit, its PID, the taken ports and the
  `systemctl` commands to use, when a systemd unit's main process is a soli-proxy and a port it
  would listen on is already taken. systemd itself confirms the main process (`MainPID`), so a
  proxy started from a terminal that a desktop session launched as a service is not mistaken for
  a managed one, and a proxy on other ports starts normally. Subcommands are not affected.
  Linux only.

### Bug Fixes

* **tui: the dashboard's uptime is the proxy's.** It was the TUI's own (a TUI opened two
  seconds ago read "2s" on a proxy up for days); it now comes from the daemon's `/api/v1/status`.
* **tui: the errors screen points at the right file.** Its hint said `log_endpoints` goes in
  `proxy.conf`; it is `[logging] log_endpoints = true` in `config.toml`.

## [1.0.6](https://github.com/solisoft/soli-proxy/compare/v1.0.5...v1.0.6) (2026-10-05)

### Performance

* **compress: gzip is ~40 % faster on large pages.** gzip ran on flate2's default miniz_oxide
  backend; it now runs on zlib-rs (pure Rust as well), 1.7× faster at the same level with
  slightly smaller output. And the encoder was flushed at every `Pending` from the backend —
  for a body read off a socket, between nearly every read — so a large page came out in small
  deflate blocks, 2–6 % larger and ~10 % slower. It is now flushed once the backend has been
  quiet for 10 ms, counted from its first pause: a streamed page still reaches the client at
  most 10 ms late. End to end, a 15.6 MB page compresses in 95 ms instead of 153 ms.
  `benches/compression.rs` measures it (`SOLI_BENCH_HTML=page.html` for a real page), and the
  README has the measured level table.

### Features

* **compress: zstd is preferred when the client accepts several codings.** The default
  `algorithms` becomes `["zstd", "br", "gzip"]`: at the levels a proxy affords per request, zstd
  3 compresses HTML as well as brotli 4 or gzip 5 in a quarter to a third of the time. Chrome,
  Edge and Firefox accept it; Safari, which does not, still gets brotli. A config that sets
  `algorithms` keeps its own order.

## [1.0.5](https://github.com/solisoft/soli-proxy/compare/v1.0.4...v1.0.5) (2026-10-04)

### Features

* **tui: an app put to sleep by scale to zero shows as Sleeping.** It read as Stopped, like an
  app that stays down until someone acts, when the next request brings it back. The admin API
  reports `"asleep": true` for it in `/api/v1/app-metrics` and `/api/v1/apps/{name}/metrics`
  (sleeping apps are listed even without traffic), and the TUI shows **Sleeping** in purple on
  the apps screen and `◐ sleep` on the dashboard. The field defaults to `false`, so a newer TUI
  still reads an older daemon.

### Bug Fixes

* **apps: no false health-check failure after an app goes to sleep.** The periodic health check
  could probe an app while the idle reaper was stopping it, and logged `Health check failed …
  Connection refused (1/3 before failover)` after every sleep. A failed probe no longer counts
  when a stop is under way, the app is asleep, or its live slot no longer runs the probed
  process; the same race on a manual `soli-proxy stop` is covered. A process that exits because
  it was asked to (deploy switch, sleep, stop) is logged at info; only an exit nobody asked for
  warns.

## [1.0.4](https://github.com/solisoft/soli-proxy/compare/v1.0.2...v1.0.4) (2026-10-03)

1.0.3 was tagged but never released: its CI failed on a race in a new test (the test probed the
child process before it had started the program it was spawned with). 1.0.4 is the same code with
the test fixed.

### Features

* **tui: the apps screen shows each app's Soli version and uptime.** Two columns, `Soli` and
  `Up`, and two lines in the detail panel (`Soli`, `Since` with the start date). Both come from
  the app's process: the version from the binary it runs (`<exe> --version`, once per binary
  file, only for a `soli*` executable), the start time from `/proc/<pid>/stat`. An app still
  running a binary that was deleted or replaced since it started (an in-place `soli` upgrade it
  has not restarted on) shows its version as `2.14.0!` in yellow, and "old binary: restart" in
  the detail panel. Linux only, like the CPU and memory columns.

### Bug Fixes

* **apps: a failed health check says why.** The warning read `error sending request for url
  (http://127.0.0.1:<port>/up)` whether the app timed out, refused the connection or reset it —
  reqwest's top-level message, with the cause left in its source chain. The periodic check (`… (n/3
  before failover)`) and the deploy check (`did not become healthy … (last error: …)`) now log
  the whole chain, so a wedged app (`operation timed out`) reads differently from one that exited
  (`Connection refused`).
* **The sites watcher works with a relative `--sites-dir`.** notify reports absolute paths, and
  the prefixes stripped from them were the paths as given: with the default `./sites`, no event
  ever matched, so a site added, removed or renamed was not picked up until a restart, with
  nothing logged. The roots are made absolute first.

## [1.0.2](https://github.com/solisoft/soli-proxy/compare/v1.0.0...v1.0.2) (2026-10-01)

Two fixes to 1.0.0, the first of them for anyone upgrading from 0.35. (1.0.1 was tagged but never
released: its CI failed on a race in the new upgrade test and on a lint the newer stable compiler
raises. 1.0.2 is the same code with both fixed.)

### Bug Fixes

* **Upgrading from 0.35 no longer quarantines the apps it left running.** 0.35 kept no spawn
  registry, so 1.0.0 could not prove the apps a 0.35 proxy had left running were its own,
  refused to touch them, and quarantined every app whose port they held ("port … is already in
  use by another process"). A leftover is now recognised by what it is — the leader of its own
  session, running as the app's user, from the app's site directory, with the app's start
  program — stopped, and the app starts afresh, which is what the 1.0.0 upgrade notes promised.
  A process differing in any of those is still never signalled, and multi-tenant mode never
  applies this. Already hit it? Restart the proxy with this version, or stop the leftover
  `soli serve` processes and `touch <site>/restart.txt`.

* **A burst of real logins is no longer turned away on a small machine.** 1.0.0 answered 503 to a
  Basic-auth check that could not get a bcrypt slot within one second. With two slots and
  ~300 ms per check, three people logging in at once on a two-core box could get a 503 — and CI's
  two-core runner did, failing a test on `main`. A check now waits up to 10 s; what bounds a
  flood is the queue's length instead: at most 16 waiting checks per slot, and past that a 503 at
  once. Ordinary traffic is unaffected either way, since bcrypt never runs on the request
  workers.

## [1.0.0](https://github.com/solisoft/soli-proxy/compare/v0.35.2...v1.0.0) (2026-10-01)

1.0 closes a full security and performance audit of 0.35 and adds what a proxy fronting a fleet of
apps was missing. Every finding of the audit is fixed — bcrypt that could freeze the whole proxy,
a WebSocket path around route scripts, tenants able to hang it, reach each other or take over a
domain, client-controlled forwarding headers — and an independent review of the result found and
fixed the remaining seams. Apps now survive a proxy restart. The proxy understands the CDN in
front of it, compresses, retries, health-checks its targets, speaks HTTP/2 and gRPC to them,
gates routes behind an SSO service, and `soli-proxy check` validates a configuration before it is
loaded. Every dependency advisory is gone (`cargo audit --deny warnings` is clean) and the test
suite went from 317 to 606.

Measured against 0.35.2 on the same machine (fat-LTO builds, 200 connections over loopback):

```
static route              127,343 → 158,842 req/s   +25%
managed app's domain      125,176 → 167,551 req/s   +34%
normal traffic while wrong passwords flood an @auth route
                               30 → 87,385 req/s    median 1,463 ms → 0.48 ms
```

### Upgrading from 0.35

Run `soli-proxy check -c <proxy.conf> --sites-dir <sites>` with the new binary first: it loads
every file the way a start would and names each problem with its line.

* **`proxy.conf` is parsed strictly.** A line or directive the parser does not understand —
  `@lb:unknown`, a malformed `@auth`, a line without `->` — is an error instead of being skipped.
  Fatal at startup; on a reload the previous configuration stays.
* **bcrypt hashes above cost 13 are refused** (4 to 13 are accepted). Regenerate them with
  `soli-proxy hash-password`.
* **Apps outlive the proxy.** Stopping or restarting the proxy leaves its apps running, and the
  next start adopts them. `soli-proxy stop --all` stops them too; `[apps] stop_on_shutdown = true`
  restores the old behaviour. The first restart into 1.0 still restarts every app once (0.35 kept
  no adoption records).
* **The systemd unit changed**: it runs as a `soli-proxy` user with `CAP_NET_BIND_SERVICE` and
  `KillMode=process`. Re-copy `scripts/soli-proxy.service`, create the user and give it the config
  and sites directories. Running native apps as other users needs the root variant documented in
  the unit.
* **Forwarding headers are the proxy's.** Client-sent `X-Forwarded-*`, `Forwarded` and
  `X-Real-IP` are always replaced. Behind a CDN or load balancer, list it in
  `[server] trusted_proxies` so its chain is kept.
* **Every request and response carries `X-Request-Id`** (`request_id_header = ""` turns it off).
* **The HTTPS listener follows `[server] bind`** instead of always binding `0.0.0.0`.
* **One client address may hold 256 connections** (`[limits] max_connections_per_ip`, 0 = off).
* **`.env` is read from the configuration directory only**, never from its parents.
* **Multi-tenant mode:** tenant port ranges, `docker_network`, `--restart` and the operator's
  proxy environment are ignored or refused; each app gets its own Docker network.
* **Cluster pushes** must carry a strictly increasing index, `http`/`https` targets and weights up
  to 255. A pushed domain is protected only once `soli-oned` sends its `auth`.

### Authentication and the admin API

#### Security

* **bcrypt no longer runs on the request workers.** Route `@auth`, app `[auth]` and the admin
  API's Basic credential verified bcrypt inline on a tokio worker, so some 40–50 wrong passwords
  a second parked every worker and froze the whole proxy, every site included. Checks now run on a
  blocking pool bounded to half the cores (at least two); a check that cannot start within a
  second answers **503 with `Retry-After: 1`**. Successes are still remembered for five minutes
  (and a remembered credential bypasses the pool), failures never. The admin API's Basic
  credential now shares that cache, so a polling TUI no longer pays bcrypt on every refresh.
  The timing-equalizer hash is computed once per cost, even under concurrent first requests.
* **A bcrypt hash is accepted only at cost 4 to 13, and only well-formed.** The cost is a work
  factor for the proxy's CPU chosen by whoever writes the hash — a tenant, for `app.infos` in
  multi-tenant mode — and `$2b$31$` made every attempt run for days. An app with such a hash now
  fails to load; the admin API and cluster pushes answer 400; a `proxy.conf` `@auth` entry is a
  load error (fatal at startup; on reload the previous config stays). `hash-password --cost`, the
  binary and the new subcommand alike, is bounded the same way. **Hashes above cost
  13 must be regenerated.**
* **The open admin API refuses a foreign `Host`.** With no credential configured, only requests
  addressed to `localhost`, a loopback IP or the bound address are answered (403 otherwise),
  which defeats DNS rebinding from a web page.
* **Failed admin logins are budgeted per IP**: ten a minute, then 429 with `Retry-After`, before
  bcrypt runs. Credential-less requests and correct credentials never count, and an
  already-verified Basic session is let through while its IP is blocked.
* **Cluster route pushes are validated.** Targets must be `http`/`https` URLs with a host, weights
  over 255 are refused instead of wrapping (`256` used to become `0`), and a push at index 0 can
  no longer be replayed: after any table is applied the index must strictly increase.
* **Cluster-pushed domains can carry, and get, Basic Auth.** A pushed target is the workload's
  raw port with nothing in front of it, so an app's `[auth]` was enforced nowhere. The push now
  accepts an optional `auth` object per domain (the `app.infos` shape and validation), which this
  proxy enforces; a pushed domain without one is still served open, and the pusher must send it.

#### Documentation

* `soli-proxy hash-password`, which the README documented, now exists as a subcommand; the
  standalone `hash-password` binary and `POST /api/v1/hash-password` remain.

### The request path

#### Security

* **WebSocket upgrades run the route's Lua scripts.** The upgrade branch returned before
  route `on_request`, global `on_route` and route `on_route` ran, so a route protected by
  `@script:auth.lua` was open to anyone adding `Upgrade: websocket` — with whatever
  `X-User` they cared to send. The same hooks now run (deny, header rewrite, target
  override) before anything is tunnelled.
* **Forwarding headers are the proxy's, never the client's.** `X-Forwarded-Host` was only
  overwritten on domain rules and https targets, and `Forwarded`, `X-Real-IP`,
  `X-Forwarded-Port`, `-Prefix` and `-Ssl` were relayed verbatim (`X-Real-IP: 127.0.0.1`
  passed "localhost only" checks). Every inbound `Forwarded` / `X-Forwarded-*` /
  `X-Real-IP` is now dropped and `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Proto`,
  `X-Forwarded-Host` set from what the proxy saw — on rules, app domains and WebSockets,
  before Lua runs. `X-Forwarded-Host` now always carries the Host as sent, port included.
* **Hop-by-hop headers are stripped before Lua, on every path.** The app-managed path did
  not strip them at all; only the first `Connection` header was read; and the strip ran
  after the scripts, so `Connection: x-user` deleted the `x-user` a script had set.
* **Rules match a canonical path.** `//admin/x` and `/%61dmin/x` missed an `/admin/* @auth`
  rule and fell through to an unprotected one. Matching (and `@auth`/`@noauth`) now decodes
  percent-encoded unreserved characters and collapses repeated `/`; the backend still gets
  the path as sent.
* **CONNECT, authority-form and asterisk-form targets are refused** (405 / 400, `OPTIONS *`
  answered directly) instead of panicking on `path[1..]`.
* **More than one `Host` header is a 400**, as is an HTTP/2 `Host` that names a different
  authority than `:authority`.
* **The `force_https` redirect can no longer be pointed elsewhere.** `Host:
  example.com:@evil.com` passed the served-host check and became
  `Location: https://example.com:@evil.com/`. The Location is rebuilt from a strictly
  parsed `host[:port]`; anything else is a 400.
* **Deflate HTML rewriting is bounded.** The body was collected before the 10 MB check and
  decoded with an unbounded `read_to_end` — a decompression bomb. A compressed body over
  10 MB is now a 502; a decoded body over 10 MB (or invalid deflate) passes through
  untouched, still compressed.
* **A Lua header write-back replaces client duplicates.** A script setting `x-user` to one
  of the values the client had sent twice left both in place. Scripts now see repeated
  headers joined (`, `, or `; ` for `Cookie`), and any change replaces every copy.
* **A Lua deny with an impossible status answers 500** instead of panicking the
  connection; only 200–599 is honoured.
* **Lua state hygiene.** Request-scoped globals were left behind when `on_route` raised and
  after every `on_request_end`; they are now cleared after every hook call, whatever it
  returned.
* **WebSocket tunnels keep their connection slot**, and **`[limits]
  max_connections_per_ip`** (default 256, `0` = off; IPv6 per /64) caps one address's
  connections across both listeners. An open WebSocket used to stop counting against
  `max_connections` the moment it was upgraded.
* **HTTP/2 connections are bounded.** They had no idle or preface timeout: a client that
  negotiated h2 and sent nothing held its connection and permit forever. Idle connections
  now get GOAWAY after `keep_alive_timeout` (default 30 s), silent ones are closed, and
  PING keep-alives drop dead peers. HTTP/1's header-read timeout is now always set (30 s
  default), which also bounds idle keep-alive connections.
* **Client aborts no longer count against backends.** An upload the client broke off was
  recorded as a backend failure (and, for apps, triggered failover); only an over-size body
  was recognised as the client's doing.
* **The rate limiter keys IPv6 clients by /64**, not by full address.

#### Bug Fixes

* `on_response` and `on_request_end` receive the real request (method, path, host,
  headers) instead of an empty one, and the global `on_response` now runs for app-managed
  domains too.
* WebSocket backend sockets set `TCP_NODELAY`.

#### Performance Improvements

* Lua: hook presence is probed once per script, so no request table is built — and no
  state locked — for a script without that hook; the request view is built once per
  request; global cleanup is one raw lookup per global instead of a string conversion each;
  a free Lua state is taken before waiting on a busy one.
* The HSTS header is built once per loaded config, not per HTTPS response; the config is
  loaded once per request instead of three times.
* `strip_hop_by_hop` uses static header names; the circuit breaker uses a `parking_lot`
  lock and skips a redundant store on success; WebSocket idle timers are reset rather than
  re-created per frame; the backend pool keeps up to 256 idle connections per host (was 64).

### Apps: multi-tenant isolation, routing and supervision

#### Security

* **A tenant's `app.infos` can no longer hang or exhaust the proxy.** It was read whole, with
  `read_to_string`, on an async worker while holding the lock every proxied request takes: a
  FIFO stopped all app routing, and `app.infos -> /dev/zero` grew the proxy until it was
  OOM-killed — at every boot. It is now opened non-blocking, must be a regular file of at most
  64 KiB, and (multi-tenant) is not followed through a symlink. Discovery reads and parses on
  the blocking pool and takes the apps lock only to apply the result.
* **A `www.` directory can no longer take over its apex domain, or another app's auth.**
  Routing, Basic Auth and the app-name lookup now read one table. An app owns its declared
  domain whether or not it is running (stopping a site used to hand its apex to a `www.` site
  that derived it, while auth was still looked up on the stopped one), aliases outrank derived
  domains, and in multi-tenant mode a derived claim no longer overrides an operator's static
  rule or a cluster-pushed route. Auth is only ever taken from the app actually served.
* **The proxy kills only processes it spawned.** At startup it killed the process group of
  whatever listened on an app's ports, with no ownership check. Spawned processes are now
  recorded with their start time in `run/spawned.json`, and a PID — or the group it belongs
  to — is signalled only when it matches a record. Container slots are stopped with
  `docker stop`/`docker rm -f` by name, never by PID.
* **Tenants no longer choose their ports.** In multi-tenant mode `port_range_start`/`end` in
  `app.infos` are ignored for the new `[apps] port_range_start`/`port_range_end` (default
  20000-30000). In every mode a range below 1024, covering one of the proxy's own listeners,
  or larger than 20 000 ports is refused (the `[apps]` range is used), and a remembered port
  outside an app's current range is reallocated.
* **Each tenant gets its own Docker network.** Multi-tenant containers used to share the
  `soli-apps` bridge with inter-container traffic on, and `docker_network` let a tenant pick
  any network. Each app now runs on `soli-app-<name>`, created with ICC disabled and a
  `sl-<hash>` bridge name (so one firewall rule covers every tenant), removed with the app.
  The README shows the nftables/iptables rules for host and private-range egress, which the
  proxy cannot set portably.
* **`--restart` is refused in tenant `docker_options`,** and `graceful_timeout` /
  `drain_delay` are capped at 3600 s. A restart policy resurrected slots the proxy had stopped.
* **The operator's egress proxy is no longer handed to tenants.** In multi-tenant mode
  `HTTP(S)_PROXY`/`NO_PROXY` reach containers only with `[apps] tenant_proxy_env = true`, and a
  value carrying `user:password@` only with `tenant_proxy_env_credentials = true` too.

#### Performance

* **An app request no longer takes the global apps lock.** Each one locked the apps map up to
  five times — and rebuilt a table of every app's domains, formatted and parsed a URL, and
  sorted every app by name — before reaching the backend, under the same mutex deploys,
  discovery and health checks hold. The routing table is now built when something it depends
  on changes (discovery, a slot starting or stopping, a traffic switch, an alias) and published
  through an `ArcSwap`; a request does one load and one hash lookup, gets its target, app and
  auth from the same entry, and records itself for scale to zero with an atomic store.
  Attributing a response to its app no longer locks the port allocator either.
* **Per-app metrics take a read lock**, not the write lock every proxied request used to queue
  behind; the write lock is taken once per app, the first time it is seen.

#### Bug Fixes

* **One bad health check no longer restarts an app.** The monitor failed an app over on the
  first error or non-2xx answer, while the README promised it only reacted to actual failures.
  Now a failure is no answer, a timeout or a 5xx, and failover waits for
  `[apps] health_failure_threshold` consecutive ones (default 3). A 4xx means the app is up and
  its `health_check` path is wrong: it is logged as a warning, not acted on. The old fallback
  that retried `/` after a 404 is gone with it. Health probes go to `127.0.0.1`, not
  `localhost`.
* **State files are written atomically.** `proxy.conf`, `run/aliases.json`,
  `run/app_state.json`, `run/ports.lock` (and the new `run/spawned.json`) are written to a
  temporary file, fsynced and renamed, so a crash or a full disk leaves the previous version
  instead of a truncated one. The `proxy.conf` watcher now watches the file's directory — a
  rename-into-place left it watching the replaced inode — and recognises the proxy's own writes
  by their content instead of swallowing exactly one event, which dropped the next real edit
  whenever a write raised more than one.
* **The sites watcher no longer watches tenant trees.** It watched the whole sites directory
  recursively: a tenant could exhaust the host's inotify watches, and any write anywhere set off
  a rediscovery and route sync. Outside dev mode it now watches the sites directory and each
  site non-recursively, reacts only to sites appearing/disappearing/renamed and to `app.infos`,
  coalesces bursts (500 ms quiet, 5 s max) and spaces rediscoveries at least 2 s apart.
* **Docs: an auto-detected Soli app's health check is `/up`**, not `/` as the README said.

### Configuration, routing and packaging

* **A prefix rule pointing at `redirect://` can no longer redirect off-site.** The part of the
  path left after the prefix was glued straight onto the target, and a `redirect://` target has
  no path of its own: `example.com/old/* -> redirect://new.example` plus `/old/.evil.com/`
  answered `Location: https://new.example.evil.com/`. The remainder is now always joined as a
  path — exactly one `/` between target and suffix — and the resolved URL is checked to still
  carry the configured authority. The same join fixes `http://h/v2` + `/api/x` becoming
  `http://h/v2x` (now `http://h/v2/x`), a target with its own query string getting a second
  `?`, and a panic on an empty request path.
* **`.env` is read from the config directory only, and never exported.** The proxy used
  `dotenv` (unmaintained, RUSTSEC-2021-0141), which searched the working directory and every
  parent for a `.env` and exported all of it — a stray file in `/srv` or `$HOME` could set the
  admin API's `ADMIN_USER`/`ADMIN_PASSWORD`, or an `HTTP_PROXY` inherited by every spawned app.
  Now `dotenvy` reads exactly `<config dir>/.env`, takes only `ADMIN_USER`, `ADMIN_PASSWORD` and
  `ADMIN_PASSWORD_HASH` from it, and leaves the process environment untouched; real environment
  variables still win. A `.env` that does not parse is now an error instead of being ignored.
* **`cargo audit --deny warnings` is clean.** `rustls-pemfile` (unmaintained, RUSTSEC-2025-0134)
  is replaced by the PEM reader in `rustls-pki-types`, and `ratatui` 0.28 → 0.30 (with
  `crossterm` 0.29) drops the unsound `lru` (RUSTSEC-2026-0002) and the unmaintained `paste` it
  pulled in. No behaviour change.
* **The systemd unit no longer runs the proxy as root.** `scripts/soli-proxy.service` now uses a
  dedicated `soli-proxy` account with `AmbientCapabilities=CAP_NET_BIND_SERVICE` and nothing
  else, under `NoNewPrivileges`, `ProtectSystem=strict` (`ReadWritePaths=/etc/soli-proxy
  /srv/sites`), `ProtectHome`, `PrivateTmp`, kernel protections and `UMask=0027`, with
  `StateDirectory`/`LogsDirectory` and `ExecReload` (SIGUSR1). Native apps that run as *other*
  users need `CAP_SETUID`, which must not be handed out as an ambient capability (apps would
  inherit it), so the unit documents a root variant for that setup. **Operators upgrading:**
  create the account and `chown` `/etc/soli-proxy` and the sites directory, or keep the root
  variant.
* **The setcap sudoers grant names a root-owned path.** `deploy/soli-proxy-setcap.sudoers`
  targeted `/home/soli/.local/bin/soli-proxy`, which the grantee can replace with a symlink —
  `setcap` follows it, so the account could give `cap_net_bind_service` to any binary on the
  machine. It now names `/usr/local/bin/soli-proxy`; install the binary there, root-owned.
* **`weight:N` is parsed, round-tripped and honoured.** The README's
  `/api -> weight:70 http://a, weight:30 http://b` never parsed (every target was stored at
  weight 100), and the admin API's rewrite of `proxy.conf` dropped weights anyway. Targets now
  take `weight:0`–`255`; any weight implies `@lb:weighted` unless the rule names a strategy;
  `weight:0` drains a target (last resort only). The weighted picker reduces weights by their
  common divisor and interleaves them with a coprime stride — 70:30 goes A B A A B A A B A A,
  exactly 70/30 per cycle, with no lock — and the picker no longer allocates a `String` per
  candidate examined.
* **`headers { }` blocks work.** They were documented and silently ignored. A block now applies
  to the rule above it: `Name: value` sets an upstream request header (after the proxy's own
  `X-Forwarded-*`, so it can override them), `-Name` removes one, and values may use
  `$client_ip`, `$scheme`, `$host`. Hop-by-hop/framing headers are refused. Blocks round-trip
  through the admin API.
* **Regex rules substitute their captures.** `~^/users/(\d+)$ -> http://svc/users/$1` sent the
  literal `$1`. `$N`, `${N}` and `${name}` are now expanded in the target's path and query (never
  its host), the client's query string is kept, and a reference to a group the pattern lacks is
  a load error.
* **`proxy.conf` lines the parser cannot read are errors.** Lines without `->`, unknown `@`
  directives, unknown `@lb` strategies, invalid `@script` names, malformed `@auth` entries (which
  left the route *unprotected*), invalid `@noauth` paths and junk after `[global]` were all
  skipped or defaulted, at most with a warning. Each is now an error naming its line: fatal at
  startup, a no-op on reload. **Operators upgrading:** a file that loaded before may now be
  refused — the log says which line. Also fixed: directives written after a `@script:` list were
  dropped, and `example.com/api` (no `/*`) became the unmatchable prefix `api`.
* **`[logging]` is honoured, written off the request path, and rotated.** `level`, `format` and
  `output` were ignored — the proxy always logged JSON at INFO, synchronously, to stdout or
  (with `-d`) to a `proxy.log` that grew forever with umask permissions. Now `level` takes a level
  or a `tracing` filter (falling back to `RUST_LOG`), `format` is `json` or `text`, `output` is
  `stdout`, `stderr` or `file:/path`, every write goes through `tracing_appender::non_blocking`,
  and file output rotates by size (`max_size`, default 100MB; `max_files`, default 5), creating
  files `0640`. Defaults are unchanged: JSON, INFO, stdout. The TUI's error screen reads the
  configured file.
* **TLS sessions resume.** The HTTPS `ServerConfig` used rustls' defaults: no session ticketer
  (TLS 1.3 clients could not resume) and a 256-entry TLS 1.2 cache. It now has an aws-lc-rs
  ticketer and a 32k-entry session cache, so returning clients skip the full handshake. New
  `[tls] min_version` (`"1.2"` default, or `"1.3"`).
* **The HTTPS listener uses the configured bind address.** It was hardcoded to
  `0.0.0.0:<https_port>`: a proxy bound to `127.0.0.1:80` still served HTTPS on every interface,
  and none of the IPv6 ones. It now listens on `bind`'s address; `bind = "[::]:80"` is
  dual-stack on both ports (`IPV6_V6ONLY` is cleared explicitly). **Operators:** HTTPS now follows
  `bind` — a loopback or single-interface `bind` narrows HTTPS too.
* **The TUI's Circuits screen shows the daemon's circuit breakers.** It read a `CircuitBreaker`
  the TUI process had just created — always empty, so every backend looked healthy. It now reads
  `GET /api/v1/circuit-breaker` and says "unavailable" when it cannot. The TUI also works against
  a Basic-auth admin API: it sent only `X-Api-Key`, so every call was a 401; it now reuses the
  password typed at its login as HTTP Basic (polling every 5 s in that mode), sends
  `X-Requested-With` on every request, and reports refused credentials as such.
* **`soli-proxy hash-password` exists.** The README, `app.infos` docs and the admin API hints all
  named it; only a separate `hash-password` binary did. The subcommand prompts twice without echo
  (or reads stdin when it is not a terminal), prints only the hash, never takes the password from
  argv, and accepts `--cost 4..31` (default 12).
* **Lua examples named in `config.toml` ship, and `rate_limit.lua` is not spoofable.**
  `scripts/lua/cors.lua` (allowlisted origins, preflights answered with 204 and the
  `Access-Control-Allow-*` headers) and `scripts/lua/logging.lua` now exist. `rate_limit.lua`
  keyed its buckets on the client-supplied `X-Forwarded-For`, so every request could claim a fresh
  budget; it now keys on `req.client_ip` when the proxy provides it, else one bucket per host.
* **Documentation matches the code.** The README no longer claims API-key/JWT auth for routes,
  "graceful draining" on reload, a `soli-proxy [dev|prod]` CLI or `SOLI_CONFIG_PATH`, or calls
  the project a forward proxy; the dead `[auth]` block (with `jwt`/`jwks_url`) is gone from
  `config.toml` and from the generated default. Newly documented: `[limits]` WebSocket keys,
  `[scripting] exposed_env`, `force_https`, `max_connections`, `request_timeout`, every admin
  endpoint (`routing-table`, `acme-challenges`, `app-metrics*`, `events/apps`, `settings`, …),
  what a hot reload does and does not change, and the real project layout. The www docs' reload
  examples now use `/api/v1/reload` and the Docker example the real `--conf` flag.

### Robustness

* **A backend that fails mid-body no longer panics the connection.** The response body type
  declared its error `Infallible`, so a backend's body error — a reset, a truncated chunk — went
  through `unreachable!()` and panicked the task serving that client connection. Errors now
  propagate: hyper aborts the client's response (HTTP/1: the connection is closed without the
  final chunk; HTTP/2: the stream is reset), so the client sees a truncated response instead of
  a dead connection, and other requests on an HTTP/2 connection carry on. The `_admin` app
  passthrough had the same panic.
* **`max_connections` no longer stalls below the number of accept loops.** Each accept loop (one
  per core, per listener) took a permit *before* calling `accept`, so idle loops sat on permits
  they had no connection for: with `max_connections` under the loop count, or near the limit,
  the permits could all be parked on the HTTPS listener while HTTP connections waited for a
  slot nobody used. The permit is now taken after `accept`; the loop waits for it inline (still
  backpressure: it accepts nothing meanwhile and the listen backlog absorbs the rest), FIFO
  across both listeners, and closes a connection that gets no slot within 10 s.
* **`proxy_requests_in_flight` no longer drifts upwards.** The gauge was decremented by hand on
  each return path and several had none — failed WebSocket upgrades among them — nor did a
  request whose client went away. It is now held by a guard released on every exit.
* **The admin API's `_admin` passthrough uses the proxy's forwarding headers.** It overwrote
  `X-Forwarded-For`/`-Proto`/`-Host` but relayed a client's `X-Real-IP`, `Forwarded` and other
  `X-Forwarded-*` verbatim (on WebSockets too); it now goes through the same
  `set_forwarding_headers` as every proxied request. The admin API's rate limiter and its
  failed-login budget key IPv6 clients by /64, like the proxy's.
* **Two more backend-controlled panics are gone.** A backend's WebSocket 101 whose
  `Sec-WebSocket-Accept`/`-Protocol` held a control character (a lone CR, DEL) panicked on
  building the client's 101 (proxy and `_admin` passthrough alike); it is now a 502. A
  prefix-mounted redirect whose rewritten `Location` could not be a header value panicked; the
  `Location` is now left as the backend sent it.
* **Routes created through the admin API are validated in full.** `POST`/`PUT /api/v1/routes`
  and `PUT /api/v1/config` only checked `auth_exempt` paths (and auth hashes); a bad `headers`
  entry (a hop-by-hop name, an unknown `$variable`, an invalid value) or a regex target naming a
  capture the pattern lacks was written to `proxy.conf`, which the next load then refused. They
  now get the same checks as a `proxy.conf` line, and a 400 up front.

### Restarts, upgrades and `soli-proxy check`

#### Features

* **A proxy restart no longer takes every app down.** SIGTERM used to send GOAWAY, sleep a fixed
  2 s and stop every managed app, so each restart, upgrade or crash-and-restart was a fleet-wide
  outage followed by a cold start of every app. Now the proxy stops accepting, lets in-flight
  requests finish and exits **leaving its apps running**; the next proxy **adopts** them instead
  of restarting them. An instance is adopted only when it is provably the proxy's own and
  unchanged: a native process must be in `run/spawned.json` with a live PID *and* the recorded
  start time, on the slot's current port, listening on it (or a member of its process group
  is), and launched with today's exact program, arguments, environment and user (a recorded
  digest); a container `<app>-<slot>` must be running with the proxy's new labels for that app,
  container and port and a `docker run` digest equal to what the proxy would run now. Then it
  must pass its health check (three tries). It goes into the routing table before the listeners
  open and is supervised as usual. Ours-but-changed, -wrong-port or -unhealthy instances are
  stopped and started afresh (so a restart still applies a changed command, image, options,
  user or environment); a leftover from a deploy the restart interrupted is stopped; anything
  not provably ours is neither adopted nor signalled. The slot that was serving now comes from
  `run/app_state.json` (it was ignored at startup and every app came back on blue).
* **Configurable drain: `[server] shutdown_grace_period`** (default 10 s, max 3600) replaces the
  fixed sleep. The proxy counts the connections it is serving and waits until the last one has
  finished its response — a restart under normal traffic takes milliseconds — or until the
  grace period. WebSockets are not waited for. A second SIGTERM/SIGINT exits at once.
  `soli-proxy -d` replacing a daemon waits for that drain (plus 5 s) instead of 10 s.
* **`[apps] stop_on_shutdown`** (default `false`; `true` under `--dev`, so ^C still cleans up)
  restores the old behaviour. **`soli-proxy stop --all`** and **`POST /api/v1/apps/stop-all`**
  stop every app (both slots) while the proxy keeps running; without a daemon, `stop --all` and
  `stop <app>` find native processes through the spawn registry — previously a slot started by
  an exited proxy could not be stopped from the CLI at all.
* **`soli-proxy check [-c <conf>] [--sites-dir <dir>] [--dev]`** validates `config.toml`
  (and `.env`), `proxy.conf` with the strict parser and every site's `app.infos` with the
  discovery rules (multi-tenant ones included), then checks what a start only finds later or
  only logs: bind/admin addresses, the admin API's refusal to run publicly without a credential,
  bcrypt hashes and costs, port ranges, Lua script files, and whether each app can be launched
  (`docker run` options, users). Nothing is started, bound or written. Every problem is printed
  as `file:line: error|warning: message` — every bad `proxy.conf` line, not only the first — and
  the exit status is 1 on any error. **`POST /api/v1/config/validate`** runs the same checks on a
  proposed `{"proxy_conf", "config_toml"}` without applying it.
* **`soli-proxy update`** no longer prints a fake "Restarting soli-proxy..." (`--reinstall` just
  exited); it explains the restart, which is now safe at any time, and suggests `check` first.

#### Bug Fixes

* **`--watch false` works.** The flag was a bare `bool`, so clap refused any value: the
  documented way to turn the file watchers off made the proxy exit with a usage error.
  `--watch false` now disables them; `--watch` alone still means `true`.
* Docs: the daemon's PID file is `$SOLI_PID_DIR/proxy.pid` (default: the working directory),
  not `/var/run/soli-proxy/soli-proxy.pid`.

#### Operators upgrading

* **The systemd unit sets `KillMode=process`.** The default (`control-group`) SIGTERMs the whole
  cgroup — every native app — on stop/restart. Copy the new `scripts/soli-proxy.service` (or add
  the line) and `systemctl daemon-reload`, or apps still die with the proxy. Note that
  `systemctl stop soli-proxy` now leaves apps running too: `soli-proxy stop --all` first.
* The first restart *into* this version still restarts the apps: the old binary (or systemd's
  cgroup kill) stops them, and whatever survives was started without the launch digest and
  container labels adoption requires, so it is replaced once. Adoption starts with the restart
  after that.
* Native apps get `/dev/null` as stdin (they inherited the proxy's); their stdout/stderr already
  went straight to `run/logs/`, so no app dies of SIGPIPE when the proxy exits.
* Two proxies side by side (an overlapping blue/green start using `SO_REUSEPORT`) is **not**
  supported: the admin port is not shared and both would supervise the same apps.

### Behind a CDN or load balancer: client identity, request IDs, access log

#### Features

* **The real client behind a CDN or load balancer.** The proxy replaced `X-Forwarded-For` with
  the TCP peer, so behind Cloudflare or a balancer every client was the balancer: one rate-limit
  bucket for everyone, the balancer's address in logs and in `X-Real-IP`. New `[server]
  trusted_proxies` (CIDRs, addresses, or the presets `"cloudflare"` — Cloudflare's published
  ranges, compiled in — `"private"` and `"loopback"`) and `real_ip_header` (`X-Forwarded-For` by
  default, or a single-address header such as `CF-Connecting-IP`). From a trusted peer the
  client is found by walking `X-Forwarded-For` right to left past trusted hops, and used for the
  rate limiter, the `/metrics` loopback check, `X-Real-IP`, `headers { }` `$client_ip`, Lua's new
  `req.client_ip`, logs and the admin API's budgets; that peer's chain is appended to rather than
  replaced and its `X-Forwarded-Proto` kept. Untrusted peers are handled exactly as before (and
  a `real_ip_header` they send is removed). Hot-reloadable. Off by default.
* **PROXY protocol v1/v2.** `[server] proxy_protocol = "v1" | "v2" | "any"` (or
  `{ http = …, https = … }`) reads the header a TCP balancer prepends — before TLS and HTTP,
  within 5 s and 1 KiB, only from `trusted_proxies` (anyone else is disconnected). The carried
  address is the connection's peer for everything after, `max_connections_per_ip` included.
  Enabling it with no `trusted_proxies` is a configuration error.
* **Request IDs.** Every request carries `X-Request-Id` (`[server] request_id_header`; `""` turns
  it off) upstream and back to the client, in the access log and in Lua's `req.request_id`. One
  sent by a trusted peer is kept when it is 1–128 visible ASCII characters; anything else is
  replaced by 128 random bits as 32 hex digits, drawn from a per-thread generator (no syscall,
  no lock). W3C `traceparent`/`tracestate` pass through untouched.
* **Access log.** `[logging] access_log = "off" | "stdout" | "stderr" | "<path>"` and
  `access_log_format = "json" | "combined"`: one line per request with time, real client IP,
  method, host, path and query, protocol, status, bytes in (`Content-Length`) and out, duration,
  upstream, app, request ID, user agent, referer and TLS. The line is written when the response
  body has been sent (or abandoned — `complete: false`), so bytes out and duration are the real
  ones; formatted into a reused per-thread buffer and queued to a non-blocking writer that drops
  rather than blocks; a file rotates by `max_size`/`max_files`. Read at startup.

#### Behaviour changes

* **Responses now carry `X-Request-Id`, and upstream requests too**, by default. A client's own
  `X-Request-Id` no longer reaches the backend (it is replaced); set `request_id_header = ""` for
  the old behaviour.
* **A trusted proxy is exempt from `max_connections_per_ip`**: it carries everyone's connections.
  The cap is applied on accept, before any header is read, so it stays keyed on the TCP peer (or
  the PROXY protocol address); clients behind a trusted proxy that does not speak PROXY protocol
  are limited per request by `[rate_limiting]`, not per connection.

### Responses: compression, error pages, maintenance mode

#### Features

* **Response compression: gzip, brotli and zstd** (`[compression]`, **off by default**). A
  backend's response is compressed when the client asks (`Accept-Encoding`, q-values honoured, a
  tie going to `algorithms` order: br, zstd, gzip) and it is eligible: no `Content-Encoding`
  already, not 1xx/204/206/304, a `Content-Type` in `types` (text, JSON, JS, XML, SVG, wasm,
  icons, ttf/otf, `*+json`, `*+xml` by default) other than `text/event-stream`, at least
  `min_length` (1024) bytes when the length is known, no `Cache-Control: no-transform`. It
  gets `Vary: Accept-Encoding` (so does every eligible response, compressed or not), loses
  `Content-Length` and `Accept-Ranges`, and a strong `ETag` turns weak. Encoding is streamed:
  at most 64 KiB of input per poll before yielding, and a flush whenever the backend pauses, so
  progressive pages and chunked streams stay live. Levels default to gzip 5, brotli 4 (1 MiB
  window), zstd 3. Per route `@compress:on|off` (round-tripped by the admin API), per app
  `compress = false` in `app.infos` (`true` opts in, except in multi-tenant mode). A path-prefix
  mount's HTML rewrite happens first, then compression. Off by default because it costs one to
  two orders of magnitude more CPU per text byte than passthrough, changes caching headers, and
  compressing pages that reflect input next to secrets is what BREACH exploits.
* **Custom error pages** (`[error_pages] dir`). The proxy's own errors (502, 503, 504, 421, 401,
  413, 429, …) are served as HTML to clients whose `Accept` lists `text/html`: `<status>.html`,
  then `4xx.html`/`5xx.html`, then `default.html`, with `{{status}}`, `{{reason}}`, `{{host}}`
  and `{{request_id}}` (HTML-escaped; the response's `X-Request-Id`, else the request's). Status
  and headers (`Retry-After`, `WWW-Authenticate`) are kept, other clients keep the plain text,
  and a backend's own error or a Lua `deny` is never replaced (`intercept_upstream_errors =
  true` extends the pages to backends' errors). Pages are read at load/reload, 64 KiB each. An
  app may ship `error_pages/` in its site directory, read at discovery (256 KiB in total); in
  multi-tenant mode it is opened `O_NOFOLLOW` and read through that descriptor, so a tenant
  cannot have a host file served back as its error page.
* **Maintenance mode**, global or per app: 503 with `Retry-After` and `maintenance.html` (the
  app's, the global one, or a built-in page with the toggle's message). Switched through
  `PUT /api/v1/maintenance` and `PUT /api/v1/apps/{name}/maintenance`
  (`{"enabled", "retry_after"?, "message"?}`, persisted atomically to `run/maintenance.json` and
  restored at startup; `GET /api/v1/maintenance` shows the state), or by a
  `<site>/maintenance.flag` file for deploy scripts without admin credentials, which the sites
  watcher picks up. `[maintenance]` holds the policy: `retry_after` (300), `allow_ips`
  (IPs/CIDRs) and `allow_paths`; ACME challenges and the proxy's health and metrics endpoints are
  always served. `GET /api/v1/apps` reports `"maintenance"` per app.

#### Operators

* Nothing changes until a section is configured. A `run/maintenance.json` that does not parse
  stops the proxy at startup rather than reopening sites closed on purpose; a missing
  `[error_pages] dir` or an oversized page is a configuration error like any other.
* New dependencies: `brotli` 8 and `zstd` 0.13 (libzstd, built from source by `zstd-sys`).

### Upstreams: retries, health checks, HTTP/2, TLS, Unix sockets

#### Features

* **A failed attempt is retried on the next target when that is safe.** A request used to get one
  try and a 502; an app's failover only helped the *next* request. Now an attempt that fails
  before any response byte goes to the rule's next available target (`[upstream] retries`, default
  **1**; `@retries:N` per rule; `0` turns it off). A connect failure (refused, unreachable, connect
  timeout, TLS handshake) is always retried, request body included — the body is handed back
  unread; any other failure (reset, connection closed), and a status named in `retry_on` (`"500"`,
  `"502"`, `"503"`, `"504"`; none by default), only for an idempotent method without a body. A
  managed app retries on its other slot while a blue/green deploy has one running, and the failed
  slot is failed over at once; a cluster-pushed domain on another instance; a target a Lua
  `on_route` hook chose is never second-guessed. `try_duration` caps the time spent. Every failed
  attempt still counts in the circuit breaker. **Operators:** multi-target rules now retry by
  default; such a rule keeps a copy of the request head per request for it (`retries = 0` avoids
  that).
* **Active health checks for `proxy.conf` targets.** `@health:/path` (and `@health_interval:`) on a
  rule, or `[health_checks] default_path` for every rule (`@health:off` opts out), starts a probe
  per distinct target, through the rule's own client. `unhealthy_threshold` failures in a row (any
  answer ≥ 500, a timeout, no answer) take the target out of every strategy until
  `healthy_threshold` successes; the verdict lives beside the circuit breaker and is reported by
  `GET /api/v1/circuit-breaker` as `"health": "up"|"down"` (and in the TUI). Probes are rebuilt on
  every reload — removed checks stop, their verdicts are forgotten — and stop at shutdown.
* **HTTP/2 to upstreams, and gRPC.** `h2c://host:port` targets (prior knowledge) and `@h2` rules
  (ALPN `h2` over TLS, prior knowledge in cleartext or on a socket) get a dedicated HTTP/2 client
  instead of a request forced to HTTP/1.1. `TE: trailers` now survives the hop-by-hop strip (any
  other `TE` value is still dropped, and HTTP/1.1 upstreams get no `TE` at all), and `Trailer` is
  no longer stripped — it is an end-to-end field — so gRPC trailers reach the client, over HTTP/1.1
  too when announced. On an HTTP/2 upstream a `Host` contradicting `:authority` is dropped (the
  client's host stays in `X-Forwarded-Host`).
* **Upstream TLS options per rule:** `@tls_ca:/path` (a private CA, replacing the public roots),
  `@tls_sni:name`, `@tls_client_cert:/cert.pem,/key.pem` (mTLS) and `@tls_insecure` (no
  verification; warned about on every load). Files are read at load — a missing or invalid one is a
  load error — and are part of the client's identity, so replacing one takes effect on reload.
  WebSocket upgrades to the rule's `https://` target use the same settings.
* **Unix socket upstreams:** `unix:/absolute/path.sock`, the client's `Host` preserved, WebSocket
  upgrades included, through a small connector of our own over `tokio::net::UnixStream`. A Lua
  override can never target a socket.
* **Per-route timeouts:** `@timeout:120s` replaces `[limits] request_timeout` for the rule (longer or
  shorter); `@connect_timeout:2s` replaces the 5 s connect timeout.
* Rules with the same upstream options share one client (and connection pool), built when the
  configuration loads and reused across reloads; a request picks its client with a field read. All
  new directives are validated by the parser and for admin-API rules, written back by the
  serializer, and kept by the TUI's route editor. `validate_proxy_target_url` accepts `h2c://` and
  `unix:` targets.

### Forward authentication

#### Features

* **Forward authentication: one SSO service can gate any route or app.** The README used to
  claim JWT auth the proxy never had; it now delegates the decision the way Traefik's
  ForwardAuth, nginx's `auth_request` and Caddy's `forward_auth` do. A route takes
  `@forward_auth:http://auth.internal:4180/verify` and, optionally,
  `@forward_auth_headers:X-Auth-User,X-Auth-Email`; an app takes `[auth] forward = "…"` and
  `forward_headers = […]` in `app.infos` (cluster pushes accept the same keys). Before proxying —
  and before a WebSocket upgrade — the proxy sends the auth service a bodiless `GET` with the
  client's `Cookie`, `Authorization`, `Accept`, `User-Agent`, `X-Requested-With`, its own
  `X-Forwarded-For`/`-Proto`/`-Host`/`X-Real-IP`, and `X-Forwarded-Method`/`X-Forwarded-Uri`.
  **2xx** lets the request through with the named response headers copied onto it; **any other
  answer** (401, 403, a 302 to the login page) is relayed to the client — status, headers
  including `Location` and `Set-Cookie`, body capped at 64 KiB — and the upstream is never
  contacted; **no answer** within `[forward_auth] timeout_secs` (default 5) is a **503**, never a
  pass. The subrequest uses the shared upstream connection pool; no verdict is cached, so a
  revoked session stops working on the next request.
* **The copied header names are stripped from every client request first**, whatever the auth
  service answers and on `@noauth` paths too, so a client cannot forge `X-Auth-User`. Naming a
  hop-by-hop or framing header, `Host` or a forwarding header is refused.
* **Basic Auth and forward-auth combine:** Basic runs first and both must pass; the client's
  `Authorization` (the Basic password) is then not sent to the auth service. `@noauth` /
  `[auth] noauth` paths skip both.
* **Multi-tenant mode: `[forward_auth] allowed_urls`.** A tenant's `[auth] forward` is a URL the
  proxy fetches with the visitor's cookies and whose denials it relays — a server-side request
  forgery if left open (`http://169.254.169.254/…`, an internal admin port). In multi-tenant mode
  an app whose `forward` no entry covers (same scheme, host and port; an entry ending in `/`
  covers the paths below it) fails to load. Empty by default: no tenant can use forward-auth
  until the operator lists a service.
* Forward-auth URLs must be `http`/`https` with a host, and carry no credentials or fragment —
  checked by the `proxy.conf` parser, `rule.validate()` (admin API), `app.infos` loading and
  cluster pushes. Routes round-trip through the admin API as
  `"forward_auth": {"url": …, "headers": […]}`, and through `proxy.conf` rewrites; the TUI's
  route editor keeps a route's forward-auth when it saves.

### Fixes across the new features

* **`force_https` no longer loops behind a TLS-terminating CDN.** A request from a trusted proxy
  whose `X-Forwarded-Proto` is `https` is not redirected; from any other peer the header is
  ignored, as before.
* **Saving a route in the TUI keeps what the editor has no field for**: its `headers { }` block,
  `@forward_auth`, `@compress` and target weights (`weight:N` is now read and written in the
  targets field). Saving used to drop them.
* **The health monitor falls back to `/health`**, like the deploy gate and adoption; it fell back
  to `/`, so an app could be alive for one and dead for the other.
* **An `accept()` that fails for lack of descriptors backs off 100 ms** instead of spinning a core.
* **Multi-tenant: a tenant's derived apex no longer lends its error pages or maintenance flag to
  the operator's site.** A tenant's `www.victim.com/` derives a claim on `victim.com`; routing
  let it yield to the operator's `proxy.conf` rule or a cluster push for that apex, but custom
  error pages and `maintenance.flag` looked the host up by name — so the tenant's `error_pages/`
  (its HTML and scripts, on the victim's origin) answered the apex's errors, and its flag closed
  the apex. Both now ask `AppManager::serving_route`, which applies routing's own precedence, and
  routing uses it too. A yielding app is also no longer woken or counted active by those requests.

* **`$client_ip` in a `headers { }` block is the forwarded client again.** It was read after the
  request's extensions were cleared, so behind a trusted proxy it was always the proxy.
* **Custom error pages no longer replace a forward-auth denial.** The auth service's 401/403 (its
  login form, its JSON) was taken for one of the proxy's own errors, and its body swapped for the
  proxy's page under the service's headers; it is now relayed like a backend's answer, replaced
  only under `intercept_upstream_errors`.
* **A forwarded client can no longer be this host.** A trusted peer's `X-Forwarded-For` (or
  `real_ip_header`) naming a loopback, unspecified, link-local, multicast or broadcast address is
  a forgery: the peer is the client instead. `/metrics` is judged on the connection itself — the
  TCP peer (or PROXY source) and the client must both be loopback — so a tenant container on a
  trusted Docker range sending `X-Forwarded-For: 127.0.0.1` no longer reads it, and neither does
  a remote client relayed by a front proxy on this host. **`soli-proxy check` warns** when
  `multi_tenant` is on and `trusted_proxies` covers loopback or Docker's `172.16.0.0/12` /
  `192.168.0.0/16` pools (the `"private"` and `"loopback"` presets do): tenants would be trusted
  proxies.
* **The admin API writes a route only once it loads.** `proxy.conf` was written (and marked as the
  proxy's own write) before the route's `@tls_ca` / `@tls_client_cert` files were read, so a route
  answered 500 yet sat on disk and failed the next reload. And every string the serializer writes
  verbatim — TLS and health paths, `@tls_sni`, matchers, `@auth` users, `@noauth` paths, script
  names, global scripts — is refused (400) when it holds whitespace, a control character, `->`
  or a trailing backslash: a `\n` in a route's JSON injected a `proxy.conf` line of the caller's
  choosing. The `.conf` parser refuses the same values.
* **TLS files are read safely, and fail quietly.** Only a regular file of at most 1 MiB is read,
  opened non-blocking (a FIFO used to hang the load — and the admin request behind it), off the
  async workers, outside the client registry's lock, and once: the trust store is built from the
  bytes the client's key was hashed from. A file that cannot be used — missing, unreadable, not a
  certificate — is reported as `cannot load TLS file <path>` by the admin API and
  `POST /api/v1/config/validate`; the reason goes to the log. The distinct errors (and a PEM
  parser quoting the line it choked on) made the API a probe of the proxy's filesystem.

* **A PROXY header that names no client no longer vouches for the connection.** On v1 `UNKNOWN`,
  v2 `LOCAL` or an address-less v2 header the balancer stayed a trusted peer, so the client's own
  `X-Forwarded-For`, `real_ip_header`, request ID and `X-Forwarded-Proto` were believed and the
  per-IP cap skipped. Such a connection is still served (health checks) but trusted for nothing,
  and counted per IP against the balancer's address.
* **`X-Forwarded-Proto` is read one way.** `force_https` took the first value while the forwarding
  headers dropped a multi-valued header; both now take the last value — the nearest proxy's.
* **The admin listener strips an untrusted client's `real_ip_header`** (`CF-Connecting-IP`…)
  before the `_admin` passthrough, like the proxy's listeners do.
* **Userinfo in a request's host is a 400**, in the HTTP/2 `:authority` and in `Host` alike;
  maintenance used to judge `x@site.example` raw while routing used `site.example`. A malformed
  request is no longer looked at by maintenance at all.
* **A Lua `on_route` override keeps the rule's upstream client only for the rule's own origins.**
  Sent anywhere else, it used to take the rule's mTLS certificate, `@tls_insecure` and
  `@tls_sni` along (HTTP and WebSocket alike); it now gets the shared pool's defaults.
* **WebSocket upgrades are routed like requests.** When an app takes a whole-domain rule over,
  only the app's gates apply (the rule's ran too, so forward-auth was asked twice); the target is
  chosen by the rule's balancing past open breakers and down targets, with the rule's
  `@connect_timeout` (it was always the first target, 5 s), and the tunnel's connect/handshake
  outcome feeds the breaker; the rule's `headers { }` block applies to the upgrade.
* **A pushed domain's retry is no longer dropped by a half-open breaker:** the next instance was
  checked twice, and the second check refused what the first had just let through as the probe.
* Smaller seams: a rule's `@timeout` no longer applies when an app takes the rule over; error and
  maintenance pages show the request ID under `request_id_header`, not always `X-Request-Id`;
  `soli-proxy check` files assembly errors under the right file (a route's TLS file was blamed on
  `.env`); a response with any non-`identity` coding in any `Content-Encoding` field (`identity,
  gzip`) is no longer compressed again; a backend error page replaced under
  `intercept_upstream_errors` drops its `ETag`, `Last-Modified`, `Content-Disposition`,
  `Content-Range` and `Content-Encoding`. The README now says that forward-auth's
  `X-Forwarded-Uri` is the raw request target, for redirects, not for authorization.

## [0.35.2](https://github.com/solisoft/soli-proxy/compare/v0.35.1...v0.35.2) (2026-09-27)

### Bug Fixes

* **A route pushed by the cluster is balanced across its instances.** It served its first
  target, always: a second replica took no traffic, and a dead first one took all of it until
  the cluster recomputed the table. Pushed routes now use the weighted round-robin the proxy's
  own routes use, and pass over a target whose circuit breaker is open, so a replica that stops
  answering is skipped on the next request rather than the next push.

  ```
  20 requests, two replicas:  10 · 10   (they went 30 · 0)
  ```

* **Plain HTTP for a pushed domain is redirected, not refused.** With `force_https` the proxy
  redirects only the hosts it recognises, and that check knew its own apps and rules but not the
  table the cluster pushes — so `http://` for a cluster domain answered **400** instead of its
  **308** to the HTTPS side that serves it.

### Build

* **Linux release binaries are built on `ubuntu-24.04`**, pinned rather than `ubuntu-latest`:
  glibc 2.39, which is Rocky Linux 10's, where soli-one repackages the binary as an RPM. A build
  on a newer runner would need a newer glibc and not start there.

## [0.35.1](https://github.com/solisoft/soli-proxy/compare/v0.35.0...v0.35.1) (2026-09-23)

### Performance Improvements

* **A credential is verified once, not once per request.** bcrypt at cost 12 takes ~300 ms
  by design — that slowness is what makes guessing passwords expensive. The Basic-auth gate
  ran it on *every* request, so a page paid it, then its stylesheet paid it, then each of
  its images. Measured on a protected production site: **15 ms of application behind 360 ms
  of doorman**, and the same page served through Cloudflare took 470 ms end to end.

  `auth::verify_once` now remembers a verdict for five minutes, keyed by a SHA-256 of the
  `Authorization` header **and** of the accounts configured on the route — so rotating a
  password invalidates what was remembered instead of leaving the old one working. Digesting
  also keeps the plaintext credential out of the process memory.

  ```
  right password:  483 ms, then 3.9 ms · 5.0 ms · 4.5 ms
  wrong password:  237 ms · 232 ms, still 401
  ```

  ⚠️ **Only successes are remembered, and that is the whole design.** Caching failures would
  hand an attacker a fast path to millions of guesses. A wrong password still pays full
  price, every time.

### Bug Fixes

* **The timing equalizer follows the accounts' cost.** `dummy_hash()` was pinned to
  `DEFAULT_COST` while its own comment required it to match the configured hashes. An
  operator lowering a gate to cost 8 — a staging password needs no key stretching — would
  have made an unknown username measurably *slower* than a known one, handing back the user
  enumeration the equalizer exists to prevent. `dummy_hash_at(cost)` reads the cost from the
  accounts and memoizes one dummy per cost.

### Features

* **`hash-password --cost N`** (4–31, default 12), without which no operator could lower
  that cost in the first place.

## [0.35.0](https://github.com/solisoft/soli-proxy/compare/v0.34.0...v0.35.0) (2026-09-15)

### Bug Fixes

* **A path carve-out is no longer deleted from `proxy.conf`.** `sync_routes` prunes static
  rules for app-managed domains so they cannot shadow blue-green routing, and it matched
  `host/path/* -> …` as well as `host -> …`. A carve-out shadows nothing — it claims one
  prefix, and the router already relies on that: `override_with_app` defers to the
  `AppManager` only for whole-domain rules, precisely so an explicit path rule still wins.
  The pruner was deleting the rules the router documents as intentional.

  The cost was quiet and recurring. Pruning rewrites `proxy.conf`, and `sync_routes` runs
  from three places — adding an alias, app auto-start (**every restart**) and the traffic
  switch (**every deploy**). So a hand-written route vanished, most often mid-deploy, with
  only an info line to say why; re-adding it worked until the next deploy, which is what
  disguised it as anything other than a proxy behaviour.

  ```
  # Deleted on every deploy before this release; kept now.
  site.example.com/_eui/* -> https://backend.example.com/_eui/
  ```

  Whole-domain rules are still pruned, unchanged: those really do shadow an app.

## [0.34.0](https://github.com/solisoft/soli-proxy/compare/v0.33.0...v0.34.0) (2026-09-15)

### Features

* **Scale to zero: `idle_timeout` in `app.infos`.** Most fleets are mostly idle — on a box
  hosting thirty small sites a day's traffic typically touches a handful, and every other one
  holds its full runtime in memory for nothing. An app past its threshold is stopped the way
  `soli-proxy stop` stops it, so the exit is not mistaken for a crash: no failover, no
  quarantine. The next request for one of its domains is **held** while the app starts on its
  current slot and is polled for health, then forwarded as usual — the first visitor waits about
  a second, everyone else finds it running, and concurrent first requests share one start.

  ```toml
  idle_timeout = 900   # sleep after 15 minutes without a request
  ```

  A sleeping app keeps its certificate registered and keeps winning over static `proxy.conf`
  rules for its domains, exactly as a running one does. The default is `0` — never sleep — which
  is the right value for anything that does work without being asked: cron jobs, background
  workers, WebSocket rooms, a cache that takes more than a moment to rebuild. `[apps]
  idle_timeout` in `config.toml` sets a fleet-wide default; `_admin` never sleeps regardless.

* **`[development]` and `[production]` sections in `app.infos`.** An app has one manifest, and
  the environment the proxy runs in picks the values — instead of a dev copy and a prod copy
  drifting apart in two files nobody diffs:

  ```toml
  workers = 4
  idle_timeout = 1800

  [development]
  workers = 1          # one worker, and no sleeping, while developing
  idle_timeout = 0
  ```

  `--dev` selects `[development]`; every other run selects `[production]`. The chosen section
  is applied key by key over the top level, and a nested table merges into its counterpart
  rather than replacing it, so `[production.auth.users]` adds accounts without discarding the
  `noauth` list written above it. The section that is not selected is dropped unread, so a
  `[production]` block written for a newer proxy never stops a developer's machine from
  starting the app. Both sections are optional and a manifest carrying neither parses exactly
  as before.

* **Discovery logs the `app.infos` keys it does not recognise.** Serde has always ignored them
  without a word — `worker = 4` ran the app with one worker and said nothing — and the overlay
  sections raise the stakes, since a key that lands in the wrong section is ignored just as
  quietly. Unknown keys are still ignored rather than fatal: refusing the manifest would take a
  running app off the routing table over a typo.

## [0.33.0](https://github.com/solisoft/soli-proxy/compare/v0.32.0...v0.33.0) (2026-09-10)

### Features

* **HTTP Basic Auth per app, in `app.infos`.** Apps are routed by the app manager rather than
  by `proxy.conf` rules — `sync_routes` prunes static rules for app-managed domains — so a
  route's `@auth` could never protect an app. An app now declares its own:

  ```toml
  [auth]
  noauth = ["/webhooks/stripe", "/hooks/*"]

  [auth.users]
  admin = "$2b$12$..."
  ```

  `noauth` takes the same syntax as the `@noauth:` route directive (exact path, or a prefix
  ending in `*`) and the same fail-closed rule: a path carrying percent-encoding or a `..`
  segment is never exempt. Auth covers the app's derived domains (`www.`-stripped, `.test` in
  dev) and any admin-managed alias pointing at it, and is enforced on WebSocket upgrades as
  well as plain requests. A `[auth]` section the proxy cannot enforce as written — an empty
  hash, a pattern that does not compare literally — makes the app fail to load rather than
  come up unprotected. `GET /api/v1/apps` reports the configured usernames and carve-outs,
  never the hashes, and the admin UI shows an `auth` badge on protected apps.

### Fixes

* **`app_name_for_host` settles a contested domain the same way routing does.** It iterated a
  `HashMap`, so when two apps declared one domain the app it returned could differ from the
  one `running_app_domains` actually routes to (which picks by name order). Per-app metrics
  could be attributed to the wrong app; with per-app auth reading the same lookup, it would
  have meant answering a protected app's traffic with another app's credentials, or none.

## [0.32.0](https://github.com/solisoft/soli-proxy/compare/v0.31.0...v0.32.0) (2026-09-09)

### Features

* **`@noauth:` exempts paths from a route's Basic Auth.** A whole domain can be
  password-protected while the endpoints that machines call — a Stripe webhook, a health
  probe — stay reachable without credentials:
  `app.example.com -> http://app:8080 @auth:admin:$2b$12$... @noauth:/webhooks/stripe,/hooks/*`.
  Entries are comma-separated and each is either an exact path or a prefix ending in `*`
  (which also matches the bare prefix). Paths are matched against the URL as the client sent
  it, before any prefix stripping, so what you write is what you see in the browser.
  `@noauth` without `@auth` does nothing. Editable from the admin UI (Routes → Basic Auth)
  and the TUI route form, and exposed as `auth_exempt` on the admin API.

  The match is deliberately literal and fails closed: a path carrying percent-encoding or a
  `..`/`.` segment is never exempt, so a request cannot walk out of the carve-out into a
  protected path that a normalising backend would resolve differently. Patterns that cannot
  be compared literally (relative, traversing, percent-encoded) are refused by the admin API
  and dropped with a warning by the `.conf` parser, leaving the path protected.

## [0.31.0](https://github.com/solisoft/soli-proxy/compare/v0.30.0...v0.31.0) (2026-09-04)

### Security

* **Request paths with dot segments are rejected before routing.** Rules match on the raw
  path and per-route auth binds to the matched rule, so `/api/../admin/users` could pass an
  open `/api/` rule and land on `/admin/users` at any backend that normalises. Literal and
  `%2e`-encoded dots are caught, terminated by `/`, end of path, a `;` path parameter
  (`/api/..;/admin`, as Tomcat/Jetty/Spring strip it) or a backslash (`..\`, as IIS treats
  it). An encoded slash (`%2F`) anywhere is rejected as well, since a backend that decodes it
  before routing would see a path the proxy never matched. Backends whose API paths carry
  `%2F` as data (GitLab's `group%2Fproject`, S3-style keys) can set
  `[server] allow_encoded_slash = true`; `..%2F` and `%2F..` stay rejected.
* **`docker_network` is validated.** The value went straight to `docker run --network`, so
  `docker_network = "host"` bypassed the namespace denylist that only looked at
  `docker_options`. `host` and `container:<id>` are refused in every mode, the name must be
  one docker accepts, and the manifest is fully validated before the network is created, so
  a rejected deploy no longer leaves a tenant-named network behind.
* **The single-tenant `docker_options` denylist reads docker's syntax.** It split on `=` and
  whitespace and inspected the next token, so `-v/:/host`, `--mount type=bind,source=/`,
  `/./:/host`, `--pid container:x`, `--volumes-from`, `--env-file` and `--group-add` all
  passed. Flags are now parsed the way docker parses them (attached shorthand, `--mount`
  key=value specs), mount sources are normalised and canonicalised before the root / docker
  socket check, and the namespace, volumes-from, env-file and group-add flags are on the list.
* **Multi-tenant bind mounts may only be the site directory itself, emitted canonicalised.**
  A sub-path such as `<site>/data` was validated by canonicalising it, but the tenant's raw
  token reached `docker run`, which resolves the path again at mount time — and every
  component under the site directory is writable by the tenant's still-running previous slot,
  which could swap `data` for a symlink to `/` in between. The site directory's own path has
  no tenant-writable component; it is the only permitted source, and its canonical path is
  what reaches docker.
* **`PUT /api/v1/config` pairs auth hashes by matcher, not index.** A `hash: ""` entry (the
  API never returns hashes) was resolved against whichever old rule sat at the same index, so
  deleting or reordering rules handed a route the password of another (same username) or
  rejected the change with 400 (different username).
* **Empty admin credentials count as unset.** `[admin] api_key = ""` (a templated config with
  an unresolved variable) made the server log "no authentication configured" and then 401
  every request, and `ADMIN_USER="" ADMIN_PASSWORD=""` was hashed into a credential that
  `Authorization: Basic Og==` satisfied. Empty strings are dropped at load time.
* **Admin mutations need `X-Requested-With`.** Any non-GET request without `X-Api-Key` must
  carry an `X-Requested-With` header of any value, or it is answered 403. An HTML form cannot
  set it, which is what stops a page the operator visits from driving the API with cached
  Basic credentials or the open loopback default. A bare `curl -X POST` against loopback
  needs `-H X-Requested-With:curl` now.

### Changed

* **`base64.decode` in Lua returns `nil, err` on malformed input instead of raising.** Hook
  errors now fail closed (500 "script error"), so a raise on an attacker-controlled
  `Authorization` header would have turned every malformed credential into a 500. Scripts
  written against the old contract (`pcall(base64.decode, s)`) keep working for valid input,
  but the failure branch must change to check the return value:

  ```lua
  local decoded = base64.decode(token)
  if not decoded then return req:deny(401, "Malformed credentials") end
  ```

  The bundled `scripts/lua/auth.lua` is updated.
* **`name` and `domain` in `app.infos` are validated in every mode.** Hostname characters
  plus `_` (an existing `sites/my_app.example.com` keeps loading), a leading `_` only for
  bundled apps, and `health_check` must be an absolute URL path. A directory whose manifest
  fails is skipped and logged at warn level.
* **The environment allowlist reaches Docker apps too.** `HTTP(S)_PROXY`/`NO_PROXY`,
  `SOLI_RELEASE_BASE_URL` and `SOLI_NO_PIN` are passed as `-e` flags into the container;
  the host-path entries (`XDG_CACHE_HOME`, `SSL_CERT_FILE`, `SSL_CERT_DIR`) are native-only.

### Fixed

* **Apps got the proxy's `HOME`, not their own.** The proxy drops privileges to
  the app's `user` but handed the child the environment variable it inherited
  itself — `/root` under systemd. Every `~`-resolved path therefore pointed at a
  directory the app could not read, silently breaking soli's package cache
  (`~/.soli/packages`), its registry credentials and the Tailwind CLI it
  downloads to `~/.soli/bin`. `HOME` is now read from the passwd entry of the
  user the app actually runs as.

### Added

* **A short environment allowlist survives `env_clear()`.** Apps still start
  with a cleared environment, but `XDG_CACHE_HOME`, `SOLI_RELEASE_BASE_URL`,
  `SOLI_NO_PIN`, the `HTTP(S)_PROXY`/`NO_PROXY` family and `SSL_CERT_FILE` /
  `SSL_CERT_DIR` now pass through when set on the proxy. Without them an app
  behind an egress proxy could not make outbound HTTPS requests, and could not
  be pointed at a shared cache.

  Together these let a Soli app pin its interpreter version
  (`soli_version = "=2.0.3"` in `soli.toml`) and have the proxy start it on that
  version. No proxy configuration is needed — the app already starts with its
  own directory as the working directory, which is where soli looks for the pin.

## [0.29.2](https://github.com/solisoft/soli-proxy/compare/v0.29.1...v0.29.2) (2026-07-29)

Website and admin UI only — the proxy binary is unchanged from 0.29.1.

### Added

* **www:** a Changelog page at `/changelog`, linked from the docs sidebar, the mobile navigation, and the footer.
* **admin:** a Changelog page in the admin UI, linked from the sidebar.

### Fixed

* **fix(www):** the Tailwind content glob was `./app/views/**/*.{erb,html,html.erb}`. Brace expansion matches the whole extension, so `*.html.slv` never matched and every class used only in a `.slv` view was dropped from the build — silently affecting the two pre-existing `.slv` pages (`benchmark`, `dev_https`). Building with the old glob yields 45029 bytes and drops `bg-purple-500/10` and `list-decimal`; with `slv` added, 45853.
* **fix(admin):** the committed `output.css` predated several views and Tailwind is not run at request time, so the changelog page's badge classes resolved to nothing. Rebuilt, and restricted to colour families the palette already carries.

## [0.29.1](https://github.com/solisoft/soli-proxy/compare/v0.29.0...v0.29.1) (2026-07-28)

### Added

* **apps:** touching `restart.txt` at the root of a site triggers a zero-downtime blue/green deploy of that app, so a deploy script can end with `touch <site>/restart.txt` instead of an SSH-side `soli-proxy restart <app>`. The file is **polled** (2s by default) rather than watched: sites are typically symlinks into out-of-tree repositories and inotify does not traverse symlinks, so the existing sites watcher never sees files inside them. The first poll after startup only records a baseline, so an already-present trigger file does not redeploy every site on daemon restart. Configurable via `[apps].restart_trigger_file` and `[apps].restart_trigger_poll_secs` (`0` disables it).

### Security

* **security(apps):** an app that **fails to start** — spawn error, or a new slot that never passes its health check — is now quarantined instead of being restarted forever. Previously `check_health()` called `failover()` every 30s on any unreachable app with **no failure cap** (`failure_count` was only incremented by the process-exit monitor), so a broken deploy left the app flapping indefinitely, respawning processes and churning ports. The failed slot is killed and marked `Failed`, the previous slot keeps serving, and the health loop, process-exit monitor, and request-triggered failover all skip the app until an **explicit** deploy (trigger file, CLI, or admin API) clears the quarantine. Exposed as `"quarantined": true` on `GET /api/v1/apps[/{name}]` plus a `StatusChanged` SSE event; the deploy-failure path also emits a `failed` status event, which it previously did not.

* **security(proxy):** request-body size limits are now enforced on chunked / HTTP-2 bodies by streaming the inbound body through `http_body_util::Limited` (`proxy_request_body`) and returning **413** on overflow, instead of blanket-rejecting `Transfer-Encoding: chunked` — a body that omits `Content-Length` (or lies about it) can no longer slip past the fast-path check and buffer without bound. The admin proxy path buffers with the same hard cap.
* **security(circuit_breaker):** a backend request that fails because the client's body exceeded `max_request_size` no longer records a circuit-breaker failure or triggers async failover — the backend never saw a completed request, so an attacker sending repeated oversized uploads can no longer trip a healthy backend's breaker open and take it offline for everyone. The limit condition is detected by downcasting to `http_body_util::LengthLimitError` (Display-string match kept only as a backstop).
* **security(proxy/websocket):** the raw WebSocket upgrade request and every forwarded header are guarded against CR/LF — a header value, host, path, query, `Sec-WebSocket-*` value, or rewritten `Origin` carrying `\r`/`\n` can no longer smuggle extra request lines or headers into the backend handshake.
* **security(proxy/lua):** proxy target URLs from config and from Lua `on_route` overrides are validated — only `http://`, `https://`, and `redirect://` with a non-empty host are allowed; `file://`, `gopher://`, `ftp://`, and CRLF-bearing targets are refused (**502** / ignored override), closing an SSRF/scheme-smuggling avenue through a compromised route script.
* **security(proxy):** the `force_https` HTTP→HTTPS redirect only redirects to a host/path the proxy actually serves (a matching routing rule or a managed app domain); an unserved forged `Host` gets **400** instead of a 308 to an attacker-chosen origin — closing an open-redirect / Host-header injection vector.
* **security(admin):** the admin API logs a loud warning when it binds a loopback address with no authentication configured — any other local process could otherwise deploy apps, stop apps, and edit routes. Set `ADMIN_USER`/`ADMIN_PASSWORD` or `[admin].api_key`.
* **security(config):** a plaintext `ADMIN_PASSWORD` is now bcrypt-hashed at startup (both the `Default` and env-loaded paths) instead of being stored as-is — previously such a value was kept verbatim and every login attempt failed. `ADMIN_PASSWORD_HASH` is preferred and takes precedence.
* **security(tls/acme):** self-signed and ACME private-key files are tightened to `0600` on load if an earlier install left them group/world-readable.
* **security(admin/deploy):** the Docker container command is spawned without a shell — it uses the same argv parsing (`parse_start_command`) as the native spawn path, so a compromised `start_script` can no longer inject through `/bin/sh -c`.
* **security(admin):** deployment-log responses are capped at the last **256 KiB** so a multi-GB app log can't OOM the proxy; admin request bodies are capped at **1 MB** (`Limited`).

### Performance

* **perf(proxy):** all HTTP and HTTPS accept loops now share **one** connection pool (cheap clones, shared idle keep-alive sockets) with a per-host idle cap of **64** — previously every listener built its own pool, and a multi-tenant deploy with many origins could grow unbounded keep-alive pools.
* **perf(proxy/routing):** host matching in `find_matching_rule` is a single case-insensitive linear scan for any rule count. A previous "optimization" rebuilt a throwaway `HashMap` domain index on **every** request (O(rules) allocations for one lookup), which was slower than the scan it replaced; it's removed.
* **perf(circuit_breaker):** known backends are pre-registered (`prewarm`) at startup so the first request under load doesn't take the `targets` write lock on a cold map.

### Fixed

* **fix(systemd):** the shipped `scripts/soli-proxy.service` could never start — `ExecStart` invoked a `daemon` subcommand that does not exist (`error: unrecognized subcommand 'daemon'`; the flag is `-d`/`--daemon`) and hardcoded a developer's home directory. It now uses `--conf` + `--sites-dir` with a `WorkingDirectory`, and documents that `--conf` takes **`proxy.conf`** (not `config.toml`, which is read from the same directory), that `--sites-dir` is the only way to set the sites location, and that `-d` must not be combined with `Type=simple`. The README's systemd section gained a table of where `run/logs/<app>/<slot>.log`, `run/app_state.json`, `run/ports.lock`, and `certs/` actually land — all relative to `WorkingDirectory`, and unaffected by `SOLI_LOG_DIR`.
* **fix(proxy/lb):** per-rule round-robin / weighted counters that grow on demand — hot-reloaded routes beyond the startup rule count previously all shared `counters[0]`, so their load balancing was coupled; each route now advances an independent counter.
* **fix(proxy/lb):** the weighted strategy with all-zero target weights falls back to the first available target instead of recursing into itself forever (stack overflow).
* **fix(proxy/lua):** Lua `on_request` header edits are actually applied to the forwarded request (they were previously computed and discarded), and only headers whose value genuinely changed are rewritten — so duplicate-valued and non-UTF8 original headers are preserved rather than collapsed to the lossy Lua snapshot.

### Changed

* **config:** `include_request_body` / `include_response_body` are documented as reserved (currently no effect) and default to `false`; the unused `redis_url` is dropped from `[rate_limiting]` (the token bucket is in-process).

## [0.5.0](https://github.com/solisoft/soli-proxy/compare/v0.4.0...v0.5.0) (2026-02-12)


### Features

* **ci:** add macOS build target for cross-compilation ([6242c6c](https://github.com/solisoft/soli-proxy/commit/6242c6cca5f7dee41001ab83237d49a6d82b079f))
* **ci:** add system dependencies installation to CI workflow ([c5e3e48](https://github.com/solisoft/soli-proxy/commit/c5e3e48bf869a779bbbd6242cca4a1f76ba2ce91))

## [0.4.0](https://github.com/solisoft/soli-proxy/compare/v0.3.0...v0.4.0) (2026-02-10)


### Features

* **ci:** add build-binaries job for cross-compilation and release asset upload ([87bc970](https://github.com/solisoft/soli-proxy/commit/87bc9701b1aff4756010145bb3195e162dc6a236))


### Bug Fixes

* **ci:** update PR merge command to remove auto flag for better control ([5f078d5](https://github.com/solisoft/soli-proxy/commit/5f078d5de6f1f66099dd8ae7deb89e983c06bc68))

## [0.3.0](https://github.com/solisoft/soli-proxy/compare/v0.2.0...v0.3.0) (2026-02-10)


### Features

* **app:** enhance AppInfo configuration with auto-detection and fallback logic ([852fc03](https://github.com/solisoft/soli-proxy/commit/852fc030781846859d29cbfc1b697a56e2325224))
* **metrics:** enhance application metrics tracking and add API endpoints for retrieving app metrics ([c5f93b8](https://github.com/solisoft/soli-proxy/commit/c5f93b8278abd37ed4f3f811598a624f16008b6c))

## [0.2.0](https://github.com/solisoft/soli-proxy/compare/v0.1.0...v0.2.0) (2026-02-10)


### Features

* **admin:** initialize _admin module with MVC structure, controllers, and views ([9023363](https://github.com/solisoft/soli-proxy/commit/9023363f2e151d8081038c9f06a07e7b91b49cb6))


### Bug Fixes

* **app:** modify AppInfo::from_path to return default AppConfig if app.infos is not found ([a850a70](https://github.com/solisoft/soli-proxy/commit/a850a705661099954543eaa785fc747082ded2a0))

## 0.1.0 (2026-02-10)


### Features

* **admin:** implement admin REST API with configuration and metrics endpoints ([0061028](https://github.com/solisoft/soli-proxy/commit/006102838192d752ffd72554178d2bd9a7cbd04c))
* **app:** introduce app management with deployment, restart, and rollback endpoints ([4d24521](https://github.com/solisoft/soli-proxy/commit/4d245214c415c2a2ccd129d35aae175e3ab1ad71))
* **circuit_breaker:** implement circuit breaker functionality with configuration and admin endpoints ([8794584](https://github.com/solisoft/soli-proxy/commit/8794584dc6c26ca9767263ebd9fd4e47c528a209))
* **config:** enhance proxy configuration parsing with line continuation support and add tests ([44737ea](https://github.com/solisoft/soli-proxy/commit/44737eab1c1ad7b6283d5542555fadba56a46e8a))
* **lua:** add configuration and integration for Lua scripting support ([1024df5](https://github.com/solisoft/soli-proxy/commit/1024df5b732fafbcc6bc6b65531b87d104bc7547))
