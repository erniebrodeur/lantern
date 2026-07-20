# Lantern

[![CI](https://github.com/erniebrodeur/lantern/actions/workflows/ci.yml/badge.svg)](https://github.com/erniebrodeur/lantern/actions/workflows/ci.yml)

Lantern turns Nmap scans into a local, time-aware 3D network map.

It runs on your machine, stores observations in SQLite, and keeps each scan as
evidence you can revisit or compare later.

> **Status:** Lantern is under active development. The current version is 0.2.0.

## Features

- Background Nmap scans with live progress and cancellation
- Multiple concurrent scans
- Built-in and custom scan profiles
- 3D address-space and traceroute views
- Multi-scan temporal views without duplicate host spheres
- Port, service, OS, reverse DNS, network profiles (RDAP with WHOIS fallback), and local DNS-SD evidence
- One provider lifecycle for discovery, fallback, progress, logs, and evidence
- Local SQLite storage
- One binary with the web interface embedded

## Requirements

- macOS or Linux
- [Nmap](https://nmap.org/) on `PATH`
- A WebGL-capable browser

Optional:

- `mtr` or `traceroute` for route mapping
- `whois` for fallback public network ownership details; Lantern uses RDAP by default
- `avahi-browse` on Linux for local mDNS/DNS-SD advertisements; macOS uses
  the built-in `dns-sd`

## Build and run

Building requires Go 1.25+, Node.js 22.12+ or 20.19+, npm, and Make.

```sh
git clone https://github.com/erniebrodeur/lantern.git
cd lantern
make build
./bin/lantern
```

The frontend is compiled and embedded into `bin/lantern`.
Open <http://127.0.0.1:1414>.

## Usage

Start a previously built Lantern binary:

```sh
./bin/lantern
```

Show the compiled version:

```sh
./bin/lantern --version
```

Lantern includes four scan profiles:

- **Discovery** — host discovery only
- **Quick** — top 100 TCP ports with light service detection
- **Standard** — top 1,000 TCP ports with service detection
- **Deep** — all TCP ports with full version probing

Custom profile arguments can be edited in the scan bar. Lantern's Nmap provider
owns the target, XML output, and progress arguments and executes without a shell.

OS detection requires a privileged launch:

```sh
sudo ./bin/lantern
```

When launched through `sudo`, Lantern continues to use the invoking user's
database and defaults OS detection on.

## Configuration

| Variable | Default |
| --- | --- |
| `LANTERN_ADDR` | `127.0.0.1:1414` |
| `LANTERN_DB_PATH` | `~/.lantern/lantern.db` |
| `LANTERN_NMAP_PATH` | `nmap` |
| `LANTERN_MDNS_PROVIDER` | OS default (`dns-sd` on macOS, `avahi` on Linux) |
| `LANTERN_OWNERSHIP_PROVIDER` | RDAP with WHOIS field fallback |
| `LANTERN_ROUTE_PROVIDER` | `mtr`, then `traceroute` |
| `LANTERN_WHOIS_PATH` | `whois` |

Example:

```sh
LANTERN_ADDR=127.0.0.1:1515 \
LANTERN_DB_PATH=/tmp/lantern.db \
./bin/lantern
```

Lantern binds to loopback by default. It is not intended to be exposed directly
to the internet.

Provider selection and availability are reported by `/api/capabilities`. Set
`LANTERN_<CAPABILITY>_PROVIDER=disabled` to disable a capability, or set it to a
provider ID to pin one implementation. Hyphens become underscores; for example,
`LANTERN_REVERSE_DNS_PROVIDER=disabled` disables PTR lookups.

Public-address enrichment sends the queried address over HTTPS to RDAP.org,
which redirects to the authoritative regional registry. Set
`LANTERN_OWNERSHIP_PROVIDER=disabled` to prevent external ownership lookups.

## Data

Scan history, profiles, host observations, services, OS matches, and saved routes
are stored in SQLite:

```text
~/.lantern/lantern.db
```

Stop Lantern before backing up the database so SQLite can reconcile its WAL.

## License

Lantern is licensed under the [GNU General Public License v3.0](LICENSE).

## Development

```sh
make check
```

`make check` builds the frontend, runs the Go test suite, and runs `go vet`.

For frontend development:

```sh
npm --prefix web ci
npm --prefix web run dev
```

Vite proxies API requests to the Go server on `127.0.0.1:1414`.

If you have any issues, please open a GitHub issue.
