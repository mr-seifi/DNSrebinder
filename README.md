# DNSrebinder

DNSrebinder is a minimal DNS server that can be used to test/verify DNS rebinding vulnerabilities. It is based on the Python DNS library [dnslib](https://github.com/paulc/dnslib). DNSrebinder allows you to define various settings on the command line, including the number of requests before the actual rebinding should occur.

## Installation

The recommended way is to use a Python virtual environment

```
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

On systems using systemd, `systemd-resolved` listens on port 53 and conflicts with DNSrebinder. When you run on port 53 (the default), DNSrebinder now **stops `systemd-resolved` automatically on startup and restarts it on exit** (including on Ctrl-C / SIGTERM). This requires running as root (sudo).

If you'd rather manage it yourself, pass `--no-resolved` and stop/start it manually:

```
sudo systemctl stop systemd-resolved   # before
sudo systemctl start systemd-resolved  # after
```

Please make sure that you have a DNS-NS record that points to the system that is running DNSrebinder.


## Usage

Example usage:
```bash
$ python3 dnsrebinder.py --domain rebind.mydomain.eu. --rebind 127.0.0.1 --ip 8.8.8.8 --counter 2
...
```

This starts a DNS server on port 53 listening on UDP and TCP. The first two(--counter 2) requests will be answered with 8.8.8.8. Every request after that will be answered with the rebind address 127.0.0.1 (--rebind 127.0.0.1).

Options overview:
```bash
$ python3 dnsrebinder.py -h
usage: dnsrebinder.py [-h] [--port PORT] [--tcp] [--udp] --domain DOMAIN
                      [--ttl TTL] [--bind BIND] [--ip IP] [--rebind REBIND]
                      [--counter COUNTER] [--flip] [--random] [--sleep SLEEP]
                      [--reset-after RESET_AFTER] [--no-resolved]

Start a DNS implemented in Python. Usually DNSs use UDP on port 53.

options:
  -h, --help            show this help message and exit
  --port PORT           The port to listen on.
  --tcp                 Listen to TCP connections.
  --udp                 Listen to UDP datagrams.
  --domain DOMAIN       The domain to listen for
  --ttl TTL             TTL value of DNS responses
  --bind BIND           IP Adress for server to listen on
  --ip IP               IP Adress used to respond
  --rebind REBIND       IP address for rebind
  --counter COUNTER     Number of requests before rebinding (ignored when
                        --flip is set)
  --flip                Constantly alternate between --ip and --rebind on
                        every query
  --random              Answer each query independently 50/50 between --ip and
                        --rebind (robust to query storms)
  --sleep SLEEP         Seconds to wait before answering each query (e.g. 1 or
                        2)
  --reset-after RESET_AFTER
                        Reset a host back to the first answer (--ip) after
                        this many seconds of inactivity, so repeated attempts
                        work without a restart
  --no-resolved         Don't automatically stop/start systemd-resolved (port
                        53 only)
```

## Contributing

Feel free to contribute.

## Authors
* **Timo Müller** - *Original script* - [mtimo44](https://twitter.com/mtimo44)
* **Hans-Martin Münch** - *Re-Write with dnslib* - [h0ng10](https://twitter.com/h0ng10)
* **Karsten Zeides** - *Command line options, cleanup* [zeides](https://github.com/zeides)

See also the list of [contributors](https://github.com/mogwailabs/DNSrebinder/graphs/contributors) who participated in this project.


## Response modes

DNSrebinder can decide which of the two addresses to answer with in three ways. They are mutually exclusive; if more than one is given, precedence is **`--random` > `--flip` > `--counter`** (the default).

| Mode | Flag | Behaviour |
|------|------|-----------|
| Counter (default) | `--counter N` | One-way rebind: the first `N` queries for a host get `--ip`, every query after gets `--rebind`. |
| Flip | `--flip` | Alternates on every query: query 1 → `--ip`, query 2 → `--rebind`, query 3 → `--ip`, … (per hostname). |
| Random | `--random` | Answers each query independently, 50/50 between `--ip` and `--rebind`. Because it doesn't depend on a query count, it's robust to duplicate/retransmitted queries ("query storms") that would otherwise desync `--flip`. |

All three track state **per hostname**, are safe under the threading servers (guarded by a lock), and honour `--sleep`, `--reset-after`, and `--ttl`.

Example — keep flipping between two addresses on every query, with a low `--ttl` (1 or 0 so answers aren't cached):

```bash
$ python3 dnsrebinder.py --udp --domain rebind.mydomain.eu. \
    --ip 1.2.3.4 --rebind 5.6.7.8 --ttl 0 --flip
```

Extra options:
```bash
  --flip             Constantly alternate between --ip and --rebind on every query
  --random           Answer each query independently 50/50 between --ip and --rebind
  --sleep SLEEP      Seconds to wait before answering each query (e.g. 1 or 2)
  --reset-after SEC  Reset a host to the first answer (--ip) after SEC seconds idle (repeatable attempts)
  --no-resolved      Don't automatically stop/start systemd-resolved (port 53 only)
```

## Rebinding an SSRF filter (precheck public, fetch localhost)

A common target validates a URL by first resolving the name and checking it's a public IP (the *precheck*), then makes the HTTP request (the *fetch*). To pass the precheck with a public IP but have the fetch land on `127.0.0.1`, serve the public IP to the first DNS query and the internal IP to every query after — with **TTL 0** so the fetch is forced to re-resolve instead of reusing the cached precheck answer:

```bash
python3 dnsrebinder.py --domain 01ca7e732.learnpilot.pro --udp --tcp \
    --ip 187.77.92.204 --rebind 127.0.0.1 --ttl 0 --counter 1 --reset-after 2
```

- `--counter 1` — first query (precheck) → `--ip` (public), every query after → `--rebind` (127.0.0.1).
- `--ttl 0` — do not let resolvers cache; the fetch must re-resolve to get the flipped answer. `--ttl 1` allows ~1s of caching, which is usually enough for the fetch to reuse the precheck's public IP and defeat the rebind.
- `--reset-after 2` — after 2s of no queries for the host, reset it to the first answer, so the next attempt's precheck sees the public IP again without restarting the server.
- Avoid `--sleep` here: a slow answer makes resolvers retransmit the query, and each retransmit advances the counter/flip and can desync which IP the fetch receives.

This depends on the target's resolver honoring TTL 0 and re-resolving for the fetch; if it caches aggressively the rebind window may not open.
