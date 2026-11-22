# ru-routing

Domain and IP lists for split tunneling from Russia: what doesn't open without
a VPN, and what is better left outside of it.

A category only says what it contains: `youtube`, `telegram`, `ru-blocked`,
`ip-check`. Where the traffic goes is up to your config.

Work in progress: for now the build produces plain text lists. Xray, Mihomo
and sing-box formats come next.

## Categories

| Category | Contents |
|---|---|
| `ai` | AI services: ChatGPT, Claude, Gemini, Copilot, Perplexity and others |
| `ip-check` | Services that show your IP address and where it is |
| `push` | Push notifications from Apple and Google |
| `ru-blocked` | Blocked by Roskomnadzor, the curated part of the registry |
| `telegram` | Telegram: apps, web and the networks of its data centers |
| `youtube` | YouTube: site, apps, player and video CDN |

## Format

A category is a file in `data/`. The format is the one of
[v2fly/domain-list-community](https://github.com/v2fly/domain-list-community)
with a few additions:

```
# The first comment block describes the category.

example.com                  the domain and all its subdomains
full:www.example.com         this exact name only
keyword:example              substring
regexp:^ex(am)?ple\.         regular expression
ip:91.108.4.0/22             network
asn:62041                    every network of an autonomous system
include:youtube              another category
include:v2fly/google @ads    an upstream list, entries marked @ads only
exclude:ip-check             drop whatever another category has
```

Upstream lists are described in [`sources.toml`](sources.toml).

## Building

Python 3.11 or newer, no dependencies.

```
python -m ru_routing build          # lists go to dist/
python -m ru_routing why chatgpt.com
```

`why` tells which categories match a domain or an address, and where each
entry came from:

```
$ python -m ru_routing why chatgpt.com
ai: domain:chatgpt.com  (v2fly/openai:3)
ru-blocked: domain:chatgpt.com  (runetfreedom/ru-blocked:81)
```

## License

The code is MIT. The lists include GPL-3.0 data, so the lists themselves are
GPL-3.0.
