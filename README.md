# ru-routing

Domain and IP lists for split tunneling from Russia: what doesn't open without
a VPN, and what is better left outside of it.

A category only says what it contains: `youtube`, `telegram`, `ru-blocked`,
`ip-check`. Where the traffic goes is up to your config.

Work in progress. The build already produces Xray and Mihomo files; sing-box
and example configs come next.

## Categories

| Category | Contents |
|---|---|
| `ads` | Ads and trackers |
| `ads-big` | Ads and trackers, the aggressive list |
| `ai` | AI services: ChatGPT, Claude, Gemini, Copilot, Perplexity and others |
| `geoblock-ru` | Services that refuse Russian users on their own |
| `ip-check` | Services that show your IP address and where it is |
| `push` | Push notifications from Apple and Google |
| `ru` | Russian sites and networks |
| `ru-blocked` | Blocked by Roskomnadzor |
| `ru-unreachable` | Everything known not to open from Russia without a tunnel, minus IP checkers |
| `telegram` | Telegram: apps, web and the networks of its data centers |
| `win-spy` | Windows telemetry |
| `youtube` | YouTube: site, apps, player and video CDN |

## Variants

The registry of blocked sites holds well over a million domains, and almost
none of them are ever opened: of 1.75 million, people in Russia visited about
nine thousand. Big lists cost memory, and VPN extensions on iOS have only 50 MB.

So every category comes in four sizes. They share the same names and differ only
in how much of the bulk lists they keep, taking the domains most visited from
Russia first (by the [Chrome UX Report](https://github.com/zakird/crux-top-lists)).

| Variant | For |
|---|---|
| `lite` | iOS |
| `standard` | phones and routers |
| `full` | every bulk domain that anyone in Russia actually visits |
| `max` | everything |

Limits live in [`variants.toml`](variants.toml).

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

Python 3.11 or newer, no dependencies. Mihomo rule-sets need the
[mihomo](https://github.com/MetaCubeX/mihomo) binary in `PATH` or in `$MIHOMO`.

```
python -m ru_routing build          # every variant into dist/
python -m ru_routing why chatgpt.com
```

The result:

```
dist/<variant>/geosite.dat              Xray, v2ray
dist/<variant>/geoip.dat
dist/<variant>/mihomo/geosite/*.mrs     Mihomo, one rule-set per category
dist/<variant>/mihomo/geoip/*.mrs
dist/<variant>/text/                    plain lists
```

`why` tells which categories match a domain or an address, and where each
entry came from:

```
$ python -m ru_routing why chatgpt.com
ai: domain:chatgpt.com  (v2fly/openai:3)
ru-blocked: domain:chatgpt.com  (runetfreedom/ru-blocked:81)
```

If upstream lists can't be reached from where you are, download them elsewhere
with `python -m ru_routing fetch`, copy `.cache/` over and build with `--offline`.

## License

The code is MIT. The lists include GPL-3.0 data, so the lists themselves are
GPL-3.0.
