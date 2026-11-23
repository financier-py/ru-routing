# ru-routing

Domain and IP lists for split tunneling from Russia: what doesn't open without
a VPN, and what is better left outside of it. Built every night from public
block lists and from our own checks made from Russian home connections.

A category only says what it contains: `youtube`, `telegram`, `ru-blocked`,
`ip-check`. Where the traffic goes is up to your config.

## Download

Every night a [release](../../releases/latest) is published if anything changed.

| | lite | standard | full | max |
|---|---|---|---|---|
| Xray, v2ray (Happ, INCY, v2rayN) | [geosite][s-lite] · [geoip][i-lite] | [geosite][s-std] · [geoip][i-std] | [geosite][s-full] · [geoip][i-full] | [geosite][s-max] · [geoip][i-max] |
| Mihomo (Clash Meta, FlClash, Koala, RabbitHole) | [rule-sets][m-lite] | [rule-sets][m-std] | [rule-sets][m-full] | [rule-sets][m-max] |
| Plain text | [lists][t-lite] | [lists][t-std] | [lists][t-full] | [lists][t-max] |

For Mihomo, point each rule provider at its own file on the `release` branch:

```
https://raw.githubusercontent.com/financier-py/ru-routing/release/full/mihomo/geosite/ru-unreachable.mrs
https://cdn.jsdelivr.net/gh/financier-py/ru-routing@release/full/mihomo/geosite/ru-unreachable.mrs
```

Ready configs are in [`examples/`](examples): Xray and Mihomo, each in two modes.
**Smart** sends only what doesn't open from Russia through the tunnel. **Classic**
sends everything except Russian sites.

[s-lite]: ../../releases/latest/download/geosite-lite.dat
[i-lite]: ../../releases/latest/download/geoip-lite.dat
[s-std]: ../../releases/latest/download/geosite-standard.dat
[i-std]: ../../releases/latest/download/geoip-standard.dat
[s-full]: ../../releases/latest/download/geosite-full.dat
[i-full]: ../../releases/latest/download/geoip-full.dat
[s-max]: ../../releases/latest/download/geosite-max.dat
[i-max]: ../../releases/latest/download/geoip-max.dat
[m-lite]: ../../releases/latest/download/mihomo-lite.tar.gz
[m-std]: ../../releases/latest/download/mihomo-standard.tar.gz
[m-full]: ../../releases/latest/download/mihomo-full.tar.gz
[m-max]: ../../releases/latest/download/mihomo-max.tar.gz
[t-lite]: ../../releases/latest/download/text-lite.tar.gz
[t-std]: ../../releases/latest/download/text-standard.tar.gz
[t-full]: ../../releases/latest/download/text-full.tar.gz
[t-max]: ../../releases/latest/download/text-max.tar.gz

## Categories

<!-- categories -->
| Category | Contents |
|---|---|
| `ads` | Ads and trackers |
| `ads-big` | Ads and trackers, the aggressive list |
| `ai` | AI services: ChatGPT, Claude, Gemini, Copilot, Perplexity and others |
| `cloudflare` | Networks of Cloudflare |
| `cloudfront` | Networks of Amazon CloudFront, a CDN |
| `discord` | Discord: apps, web, media and voice |
| `geoblock-ru` | Services that refuse Russian users on their own |
| `google` | Every Google service |
| `hand-checked` | Hosts checked by hand from a Russian home connection: broken at home, fine abroad |
| `hdrezka` | HDRezka and its mirrors |
| `hetzner` | Networks of Hetzner, a German hosting provider |
| `hypixel` | Hypixel, the Minecraft server |
| `ip-check` | Services that show your IP address and where it is |
| `meta` | Meta: Facebook, Instagram, WhatsApp, Threads |
| `os-updates` | Updates and downloads of Windows, Android, Chrome and Apple systems |
| `ovh` | Networks of OVH, a French hosting provider |
| `push` | Push notifications from Apple and Google |
| `roblox` | Roblox: site, launcher and game servers |
| `ru` | Russian sites and networks |
| `ru-blocked` | Blocked by Roskomnadzor |
| `ru-unreachable` | Everything known not to open from Russia without a tunnel: blocked, geoblocked or throttled |
| `scaleway` | Networks of Scaleway, a French hosting provider |
| `scan-broken` | Sites that don't open from a Russian home connection but do from abroad: blocked, throttled or geoblocked |
| `scan-working` | Sites on block lists that open fine from a Russian home connection, in every home scan |
| `telegram` | Telegram: apps, web and the networks of its data centers |
| `tiktok` | TikTok |
| `torrent` | Public BitTorrent trackers |
| `twitter` | X, formerly Twitter |
| `win-spy` | Windows telemetry |
| `youtube` | YouTube: site, apps, player and video CDN |
<!-- /categories -->

Put `ip-check`, `push` and `os-updates` above `ru-unreachable` in a config.
Some services refuse Russia only in part, so `ru-unreachable` holds all of
`google.com`, and push notifications sit inside it.

## Variants

The registry of blocked sites holds over 1.6 million domains, and almost none of
them are ever opened. We checked a sample of the ones nobody visits: two thirds
no longer exist, and most of the rest are casino and pirate-cinema clones. Big lists cost memory, and
VPN extensions on iOS have only 50 MB.

So every category comes in four sizes. They share the same names and differ only
in how much of the bulk lists they keep, most visited first. Popularity comes
from the [Chrome UX Report](https://github.com/zakird/crux-top-lists) for Russia,
its neighbours and the countries VPN users exit through: a site that opens from
Russia only over a VPN is counted where the VPN is.

| Variant | For | Memory the lists take in Xray 26.10, at startup |
|---|---|---|
| `lite` | iOS, if `standard` is too much | about 10 MiB |
| `standard` | iOS and phones | about 17 MiB |
| `full` | Android, computers, routers | about 17 MiB |
| `max` | everything, routers with memory to spare | over 150 MiB |

`lite` and `standard` leave out the big ad list. The popular part of the
registry is small enough today that all three keep the same `ru-unreachable`;
the limits only start to bite as it grows. They live in
[`variants.toml`](variants.toml).

## How the lists are made

Public lists go in first: the Roskomnadzor registry, v2fly, itdog, antifilter,
re:filter, no-russia-hosts, OISD and others, see [`sources.toml`](sources.toml).
A source that fails or suddenly shrinks is replaced by its last good copy.

Then our scanner checks the sites people in Russia actually visit, from home
connections in Russia and from abroad at the same time, and compares what came
back. A status code proves nothing, so it looks at the page itself:

- **blocked**: the connection is cut or a stub page comes back;
- **throttled**: the page starts loading and freezes after 16 KB or so;
- **geoblocked**: the page says it isn't available in your country, or the
  service refuses with 403 while abroad it works;
- the scripts and styles a page loads from other hosts are checked too: a page
  may load while its CDN is throttled.

A site goes to `scan-broken` only if it failed in every home scan and loaded
abroad. `scan-working` lists sites from block lists that open fine.

## Help with a scan

Blocking differs from one provider to another, so every extra home connection
makes the lists better. You need Python 3.11 or newer, nothing else.

```
git clone https://github.com/financier-py/ru-routing
cd ru-routing
curl -LO https://github.com/financier-py/ru-routing/releases/latest/download/targets.txt
python -m ru_routing scan targets.txt --limit 100000
```

The first 100 000 sites take an hour or two; the most visited ones come first,
so stopping early still helps, and a stopped scan picks up where it left off.
If a VPN is on, the scanner goes around it through your home connection and
makes sure it is seen from Russia; if it can't, it asks you to turn the VPN off.
The result is `scan.jsonl`: which sites opened and how. Nothing about you or your
computer is in it. Send it to us in an issue.

On Windows, install Python from [python.org](https://www.python.org/downloads/)
and run the same commands in PowerShell.

## Building

```
python -m ru_routing build          # every variant into dist/
python -m ru_routing check          # checks.txt against the build
python -m ru_routing why chatgpt.com
```

```
$ python -m ru_routing why chatgpt.com
ai: domain:chatgpt.com  (v2fly/openai:3)
ru-blocked: domain:chatgpt.com  (runetfreedom/ru-blocked)
```

Mihomo rule-sets need the [mihomo](https://github.com/MetaCubeX/mihomo) binary in
`PATH` or in `$MIHOMO`. `tools/memory.py` measures what a variant costs a core;
build Xray with the matcher phones get (`tools/build-xray.sh`), the desktop one
costs several times more.

A category is a file in [`data/`](data), in the format of
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
resolve:mc.hypixel.net       the addresses this name has at build time
include:youtube              another category
include:v2fly/google @ads    an upstream list, entries marked @ads only
exclude:ip-check             drop whatever another category has
```

## License

The code is MIT. The lists include GPL-3.0 data, so the lists themselves are
GPL-3.0.
