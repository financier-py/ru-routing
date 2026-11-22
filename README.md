# ru-routing

Списки доменов и адресов для раздельного туннелирования из России: что без VPN
не открывается и что, наоборот, лучше пускать напрямую.

Категория говорит только о том, что в ней лежит: `youtube`, `telegram`,
`ru-blocked`, `ip-check`. Куда отправлять трафик, решает ваш конфиг.

Проект в разработке: пока собираются текстовые списки, форматы для Xray,
Mihomo и sing-box будут следующими.

## Категории

| Категория | Что внутри |
|---|---|
| `ai` | Нейросети: ChatGPT, Claude, Gemini, Copilot, Perplexity и другие |
| `ip-check` | Сервисы, которые показывают ваш IP и где он находится |
| `push` | Push-уведомления Apple и Google |
| `ru-blocked` | Заблокированное Роскомнадзором, очищенная часть реестра |
| `telegram` | Telegram: приложения, веб и сети его дата-центров |
| `youtube` | YouTube: сайт, приложения, плеер и видео |

## Формат

Категория — это файл в `data/`. Формат тот же, что у
[v2fly/domain-list-community](https://github.com/v2fly/domain-list-community),
с несколькими дополнениями:

```
# Первый блок комментариев — описание категории.

example.com                  домен со всеми поддоменами
full:www.example.com         только этот адрес
keyword:example              подстрока
regexp:^ex(am)?ple\.         регулярное выражение
ip:91.108.4.0/22             сеть
asn:62041                    все сети автономной системы
include:youtube              другая категория
include:v2fly/google @ads    список из источника, только записи с @ads
exclude:ip-check             убрать то, что есть в другой категории
```

Источники описаны в [`sources.toml`](sources.toml).

## Сборка

Нужен Python 3.11 или новее, сторонних зависимостей нет.

```
python -m ru_routing build          # списки в dist/
python -m ru_routing why chatgpt.com
```

`why` показывает, в какие категории попадает домен или адрес и откуда взялась
каждая запись:

```
$ python -m ru_routing why chatgpt.com
ai: domain:chatgpt.com  (v2fly/openai:3)
ru-blocked: domain:chatgpt.com  (runetfreedom/ru-blocked:81)
```

## Лицензия

Код распространяется по лицензии MIT. Собранные списки включают данные под
GPL-3.0, поэтому сами списки тоже под GPL-3.0.
