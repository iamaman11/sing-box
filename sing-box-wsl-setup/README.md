# sing-box в Ubuntu WSL

## Что сделано

22 апреля 2026 года `sing-box` был настроен внутри Ubuntu WSL так, чтобы обычный исходящий трафик Ubuntu прозрачно проходил через `sing-box` через `tun`-интерфейс и выходил наружу через `vless-reality`.

Ожидаемый внешний IP из Ubuntu:

```bash
95.179.170.54
```

## Текущее состояние

- Дистрибутив: `Ubuntu 24.04.4 LTS`
- `systemd`: включен и работает
- `sing-box`: установлен из официального APT-репозитория SagerNet
- `nftables`: установлен
- Сервис: `sing-box.service`
- Состояние сервиса на момент настройки: `enabled`, `active`

## Файлы

- Основной конфиг в Ubuntu: `/etc/sing-box/config.json`
- Бэкап предыдущего конфига: `/etc/sing-box/config.json.bak.20260422-020944`
- Локальная копия активного конфига в этой папке: `config.current.json`
- Временная рабочая копия, созданная из Windows во время настройки: `C:\\Users\\Bose\\wsl-sing-box-config.json`

## Что было установлено

Команды:

```bash
sudo mkdir -p /etc/apt/keyrings
sudo curl -fsSL https://sing-box.app/gpg.key -o /etc/apt/keyrings/sagernet.asc
sudo chmod a+r /etc/apt/keyrings/sagernet.asc
cat <<'EOF' | sudo tee /etc/apt/sources.list.d/sagernet.sources
Types: deb
URIs: https://deb.sagernet.org/
Suites: *
Components: *
Enabled: yes
Signed-By: /etc/apt/keyrings/sagernet.asc
EOF
sudo apt-get update
sudo apt-get install -y sing-box nftables
```

## Как устроена текущая схема

- `sing-box` работает внутри Ubuntu, а не только на Windows.
- Создан Linux `tun` inbound с именем `sbtun`.
- Включены `auto_route` и `auto_redirect`.
- Приватные сети остаются `direct`.
- Основной outbound жёстко зафиксирован на `vless-reality`.
- DNS перехватывается самим `sing-box`.

Это значит, что обычные команды вида:

```bash
curl -4 https://api.ipify.org
apt update
git clone ...
docker pull ...
```

должны выходить в интернет через `sing-box`, а не напрямую.

## Кратко по активному конфигу

Ключевые параметры из `/etc/sing-box/config.json`:

- `inbounds[0].type = tun`
- `inbounds[0].interface_name = sbtun`
- `inbounds[0].address = 172.31.255.1/30`
- `inbounds[0].auto_route = true`
- `inbounds[0].auto_redirect = true`
- `inbounds[0].strict_route = true`
- `outbounds[0].tag = vless-reality`
- `outbounds[0].server = 95.179.170.54`
- `route.final = vless-reality`
- `route.default_domain_resolver = quad9`

## Команды проверки

Проверить внешний IP:

```bash
curl -4 https://api.ipify.org
```

Проверить статус сервиса:

```bash
systemctl status sing-box
```

Посмотреть последние логи:

```bash
journalctl -u sing-box --output cat -n 50
```

Посмотреть маршруты:

```bash
ip route
ip rule show
```

Проверить наличие `tun`-интерфейса:

```bash
ip addr show sbtun
```

## Управление сервисом

Запуск:

```bash
sudo systemctl start sing-box
```

Остановка:

```bash
sudo systemctl stop sing-box
```

Перезапуск:

```bash
sudo systemctl restart sing-box
```

Включить автозапуск:

```bash
sudo systemctl enable sing-box
```

Выключить автозапуск:

```bash
sudo systemctl disable sing-box
```

Выключить и остановить:

```bash
sudo systemctl disable --now sing-box
```

## Автозапуск

`sing-box` сейчас настроен на автозапуск внутри Ubuntu, потому что сервис включён:

```bash
systemctl is-enabled sing-box
```

Важный нюанс:

- `sing-box` стартует автоматически, когда запускается сама WSL-инстанция `Ubuntu` и поднимается `systemd`.
- Это не означает, что Ubuntu сама запускается на каждом старте Windows.
- Если WSL-инстанция не запущена, `sing-box` тоже не работает.

Сценарий после перезагрузки Windows:

1. Вы загружаете Windows.
2. `Ubuntu` сама по себе ещё не запущена.
3. Вы впервые открываете `Ubuntu` или любой процесс обращается к этой WSL-инстанции.
4. WSL запускает инстанцию `Ubuntu`.
5. Внутри `Ubuntu` поднимается `systemd`.
6. `systemd` автоматически запускает `sing-box.service`.
7. После этого трафик `Ubuntu` снова идёт через `sing-box`.

То есть после перезагрузки Windows вручную включать `sing-box` не нужно.
Достаточно просто запустить `Ubuntu`, и сервис поднимется сам, если не был отключён командой `systemctl disable`.

Запустить Ubuntu вручную:

```powershell
wsl -d Ubuntu
```

## Откат

Вернуть старый конфиг:

```bash
sudo cp /etc/sing-box/config.json.bak.20260422-020944 /etc/sing-box/config.json
sudo systemctl restart sing-box
```

Или полностью отключить WSL-side маршрутизацию:

```bash
sudo systemctl disable --now sing-box
```

## Примечания

- На Windows ранее тоже настраивался `sing-box` для проверки WSL через proxy inbound, но прозрачная маршрутизация Ubuntu сейчас делается именно через `sing-box` внутри Ubuntu.
- Именно эта WSL-side настройка делает так, что обычный трафик Ubuntu выходит с IP `95.179.170.54`.
