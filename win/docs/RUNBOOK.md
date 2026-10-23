# sing-box — операторский runbook

Единственные нормативные источники: [архитектура](../../edge-platform/ARCHITECTURE.md), [план и acceptance gates](../../edge-platform/FINALIZATION-PLAN.md), [список поддерживаемых команд](../../edge-platform/COMMAND-INVENTORY.md). [Issue #26](https://github.com/iamaman11/sing-box/issues/26) хранит физические свидетельства, [Issue #1](https://github.com/iamaman11/sing-box/issues/1) — единственный авторизованный командный канал.

| Вход Issue #1 | Назначение |
| --- | --- |
| `/host status [machine-id] [--deep]` | Только read-only диагностика, typed причина и missing proof |
| `/host apply <machine-id>` | Только точный Git desired/ReleaseSet и signed native transaction либо штатный first-use отсутствующей VM |
| `/host recover <machine-id>` | Пока read-only preflight; никаких replay/ручных repair |
| `/host apply <machine-id> config/vultr-edge/line1-gateway` или `line2-proxy` | Ограниченный config-only scope как параметр той же `/host apply` |

Старые `/windows`, `/vm`, `/production`, `/credentials`, `/vultr` и подобные команды **запрещены** как операторский mutating путь. Старые журналы и команды — архив аудита, не источник разрешения. Нет отдельного `/host reinstall`, ручного SSH, `docker exec` или прямого sudo.

**VM:** root-owned `edge-agent` — единственный Docker/sing-box mutation owner; GitHub runner — транспорт. Проверять exact receipt, journal, container health, DNS/route/firewall, 4/4 Line1 и 6/6 Line2 + TLS/auth/DIRECT/WARP. На новой машине без runner `status` может вернуть `NO_NATIVE_TARGET_AVAILABLE` — это не PASS и не основание повторять неизвестный CREATE.

**Windows:** пока намеренно STOPPED/PROXY_ONLY. Не включать SYSTEM SCM, TUN, DNS/default route и не трогать Cloudflare One. Установленный `edge-diagnostic.exe doctor` допустим только для чтения после проверки пути/доверия. Не использовать старый privileged dispatcher для новых мутаций.

**Ошибка:** неизвестный ACK или poststate → `UNKNOWN_NO_REPLAY`; спросить один адресный native/local read-only факт, `MUTATIONS=0`. Не публиковать секреты/ключи/незаредактированные runtime configs в Issue, CI, артефакты и чат.
