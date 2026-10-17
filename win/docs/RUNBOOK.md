# Оператор: одна штатная точка входа

Канонические правила: [архитектура](../../edge-platform/ARCHITECTURE.md), [план](../../edge-platform/FINALIZATION-PLAN.md), [физический курсор](https://github.com/iamaman11/sing-box/issues/26). Удалённый GitHub, не локальная копия, — источник истины.

В авторизованном Issue #1 вводятся:
- `/host status` — read-only реестр хостов.
- `/host status <machine-id> [--deep]` — read-only нативная диагностика.
- `/host apply <machine-id>` — только при доказанном безопасном праве одной мутации.
- `/host recover <machine-id>` — **пока read-only**; не выдавать за полное восстановление.

`/windows`, `/vm`, `/production`, `/vultr`, `/vpc`, `/application`, `/credentials` — существующие низкоуровневые поверхности переходного периода, **не** альтернативные пользовательские приложения. Использовать только по прямому указанию действующего Issue #26; переносить их уникальные функции в штатный host owner и затем удалять.

### Windows

`EdgePlatformController` намеренно Stopped/OnDemand, режим ProxyOnly, нет TUN. Независимый Cloudflare One Client не трогать. Установленный legacy doctor может не принимать `--fast`, поэтому в текущем коде он явно переходит к DEEP read-only:

    & "C:\sing-box\bin\edge-diagnostic.exe" doctor "C:\sing-box\current.pb"

Никакого неявного start/repair/converge/reboot, изменения DNS/маршрутов, ManagedTun ради «диагностики». Режим TUN только после отдельного приёмочного допуска.

### VM и credentials

Только установленный root-owned `edge-agent` выполняет VM контейнерные и сетевые изменения; runner — транспорт. Для оригинального A/B искать ровно его durable BEGIN в Issue #26 и независимо сверять native owner/receipts/исторический ReleaseSet и актуальный network witness. Исторический источник не должен подменяться текущим `main`. Любой неясный ACK — `UNKNOWN_NO_REPLAY`, не новая генерация, не второй BEGIN и не скрытый rollback.

Никогда не публиковать приватные credentials, хеши секрета, ключи и незаредактированные runtime конфиги в Issues, CI, артефактах или чате.
