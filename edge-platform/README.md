# edge-platform: один Rust control plane

**Навигация:** [нормативная архитектура](ARCHITECTURE.md) · [единый план 10/10](FINALIZATION-PLAN.md) · [команды](COMMAND-INVENTORY.md) · [инструкция нового чата](NEXT-CHAT.md) · [физический журнал Issue #26](https://github.com/iamaman11/sing-box/issues/26).

Защищённый удалённый GitHub `main` — единственный источник кода и desired state. GitHub авторизует/доставляет запрос и публикует immutable ReleaseSet; типизированный Rust `edge-orchestrator` решает; Windows SYSTEM Controller или VM root Rust Agent исполняет; Cloudflare Worker владеет secrets. Один HostRegistry в `infra/hosts/hosts.textproto`. Цель: `/host status`, `/host apply`, `/host recover`.

**Не считать реализацию принятой по CI.** Исходный A/B BEGIN run `39004301614` не имеет терминальной записи; `/credentials recover` #39072475032 не прошёл native Rust historical release-context check, хотя оба хоста ответили. Текущий `host recover` read-only. Windows намеренно Stopped/OnDemand/ProxyOnly, без TUN; Cloudflare One Client независим. Подробнее в [единственном плане](FINALIZATION-PLAN.md).

Новый функционал — типизированные поля и существующий владелец, а не новые workflow, службы, локальные JSON authority или обходные транспортные пути.
