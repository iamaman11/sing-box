# sing-box — единственная актуальная точка входа

Канонический проект: https://github.com/iamaman11/sing-box (удалённый защищённый `main`). Старые чаты, локальные копии, старые PR и описания этапов — не источники текущей истины.

## Документы без конкурирующих планов

1. [ARCHITECTURE.md](edge-platform/ARCHITECTURE.md) — неизменяемые принципы и целевой продукт.
2. [FINALIZATION-PLAN.md](edge-platform/FINALIZATION-PLAN.md) — **единственный план разработки** до физической приёмки 10/10.
3. [COMMAND-INVENTORY.md](edge-platform/COMMAND-INVENTORY.md) — реализованные команды против целевого публичного интерфейса.
4. [NEXT-CHAT.md](edge-platform/NEXT-CHAT.md) — инструкция продолжения в новом чате.
5. [Issue #26](https://github.com/iamaman11/sing-box/issues/26) — единственный **текущий физический курсор и долговечный журнал операций**; не второй архитектурный план.
6. [Issue #1](https://github.com/iamaman11/sing-box/issues/1) — авторизованный канал команд, не план разработки.

При расхождении данных фиксировать `UNKNOWN/BLOCKED`, сверять реальные владельцы и исходный журнал; не выдавать успешный CI за установленную или принятую систему.

## Один продукт

Один protobuf-реестр Windows/VM, один Rust Orchestrator, существующие Windows Controller и Linux Rust Agent как единственные локальные владельцы, Cloudflare Worker как единственный владелец секретов. GitHub только авторизует, доставляет, журналирует и публикует immutable ReleaseSet. **Цель:** `host status`, `host apply`, `host recover`. Новая машина, контейнер, sing-box-конфигурация не требуют ещё одного инсталлятора, демона, реестра или workflow.

## Фактическое состояние — 18 октября 2026

- PR [#394](https://github.com/iamaman11/sing-box/pull/394) и [#395](https://github.com/iamaman11/sing-box/pull/395) объединены; immutable [main promotion #39072388126](https://github.com/iamaman11/sing-box/actions/runs/39072388126) PASS.
- Read-only [VM #39072466180](https://github.com/iamaman11/sing-box/actions/runs/39072466180), [Windows #39072469654](https://github.com/iamaman11/sing-box/actions/runs/39072469654) PASS через явно обозначенный **DEEP fallback**, не новую нативную FAST-версию.
- Windows: намеренно **Stopped / OnDemand / ProxyOnly**, без sing-box и TUN; Cloudflare One независим. VM: три основных контейнера исправны; credentials B поколения `38503639351` всё ещё CANDIDATE.
- [Исходный A/B BEGIN](https://github.com/iamaman11/sing-box/issues/26#issuecomment-6229884538), run `39004301614`, **не имеет терминального COMMIT/ABORT**.
- [Recovery #39072475032](https://github.com/iamaman11/sing-box/actions/runs/39072475032) добрался до обоих владельцев, но завершился FAIL-CLOSED: исторический ReleaseSet не принят контекстом нового Rust owner. Без мутаций.

**10/10 НЕ ПРИНЯТО.** Исторический внешний Line1 4/4 и Line2 6/6 с reboot не доказывает текущий A/B COMMIT, универсальный lifecycle или TUN. См. точные критерии в плане.
