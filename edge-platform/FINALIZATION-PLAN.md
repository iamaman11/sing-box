# sing-box — единственный план завершения и приёмки

**Канон:** защищённый [GitHub `main`](https://github.com/iamaman11/sing-box/tree/main). Нормативные ограничения — [ARCHITECTURE.md](ARCHITECTURE.md), реальные команды — [COMMAND-INVENTORY.md](COMMAND-INVENTORY.md). [Issue #26](https://github.com/iamaman11/sing-box/issues/26) — доказательства и журнал, **не второй план**; [Issue #1](https://github.com/iamaman11/sing-box/issues/1) — единственный вход операторских `/host`. Ни дата в этом документе, ни старый хеш не заменяют текущие GET из GitHub и Cloudflare.

## Текущий физический блокер — pending Worker, а не криптография

Снимок на **2026-10-24T21:37:05Z**, независимо подтверждён локальным агентом и [Issue #26](https://github.com/iamaman11/sing-box/issues/26#issuecomment-6389920626). Проверять актуальность непосредственно перед операцией.

| Объект | Доказанный факт | Не доказано |
| --- | --- | --- |
| Код | [PR #473](https://github.com/iamaman11/sing-box/pull/473) MERGED; `main=05395efd2f24d601358cb5a78dc6500cd4b1d075`; CI 6/6, real Rust ring → workerd, no-rebuild promotion PASS | Работа production Host signer |
| Immutable ReleaseSet | `0cf9a1e908d26ff89158ccbcc4cf912816b8e2c43d4d2981ac324929c556f4a1` | Физически установленный VM release |
| Cloudflare Worker `sing-box-credentials-vm` | active `0f0dd4c2-e9b2-40d2-9cb1-fad5f0f09245`, 100%; pending/latest `12286a19-8130-4d31-bb1d-5c7831016cdb` (upload `2026-10-24T21:22:15Z`); 8/8 имён/типов secret bindings совпадают | **Привязка source к exact pending version доказана независимым GET**; равенство secret values остаётся UNPROVEN |
| Незавершённая операция | [apply #40133800475](https://github.com/iamaman11/sing-box/actions/runs/40133800475) FAILED после успешного version upload, **до deployment**, durable BEGIN [#6389693925](https://github.com/iamaman11/sing-box/issues/26#issuecomment-6389693925) | Историческое поле returned version ID (не подменять provider-proven pending ID) |
| VM `application-acceptance-3` | Независимый [status #40134038782](https://github.com/iamaman11/sing-box/actions/runs/40134038782): `VM_RELEASE_ABSENT_LOCAL_ONLY`, 0/3 containers | Signed native receipt, внешние 4/4+6/6 и DNS/TLS/auth/DIRECT/WARP |

**Независимое доказательство на 2026-10-24T21:49:16Z:** Cloudflare official exact-version `GET /workers/workers/{worker_id}/versions/{version_id}?include=modules` вернул модуль `index.mjs` с побайтно проверенным SHA256 `12dd57c6396e3acf9fd271ee214a77cf2d6d48cef1ccff26f83c28b98b9cb6d4` для pending `12286a19-8130-4d31-bb1d-5c7831016cdb`. Для active predecessor SHA256 `aa68a2251caa388ed23ce5bc6cc0ea088038402f1ff718b3f0db726322c35c1d`. `content/v2` соответствует latest в этом наблюдении, **не привязан** к exact active version. `etag` не используется как SHA256.

**Следующий срез реализации:** [PR #475](https://github.com/iamaman11/sing-box/pull/475) добавляет native version-bound GET и новую owner-gated reconciliation failed BEGIN → новый BEGIN → один deployment существующего ID. Статус кандидата проверять через GitHub; ни PR, ни тесты **не доказывают** физический Worker deployment.

**Запрещено:** повторять `issue1-comment-6389680710`, запускать новую загрузку Worker вместо reconciliation, принимать `content/v2` за доказанные байты **активной** версии при `active != latest`, считать `workers/tag` или `resources.script.etag` равным SHA256 без доказанного алгоритма/семантики. Ошибка `verify_exact_pending_worker_version()` сейчас объединяет несколько условий; номер нарушенного условия исторически не сохранён. Не объявлять eventual consistency причиной без evidence.

## Срез 1 — завершить единственную цепочку Worker → signed VM

**Один законченный кодовый/операционный срез; не добавлять новые команды, службы, SSH-runtime, ручной deploy или recovery fallback.**

1. **Read-only version-bound attestation.** Через существующий Rust Cloudflare provider проверить exact active/latest/deployment/traffic, immutable ReleaseSet, Git pin, VM identity, восемь bindings, отсутствие внешнего изменения Windows Worker, журнал и текущее owner состояние. Привязать **полное** содержимое pending к exact version ID через документированный `include=modules` GET, проверить в Native Rust при каждом новом допуске. `/scripts/.../content/v2` без доказанной version association не проходит этот gate; скрытые secret values недоступны и не запрашиваются.
2. **Один типизированный owner reconciliation.** Превратить общий readback отказ в отдельные Rust closed reasons с номером поля сравнения и безопасными bounded metadata; сделать состояние `PENDING_VERIFIED` адресным, а не запускать старую ветку, которая требует `active == latest`. Журнал failed upload не объявлять успешным: запрет старого operation ID остаётся. Если идентичность exact pending нельзя доказать либо нет authorized isolated previous effect — `BLOCKED_NO_REPLAY`, без автоматического PATCH/POST.
3. **Только после proof:** разрешить **новую** owner-gated транзакцию на deployment **уже загруженного** version ID (no reupload), с собственными BEGIN, exact source/Git/ReleaseSet CAS, single-write и независимым readback `active == latest == target`, 100% traffic, bindings и signed result. Если API не даёт необходимого version-bound source proof — сначала исправить контракт доказательства, **не** ослаблять verifier и не «спасать» состояние ручным Cloudflare deploy.
4. **Свежий signed INSTALL:** новый `/host apply application-acceptance-3` только после доказанного Worker deployment, чистого operation/journal допуска, доступного native root owner и соответствующего Git desired; не повторять предыдущий HostIntent. Проверить signed receipt, exact installed binaries/images/config, Docker 3/3 и отдельную внешнюю матрицу Line1 4/4, Line2 6/6, TLS/auth, DIRECT/WARP, DNS, firewall/routes и scope чужого Mesh.

**Автотесты до merge:** pending version + прежний active, чужой latest/etag/identity, изменённые bindings, uncertain upload/deploy ACK, tampered Git/journal, unknown API hash semantics, concurrency/CAS, запрет повторной записи, no secret leak и no native apply до Worker receipt. CI exact SHA **6/6** → защищённый merge → immutable ReleaseSet **без пересборки** → отдельно физическая приёмка. Успешный CI не засчитывать как VM READY.

**Критерий закрытия:** Worker `EXACT_ACTIVE_VERSION_PROVEN`, один owner/result, VM native signed receipt, 3/3 точных контейнера и **10/10** проверенных endpoints со всеми независимыми сетевыми негативными тестами. Любой недостающий факт обозначать `UNPROVEN` или `BLOCKED`.

## Срез 2 — эксплуатация, recovery и Windows

После приёмки VM, не параллельным обходом:

1. **Эксплуатационный цикл VM:** Scoped config-only Line1/Line2 без чужих изменений; exact ReplaceRelease/reinstall, offline runner, crash/unknown ACK, drift и typed `/host recover`. Сейчас `recover` — **только read-only preflight**. Mutating recover добавлять лишь в существующий native owner с typed handler, журналом и отдельной проверенной транзакцией. Отсутствующие handlers host DNS/firewall/routes остаются `UNSUPPORTED`, не shell/docker exec.
2. **Windows:** защищённый SYSTEM Controller/SCM, ACL и точный release install/readback; безопасный ProxyOnly lifecycle, replace/reinstall/rollback/reboot с native receipt. Windows сейчас **STOPPED/PROXY_ONLY**, SYSTEM apply/TUN ещё не приняты. Managed TUN, DNS leak/IPv6, default routes и сосуществование с Cloudflare One — отдельная физическая матрица только после Git desired и разрешения; чужой адаптер/службу не изменять.
3. **Архитектурный долг, только с доказанным потребителем:** заменить оставшиеся исполняемые `grep/sed` admission-проверки на закрытый Rust/Protobuf verifier в том же owner и убрать действительно нулевых потребителей старых mutating helpers. Не запускать самостоятельную бесконечную «очистку» файлов. Новая capability: `Protobuf → Rust DAG/planner → существующий native handler → typed readback → signed receipt → physical acceptance`.

**Конечный PASS:** две платформы устанавливаются, диагностируются, ограниченно перенастраиваются, обновляются и восстанавливаются **исключительно** тремя `/host` командами, с единым Git/Worker/root|SYSTEM owner chain, без произвольных команд, повторов UNKNOWN, лишних transport/secret registries, скрытых rollback. Независимо приняты network/TLS/auth/egress и негативные тесты. До этого проект `NOT_ACCEPTED_10_10`.

## Постоянные правила

- Один канонический `main` и Git desired, один immutable ReleaseSet, один Rust decision owner, один Cloudflare Worker credential/signing plane, один VM root Agent / Windows SYSTEM Controller. GitHub Actions/runner — доставка, не физический mutation owner.
- Исторические PR, issue/runner logs, Windows/WSL старые runbook — **свидетельства**, не допуск операции. Issue #26 сохранять; **не повторять** failed/unknown BEGIN/HostIntent. Отсутствие факта → **один адресный read-only запрос** существующему локальному агенту (никакого секрета в чат/GitHub).
- Сохранить source/provenance и install/external gates раздельными. Новую физическую операцию разрешать только после точной независимой сверки текущего provider/journal poststate и с новым подписанным operation ID.
- Приоритет: закончить сквозную физическую приёмку, а не плодить новые планы/этапы/службы/адаптеры.
