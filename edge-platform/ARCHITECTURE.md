# sing-box — нормативная архитектура

Это **единственный нормативный архитектурный контракт**. Единственный [план завершения](FINALIZATION-PLAN.md); [Issue #26](https://github.com/iamaman11/sing-box/issues/26) — живой курсор и архив, НЕ источник допуска к операциям. Истина — защищённый удалённый GitHub `main`, не локальные файлы или устные статусы.

**Запрещены:** историческая A/B, старые credential workflows, дубли команд, reserve secrets, migration fallback, replay и новые агенты/службы/реестры.

## Единственная цепочка ответственности

| Уровень | Единственный authority |
| --- | --- |
| Canonical desired, machine/owner selectors, code | GitHub `main`: `infra/hosts/hosts.textproto`, typed protobuf, immutable ReleaseSet |
| Resource graph и решение о переходе | Rust `edge-orchestrator` / `edge-shared-types` |
| Секреты и разрешение операции | Cloudflare Worker, CredentialRef и подписанный HostIntent |
| Физические Windows/SCM/sing-box операции | Установленный SYSTEM `EdgePlatformController` |
| Физические VM/Docker/sing-box операции | Установленный root `edge-agent` |
| Передача запроса/кандидата | GitHub Actions runner: **только транспорт**, не mutation authority |
| Итог | Durable journal + native physical readback + authenticated receipt (целевой контракт) |

## Неизменяемый контракт иерархии ресурсов

Одна сквозная цепь: `MachineId → ResourceKind/ResourceId → Parent/Dependencies → Owner → ImmutableDesired → NativeObserved → TypedReason → PlannedStep → SignedHostIntent → NativeEffect → PhysicalReadback → Receipt`.

1. **Ресурс.** `ResourceKind`, `ResourceId` и `MachineId` определяют единственную идентичность и единственного владельца. Отсутствующий/неподтверждённый owner, чужой Docker Compose project, Mesh или Windows Cloudflare One дают `BLOCKED`, никогда автоматическое присвоение.
2. **Иерархия.** Каждый узел принадлежит ровно одному зарегистрированному host; зависимости указывают на допустимые идентичности. Циклы, дубли, неявные Docker networks, подмена родителя и изменение соседнего ресурса не допускаются. Ошибка ребёнка поднимается к родителю в диагностике, но **не** разрешает менять родителя.
3. **Состояние.** Desired исходит только из Git и immutable ReleaseSet; Compose, sing-box JSON, systemd/SCM, DNS, firewall — выход рендера или фактический readback, не второй desired. Образ — pinned digest. Secret value остаётся только у Worker/целевого native owner, наружу — CredentialRef.
4. **Диагностика.** `host status <machine-id> --deep` обязан указывать путь ресурса, owner, dependencies, exact desired/observed digest, timestamp, scope источника, typed reason, proposed action, `UNPROVEN/BLOCKED`. Нельзя заменять ошибки TLS, DNS, маршрута, образа или конфигурации общим `container unhealthy`. Текст — отображение enum, не самостоятельное правило.
5. **Операция.** `host apply/recover` вызывает только один Rust planner и известный native handler. При отсутствии обработчика — `UNSUPPORTED` с `ResourceId`, не `docker exec`, SSH, shell, ручная правка конфигурации, новый workflow или универсальный reinstall. Прежде чем менять Line2, доказать scope и неизменность Line1, WARP и network; общие зависимости изменять только атомарно и явно.
6. **Неповторяемость.** Перед BEGIN: Git digest, ownership, dependency graph, exact signed intent, Worker auth и native lock. После BEGIN неизвестный ACK, crash, недоказанный poststate → `UNKNOWN_NO_REPLAY`; никакой повторной попытки или скрытого rollback. Новая транзакция возможна лишь после доказанной изоляции старого ресурса и нового разрешения.
7. **Расширение.** Новая функциональность добавляется по одному маршруту: protobuf → Rust validator/planner → существующий native owner handler → typed readback/errors → негативные тесты → физическая приёмка. Ни одного второго owner chain. `NOOP` Docker не доказывает готовность DNS/TLS/auth/DIRECT/WARP.
8. **Доказательство.** Runner-copied protobuf, CI PASS и release artifact не являются authenticated owner receipt. Обязательны typed source/time/identity, bounded readback, exact installed digest и отдельная внешняя проверка для сетевого результата.

**Line2 как стандарт диагностики:** `machine_id → VM root owner → edge_net → line2-proxy → image/config → TLS/auth → DIRECT/WARP`. При ошибке config может измениться только Line2 config при доказанной принадлежности и готовом handler; неизвестная сеть, секрет, сосед или маршрут → адресный `BLOCKED`, а не ручная команда. Сбой дочернего ресурса виден в статусе всего host без расширения mutation scope.

## Модель, команды и граница реализации

Единственный `FleetDesiredState` задаёт `FleetHostTarget`: `STOPPED|RUNNING`, для Windows `PROXY_ONLY|MANAGED_TUN`. Отсутствие target → только OBSERVE, не запуск. Сейчас Windows намеренно `STOPPED/ProxyOnly`: SYSTEM SCM не запускать, TUN не включать. Cloudflare One независимо владеет собственным туннелем/DNS; Mesh другого проекта не трогать.

Только три внешние операции:

- `host status <id> [--deep]` — bounded read-only status/причина/предлагаемый шаг;
- `host apply <id>` — подписанный одноразовый переход к Git desired и ReleaseSet;
- `host recover <id>` — диагностика/безопасная новая операция после установления фактов, никогда replay неизвестной мутации.

**CLI:** прежние mutation-команды заблокированы до Rust dispatch и скрыты; доступны host, immutable ReleaseSet build и read-only проверки. Архивные workflows ещё требуют закрытия.

**Реализовано частично в PR #403:** Protobuf DAG для Compose-owned containers/networks/images/config; typed reason, Rust planner, VM root Agent, Worker authorization и одноразовый journal. Для одной конфигурации Line1/Line2 реализован подписанный `config/<project>/<service>` в существующем `host apply`: GitHub approval → Worker Ed25519 → точный DAG node/owner → native config-only handler. Чужой ресурс, image-pair, START/STOP и cross-scope UNKNOWN блокируются. Read-only планы неизменно `owner_attested=false`, `mutation_authorized=false`.

**VM INSTALL (PR #403, code-only):** signed root Agent после BEGIN создаёт owned stack, Docker bridge, WARP и Line1/Line2 через Bollard, pinned image pull без Compose. Нужны пустая VM и ACTIVE Worker v2 credentials; иначе BLOCKED. DNS/TLS/auth и physical receipt UNPROVEN. ACK loss → `UNKNOWN_NO_REPLAY`.

**Native receipt и legacy boundary (PR #403):** root `host-enroll` создаёт защищённый Ed25519 receipt key, выдаёт public key для регистрации в Git; без exact key match apply BLOCKED. VM CLI допускает только host apply, enrollment и чтение; старый RPC listener отключён. VM/Windows legacy mutating RPC всегда PermissionDenied; новые RPC проверяются CI по умолчанию. Windows SYSTEM signed apply и физическая приёмка НЕ готовы.

**Не принято:** физическая установка scoped signer/root Agent и ключей receipt, остальные resource kinds DNS/firewall/routes/TLS/CredentialRef, Windows SYSTEM apply и полное deep-acceptance. Обычный `resource_id=sing-box` остаётся host-wide; `host recover` read-only. Код PR и CI не означают эксплуатационный допуск. Старые команды не возвращать; `UNPROVEN` не считать PASS.

## Неопределённость и восстановление

**При малейшем сомнении** в локальном owner, праве владения, release hash, журнале, сетевом результате или состоянии доступа **обратиться за адресной read-only проверкой** к существующему локальному агенту/оператору. Запросить конкретное недостающее поле, запретить мутации, сохранить `UNPROVEN/BLOCKED`. Затем устранить причину отсутствия факта в том же Rust owner и `host status --deep`, чтобы следующий раз не требовалась ручная проверка. Не придумывать дополнительный агент, polling или SSH-путь.

При `UNKNOWN_NO_REPLAY` — нельзя воспроизводить старую A/B-операцию или `BEGIN`; нужна подтверждённая изоляция и *новая* типизированная транзакция с новым `operation_id`. **старый журнал оставить пассивным аудиторским артефактом**; не читать его как admission authority. Собственные устаревшие ресурсы выводить только после доказанного ownership и сохранения операторского доступа. Не менять DNS/default routes, чужой Mesh, Cloudflare One или Windows TUN без отдельного явного desired и физического acceptance.

## Один путь развертывания и критерий 10/10

Git desired → Rust typed graph/planner → immutable ReleaseSet → Worker signer/credentials → единственный SYSTEM/root owner → journal BEGIN → native apply → физическая проверка config/DNS/routes/TLS/auth/egress → receipt. Без reserve paths, произвольных команд, дополнительного install workflow или второго control plane.

**10/10 требует одновременно:** (1) три команды и ясный typed status; (2) полный parent/resource/dependency diagnosis; (3) signed scoped one-shot apply, crash/ACK `UNKNOWN_NO_REPLAY`; (4) fresh/reinstall/recover на новой и существующей Windows/VM; (5) Line1 4/4, Line2 6/6 DIRECT/WARP/TLS/auth; (6) независимость Mesh/Cloudflare One и безопасная Windows ProxyOnly/TUN приёмка; (7) exact tested SHA → CI → ReleaseSet без rebuild → native/remote физические доказательства. До этого `NOT_ACCEPTED_10_10`.
