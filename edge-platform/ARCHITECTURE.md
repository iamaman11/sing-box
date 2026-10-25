# sing-box — нормативная архитектура

Единый архитектурный контракт. [План](FINALIZATION-PLAN.md); [Issue #26](https://github.com/iamaman11/sing-box/issues/26) — только архив/курсор. Канон — защищённый GitHub `main`.

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

## Инвариант полномочий Root Agent (решение владельца, issue #484)

**Полный нативный системный исполнитель — только установленный VM `edge-agent` под root.** Его *архитектурные возможности* не должны зависеть от закрытого списка Linux-команд: будущие разрешённые задачи могут затрагивать процессы и службы, файлы, пакеты, образы/контейнеры/тома/Docker networks, IPv4/IPv6 и все routing tables и `ip rule`, DNS, nftables/firewall, sing-box, WARP и ранее не предусмотренные системные инструменты. **Отсутствие заранее написанного Rust handler для конкретного диагностического вопроса не должно требовать новый релиз.**

При этом **полные права root владельца не являются полномочием произвольного GitHub job или непроверенного комментария**. GitHub self-hosted runner — только низкопривилегированный transport (никакого общего `sudo`, Docker socket, remote SSH или второго owner); корневой владелец проверяет точную авторизацию с привязкой к operator, `machine_id`, operation ID, digest payload, сроку действия и принятому ReleaseSet, а затем применяет native owner lock/журнал/receipt. Запросы, которые могут изменять состояние, отделены от безопасной диагностики; неизвестный результат не повторяется. Публичные GitHub logs, issues и artifacts не могут получать произвольные raw секреты и приватный вывод. Постоянное состояние — только Git desired.

**Административный интерфейс:** `/host admin <machine_id> <base64url-json>`, где JSON имеет типизированные поля в порядке `{"argv":["/usr/bin/id"],"cwd":"/","environment":[],"stdin_base64":"","timeout_seconds":60,"publish_output":true}`. При `publish_output=false` публично возвращаются только хеши и размер. Запросы и исходный JSON присутствуют в открытом Issue #1, поэтому вводить туда секреты запрещено: использовать существующий Worker/Vault. При запуске Root Agent сохраняет до 16 МиБ каждого потока в приватных файлах журнала с `0600`; подписанный результат указывает точные пути и степень полноты. Последующие части вывода читаются **новым точно авторизованным `/host admin`** с `dd` по подписанному пути и offset, а не через второй канал; для объёма больше 16 МиБ исполнитель может явно направить вывод в выбранный системный файл. Никаких ограничений на команды/interpreter/root-полномочия эти границы диагностического вывода не создают.

**Статус исполнения:** PR #489 реализует универсальный административный вход Root Agent без функционального белого списка программ: `/host admin` → точное разрешение GitHub actor/Worker → root Agent → durable no-replay → подписанный результат. **До прохождения CI, merge, Worker activation и физической приёмки на новой VM это CODE_CANDIDATE, не FULL_CONTROL.** Общий root-shell или Docker socket самому GitHub runner не выдаётся. План/критерии — [issue #484](https://github.com/iamaman11/sing-box/issues/484); предметный resource CRUD — [issue #480](https://github.com/iamaman11/sing-box/issues/480).

## Неизменяемый контракт иерархии ресурсов

Одна сквозная цепь: `MachineId → ResourceKind/ResourceId → Parent/Dependencies → Owner → ImmutableDesired → NativeObserved → TypedReason → PlannedStep → SignedHostIntent → NativeEffect → PhysicalReadback → Receipt`.

1. **Ресурс.** `ResourceKind`, `ResourceId` и `MachineId` определяют единственную идентичность и единственного владельца. Отсутствующий/неподтверждённый owner, чужой Docker Compose project, Mesh или Windows Cloudflare One дают `BLOCKED`, никогда автоматическое присвоение.
2. **Иерархия.** Каждый узел принадлежит ровно одному зарегистрированному host; зависимости указывают на допустимые идентичности. Циклы, дубли, неявные Docker networks, подмена родителя и изменение соседнего ресурса не допускаются. Ошибка ребёнка поднимается к родителю в диагностике, но **не** разрешает менять родителя.
3. **Состояние.** Desired исходит только из Git и immutable ReleaseSet; Compose, sing-box JSON, systemd/SCM, DNS, firewall — выход рендера или фактический readback, не второй desired. Образ — pinned digest. Secret value остаётся только у Worker/целевого native owner, наружу — CredentialRef.
4. **Диагностика.** `host status <machine-id> --deep` обязан указывать путь ресурса, owner, dependencies, exact desired/observed digest, timestamp, scope источника, typed reason, proposed action, `UNPROVEN/BLOCKED`. Нельзя заменять ошибки TLS, DNS, маршрута, образа или конфигурации общим `container unhealthy`. Текст — отображение enum, не самостоятельное правило.
5. **Операция.** `host apply` вызывает Rust planner и специализированные native handlers для постоянного Git desired; `host recover` пока только read-only preflight. Для любой заранее неизвестной административной задачи существует **отдельный авторизованный `/host admin`**, исполняемый самим Root Agent под root **без allowlist команд, интерпретаторов или классов системных эффектов**. Не реализованный специализированный обработчик означает `UNSUPPORTED` лишь для автоматического desired reconcile, **не запрет административного действия владельца**. Runner остаётся транспортом без собственного shell/root/Docker socket. Прежде чем менять Line2 через desired, доказать scope и неизменность Line1, WARP и network.
6. **Неповторяемость.** Перед BEGIN: Git digest, ownership, dependency graph, exact signed intent, Worker auth и native lock. После BEGIN неизвестный ACK, crash, недоказанный poststate → `UNKNOWN_NO_REPLAY`; никакой повторной попытки или скрытого rollback. Новая транзакция возможна лишь после доказанной изоляции старого ресурса и нового разрешения.
7. **Расширение.** Новая функциональность добавляется по одному маршруту: protobuf → Rust validator/planner → существующий native owner handler → typed readback/errors → негативные тесты → физическая приёмка. Ни одного второго owner chain. `NOOP` Docker не доказывает готовность DNS/TLS/auth/DIRECT/WARP.
8. **Доказательство.** Runner-copied protobuf, CI PASS и release artifact не являются authenticated owner receipt. Обязательны typed source/time/identity, bounded readback, exact installed digest и отдельная внешняя проверка для сетевого результата.

**Line2 как стандарт диагностики:** `machine_id → VM root owner → edge_net → line2-proxy → image/config → TLS/auth → DIRECT/WARP`. При ошибке config может измениться только Line2 config при доказанной принадлежности и готовом handler; неизвестная сеть, секрет, сосед или маршрут → адресный `BLOCKED`, а не ручная команда. Сбой дочернего ресурса виден в статусе всего host без расширения mutation scope.

## Модель, команды и граница реализации

Единственный `FleetDesiredState` задаёт `FleetHostTarget`: `STOPPED|RUNNING`, для Windows `PROXY_ONLY|MANAGED_TUN`. Отсутствие target → только OBSERVE, не запуск. Сейчас Windows намеренно `STOPPED/ProxyOnly`: SYSTEM SCM не запускать, TUN не включать. Cloudflare One независимо владеет собственным туннелем/DNS; Mesh другого проекта не трогать.

Только четыре внешние операции (три lifecycle и одна read-only диагностическая):

- `host diagnose <id> <approved read-only argv>` — VM only: Rust/Protobuf validated fixed unprivileged OS tools over existing GitHub runner; does not authorize native mutations or attest signed physical receipt;
- `host status <id> [--deep]` — bounded read-only status/причина/предлагаемый шаг;
- `host apply <id>` — подписанный одноразовый переход к Git desired и ReleaseSet;
- `host recover <id>` — VM: защищённый root `host-refresh` **только бинарник/trust текущего canonical ReleaseSet** + read-only post-refresh диагностика под прежним owner lock; не меняет resource journal, контейнеры или сеть и не снимает pending. Windows: пока read-only. Любой resource rollback/repair/replay — отдельный signed handler и приёмка, никогда неизвестный replay.

**Диагностический транспорт (#484):** один `/host diagnose` — отдельный read-only инструмент того же GitHub/runner/native owner, не MCP, SSH или root shell. Новый установленный бинарник и точное узкое sudoers разрешение `local host-probe` должны быть физически доказаны; source CI не означает deployed. Подписание mutating `HostIntent` этим маршрутом невозможно.

**CLI:** исторические provider/application/credential mutation verbs удалены из публичного и скрытого Clap-парсера `edge-orchestrator`, а не просто заблокированы в dispatch. Старые VM local mutation verbs и listener удалены из `edge-agent` CLI. Только `host status|apply|recover` являются операторским API; внутренние read-only/release-build verbs остаются без права ресурсной мутации. Защищённый Git `main` — единственный desired. Новый root-owned `host-refresh` без аргументов выбирает только защищённый текущий main и обновляет trust/binary атомарно; `host-apply` остаётся единственным исполнителем ресурсов.

**Реализовано в защищённом Git, эксплуатация проверяется отдельно:** Protobuf DAG для Compose-owned containers/networks/images/config; typed reason, Rust planner, VM root Agent, Worker authorization и одноразовый journal. Для одной конфигурации Line1/Line2 реализован подписанный `config/<project>/<service>` в существующем `host apply`: GitHub approval → Worker Ed25519 → точный DAG node/owner → native config-only handler. Чужой ресурс, image-pair, START/STOP и cross-scope UNKNOWN блокируются. Read-only планы неизменно `owner_attested=false`, `mutation_authorized=false`.

**VM INSTALL:** `ResourceHierarchy` содержит Worker-owned CredentialRef и ребро к Line1/Line2; `ResourceReport/v2` проверяет ACTIVE/CANDIDATE/ABSENT/UNPROVEN. Без ACTIVE и без Git-pinned first-use Worker bundle — BLOCKED, STOP допустим. First-use сверяется до BEGIN; ACTIVE создаёт root после BEGIN. Drift → UNKNOWN_NO_REPLAY. Bollard без Compose. Worker issuance/physical receipt — UNPROVEN.

**Native receipt и legacy boundary:** root `host-enroll` создаёт защищённый Ed25519 receipt key, выдаёт public key для регистрации в Git; без exact key match apply BLOCKED. VM CLI допускает только host apply, enrollment и чтение; старый RPC listener отключён. VM/Windows legacy mutating RPC всегда PermissionDenied; новые RPC проверяются CI по умолчанию. Windows SYSTEM signed apply и физическая приёмка НЕ готовы.

**Не принято:** физическая приёмка новой VM после hard cut, реальная Worker Access авторизация, ресурсные handlers для host DNS/firewall/routes, Windows SYSTEM apply/TUN/reboot и полное deep-acceptance. Код и CI ≠ runtime. Обычный `resource_id=sing-box` остаётся host-wide; `host recover` read-only. Код PR и CI не означают эксплуатационный допуск. Старые команды не возвращать; `UNPROVEN` не считать PASS.

## Неопределённость и восстановление

**При малейшем сомнении** в локальном owner, праве владения, release hash, журнале, сетевом результате или состоянии доступа **обратиться за адресной read-only проверкой** к существующему локальному агенту/оператору. Запросить конкретное недостающее поле, запретить мутации, сохранить `UNPROVEN/BLOCKED`. Затем устранить причину отсутствия факта в том же Rust owner и `host status --deep`, чтобы следующий раз не требовалась ручная проверка. Не придумывать дополнительный агент, polling или SSH-путь.

При `UNKNOWN_NO_REPLAY` — нельзя воспроизводить старую A/B-операцию или `BEGIN`; нужна подтверждённая изоляция и *новая* типизированная транзакция с новым `operation_id`. **старый журнал оставить пассивным аудиторским артефактом**; не читать его как admission authority. Собственные устаревшие ресурсы выводить только после доказанного ownership и сохранения операторского доступа. Не менять DNS/default routes, чужой Mesh, Cloudflare One или Windows TUN без отдельного явного desired и физического acceptance.

## Один путь развертывания и критерий 10/10

Git desired → Rust typed graph/planner → immutable ReleaseSet → Worker signer/credentials → единственный SYSTEM/root owner → journal BEGIN → native apply → физическая проверка config/DNS/routes/TLS/auth/egress → receipt. Без reserve paths, произвольных команд, дополнительного install workflow или второго control plane.

**10/10 требует одновременно:** (1) три команды и ясный typed status; (2) полный parent/resource/dependency diagnosis; (3) signed scoped one-shot apply, crash/ACK `UNKNOWN_NO_REPLAY`; (4) fresh/reinstall/recover на новой и существующей Windows/VM; (5) Line1 4/4, Line2 6/6 DIRECT/WARP/TLS/auth; (6) независимость Mesh/Cloudflare One и безопасная Windows ProxyOnly/TUN приёмка; (7) exact tested SHA → CI → ReleaseSet без rebuild → native/remote физические доказательства. До этого `NOT_ACCEPTED_10_10`.

## Исполняемые модули и граница GitHub Actions

- `edge-orchestrator/src/main.rs` — только канонический CLI ingress, release validation и разрешённые read-only/build verbs; `host_dispatch.rs` — единственный внутренний маршрутизатор typed HostCommand. Никаких прямых `vultr-lifecycle`, `vultr-vpc`, `application-acceptance` команд.
- `edge-agent/src/local_dispatch.rs` — read-only диагностика, `host-enroll`, `host-refresh` и подписанный `host-apply`; `host_native.rs` — единственный root/journal/receipt authority. VM bootstrap/credential legacy mutation commands не принимаются CLI.
- `edge-console/src/command_dispatch.rs` и `edge-controller/src/controller_rpc.rs` выделяют Windows командный транспорт и RPC; SYSTEM native signed apply и Windows TUN ещё не приняты и не должны активироваться этой очисткой.
- GitHub Actions получает `operation` из закрытого Rust `HostWorkflowOperation` и выбирает workflow через `needs.host.outputs.operation`. Но ряд first-use/Worker/receipt preflight всё ещё проверяет текстовые `host_*=...` через `grep/sed`; это **остающийся типизационный долг**, а не второй mutation ingress. План требует заменить такие admission-проверки закрытым Rust verifier + Protobuf, оставив GitHub только формальные outputs/exit codes и обязательный внешний JSON.
- Устаревшие исходники старых orchestrator/provider helper-модулей могут оставаться компилируемыми зависимостями first-use/render/test. Это НЕ второй доступный mutation ingress и не отдельный владелец состояния. Дальнейшее их физическое удаление требует доказанного отсутствия зависимостей в единственном first-use.

Внутренние structured desired, intent, result и receipt используют Protobuf. JSON допустим только на границе обязательного внешнего API (GitHub REST, Actions `strategy.matrix`); для выбора одной `/host` операции JSON не применяется.

Подробности уже удалённых RPC/Mesh/VM helper-функций сохранены в истории PR [#448](https://github.com/iamaman11/sing-box/pull/448)–[#451](https://github.com/iamaman11/sing-box/pull/451); здесь они не образуют новый план. Исполняемые пути и недостающие gates — только в [единственном плане](FINALIZATION-PLAN.md).
