# Единственный план завершения sing-box до 10/10

Исторический A/B recovery отменён. Источник истины — удалённый защищённый `main`. [Архитектура](ARCHITECTURE.md) — нормативная; [Issue #26](https://github.com/iamaman11/sing-box/issues/26) — архив/курсор. Новые сервисы, агенты, обходы и fallback запрещены.

## Непересматриваемое правило

Полностью запрещено **восстановление, проигрывание, продолжение, переиспользование и перенос старых операционных механизмов**: исторической A/B, прежних credential workflow, копий /windows /vm /production /credentials, резервных secret paths, машинных хардкодов и старых state-файлов как admission authority. Старые артефакты и журналы допустимы только как архив аудита; запрещено использовать их для новых mutations и восстановления «как было».

Если компонент sing-box не работает — **новый типизированный desired, новая ограниченная транзакция, новые секреты в Worker, пересборка или переустановка через единственного native owner**. Вывод старого компонента из эксплуатации допускается только после подтверждения точной принадлежности, зависимости, состояния доступа и границ влияния. Недопустимо снести соседний Mesh-проект, Windows Cloudflare One, общую VM или рабочий операторский доступ по догадке. Не включать TUN, не менять DNS/default routes и не запускать намеренно остановленный Windows SCM без нового явно заданного desired и acceptance.

## Один связный кодовый срез — порядок зависимостей, НЕ отдельные церемонии

**A. Закрыть старые входы.** PR #400 на реанимацию A/B закрыт без merge. Выключить достижимость старых mutation-команд в публичном ingress, оставить историю только audit-only. Удалить исторический credential recovery/admission из *активной* Rust-цепочки, не вводить новый исторический инспектор. Для неуверенного/UNKNOWN состояния — изоляция и явный отказ, никакой replay. Сохранить только те функции, которые используются в новом типизированном ресурсе, без старой семантики.

**B. Завершить единый Rust typed resource lifecycle.** Одна fleet/resource protobuf-модель: `machine_id`, native owner, типизированные network/DNS/TUN/containers/credentials ресурсы, desired digest, release digest, typed observations/errors, уникальный `operation_id`. Один Rust decision authority, Windows SYSTEM Controller и Linux root Agent как физические исполнители, GitHub только код/auth/dispatch/immutable release, Worker единственный владелец секретов. Никаких статических ID, второго реестра, второй службы или отдельных цепочек на VM/Windows. `host status/apply/recover` — три публичные операции.

**C. Один native install/reinstall/configure/replace.** Собирать из Git единственный immutable ReleaseSet с per-host/per-resource bundle; устанавливать и изменять контейнеры, sing-box и сеть нативными owner. Отказ `UNKNOWN_NO_REPLAY` не возобновляется: отделить старый ресурс, выделить **новую идентичность** и свежий typed intent, выполнить новую ограниченную операцию после доказанной изоляции. При удалении старого — явный owner/resource-scope, сохранение доступа и rollback по новому релизу; никакого копирования старых secrets/профилей/сценариев.

**D. Физическая приёмка.** Две Windows и две VM, включая новую машину: fresh install, update, reinstall, восстановление после crash/lost ACK/offline runner, config-only правка, добавление/удаление контейнера, централизованные новые Worker credentials, Line1 4/4 и Line2 6/6 с DIRECT/WARP/TLS/auth. Проверить независимость Cloudflare One и Mesh. Windows ProxyOnly и stopped SCM сохранять до отдельного явного решения о запуске; TUN принимать отдельно после DNS/route/reboot/browsing safety. Exact tested SHA → CI → ReleaseSet без rebuild → native poststate; `UNPROVEN` не равен PASS.

## Единый нативный readback (кандидат PR #403)

Без второй службы добавлен `FleetNativeObservation`: внутренние
`edge-agent local host-observe` (VM Docker + bundle) и
`edge-diagnostic host-observe <current.pb>` (Windows SCM + activation).
Ответ protobuf ограничен 4096 байтами и различает digest Windows
ReleaseSet activation record и VM application bundle. Windows дополнительно
сверяет точный путь SCM с проверенным release binary. Значение
`runtime_ready_proven=false` или `UNPROVEN` — не PASS.
Это **read-only наблюдение**, не подписанный native receipt,
не доказательство внешнего TLS/auth и не разрешение на apply.
Пока хосты не получили новый проверенный бинарник, старый diagnostic
остаётся только read-only; его нельзя объявлять равным новой версии.
Readiness выражена типизированными `runtime_ready` и
`runtime_ready_proven`: отсутствие сетевого пробинга не является ошибкой
наблюдения. Для STOPPED/STOPPED допускается план NOOP без сетевой проверки;
для RUNNING без доказанной готовности — BLOCKED. Сбой SCM, ownership либо
проверки бинарников продолжает блокировать. Нативный readback теперь
передаётся артефактом в **тот же** exact Rust Orchestrator в существующем
reusable workflow, проверяется по Git inventory/immutable ReleaseSet и
возвращает отдельный verdict `UNAVAILABLE`/`REJECTED`/local-only.
Копия с runner не аутентифицирована как root/SYSTEM receipt; никакого
нового агента или права на мутацию. Физическая установка нового SHA
по-прежнему обязательна.

## Rust reconcile без второй mutation authority

В PR #403 единый `FleetHostTransitionPlan` вычисляется из Git `FleetHostTarget`,
bounded нативного readback и точного ReleaseSet/VM bundle digest: `NOOP`,
`START`, `STOP`, `REPLACE_RELEASE` либо `BLOCKED`. Это **предложение**,
не permission: `owner_attested=false`, `mutation_authorized=false`;
Runner не становится root/SYSTEM. `host readback` — скрытый внутренний
Rust-приёмник наблюдения; публичные команды остаются только
`host status/apply/recover`. Новый read-only workflow сохраняет protobuf
только при наличии точной команды в установленном native binary, иначе
возвращает `UNAVAILABLE` и не повышает права.

Завершение: Worker подписывает конкретный intent, existing native owner
проверяет машинную идентичность и root/SYSTEM state, журналирует одноразовую
операцию, исполняет выбранное действие, возвращает **аутентифицированный**
readback receipt. CI и типизированное предложение не дают права на мутацию.
Windows остаётся STOPPED/PROXY_ONLY, отдельная TUN приёмка обязательна.

## Один централизованный Host signer (кандидат PR #403)

Единственный подписант HostIntent добавлен в **существующий VM credential
Worker** (`POST /v1/host/authorize`), Windows Worker подписи не выпускает.
Выпуск отключён при отсутствии Worker-owned Ed25519 PKCS8/ключа, Cloudflare
Access issuer/audience и GitHub operator ID. Worker криптографически
проверяет Access JWT (RS256), читает только канонический GitHub Issue #1,
сверяет ID автора, неизменённую и свежую команду `/host apply|recover
machine-id`, дату запроса и выдаёт detached protobuf разрешение на 120 с.
**Нет ручного утверждения SHA в Cloudflare при каждой операции** и нет
секретов подписи в GitHub/Windows/VM. Runtime verifier сверяет весь
подписанный байтовый HostIntent и его release/desired digests.

Оба прежних A/B credential slots сохранены. Только VM Worker может
дополнительно иметь ровно пять защищённых Host-параметров — остальные
bindings отклоняются. Existing `edge-secrets` использует тот же
Cloudflare Access identity и Worker TLS transport, новый POST никогда не
повторяется после неизвестного результата. Positive/negative WebCrypto
контракт проверяется офлайн в CI против точного Rust payload.

**Статус этой функции:** написан исходный код и тесты; Worker-контракт
не развернут с signer secrets. Оставшиеся обязательные условия реальных
mutations: trusted pinned Worker public key на native owner; физически
доказанная SYSTEM/root identity, root/ACL journal admission, подключение
существующих Windows Controller и VM Agent к применению выбранного
ресурса, аутентифицированный native receipt и physical poststate.
Подпись Worker не даёт runner прямой sudo/Docker/SCM authority.

## Текущие ограничения (не считать закрытыми)

**Граница привилегий VM:** в ранее установленном sudoers для `github-runner` присутствовал прямой допуск к `bundle-converge`, rollback, bootstrap и credential mutation. PR #403 закрывает этот доступ в *исходном установщике* и добавляет read-only наблюдение `host_runner_direct_mutation_authority` на фактически установленном runner. Это не доказывает, что старый sudoers уже исправлен на VM. Любые VM writes через этот старый допуск запрещены; коррекция установленной политики требует штатного доверенного native-owner handoff и физического readback, без replay исторической A/B. В PR #403 native подписанное admission и журнал находятся в разработке, Worker signing и VM Agent связаны; remote receipt и Windows execution — UNPROVEN.

На `main` после PR #399 есть независимая read-only диагностика Windows + acceptance VM, но `production-1` не подтверждён; native FAST установлен не везде. Универсальный fresh per-host bundle, deploy/replace/rollback, новый typed secret-provision и закрытие legacy-ingress **ещё не выполнены**. Имеющийся старый A/B BEGIN — архив истории, **не задача восстановления** и не вход новой операции.

## Фактический прогресс PR #403 (интеграционный срез)

Native VM readback различает `VERIFIED_ABSENT` и `UNPROVEN`; Rust
planner выбирает `INSTALL` только для RUNNING target и доказанно пустой VM.
Worker signer проверяет Access JWT, exact GitHub comment, каноническое
кодирование intent и опубликованный ReleaseSet. Один Rust transaction
entrypoint связывает owner readback → signed admission → durable resource
lock → однократную mutation callback → физический poststate. Тесты
покрывают долговечный однократный NOOP, успешный переход и UNKNOWN_NO_REPLAY.

**Сейчас:** VM START/STOP/INSTALL/scoped REPLACE через signed root Agent (код).
`ResourceReport/v2` выявляет credential dependency: без ACTIVE запуск
BLOCKED, STOP разрешён. Snapshot generation/digest привязан к BEGIN.
**First-use VM (код):** Git-pinned Worker bundle → подписанный journal BEGIN → ACTIVE cursor и native INSTALL.
**Остаётся:** Worker issuance, Windows SYSTEM handler, DNS/firewall/routes, reinstall/recover, физический receipt/TLS/auth/WARP.
CI ≠ runtime.

## Обязательный протокол сомнения (без гаданий и кругов)

1. Получить доступный native read-only typed status и проверить его актуальность, источник и область наблюдения. Не переносить факты VM-localhost на публичный endpoint, старый SHA на установленный owner или завершение GitHub job на runtime health.
2. **При любой, даже минимальной неопределённости обязательно запросить у существующего локального агента один конкретный недостающий read-only факт**, в безопасной ограниченной команде, с указанием ожидаемого поля и запрещённых мутаций. Не повторять бессодержательный probe и не догадываться.
3. Пока факт отсутствует, выдавать `UNPROVEN`/`BLOCKED`; никакого удаления, переключения secrets, запуска Windows/TUN или изменения сети. После ответа сверить все противоречащие источники.
4. Каждый такой ручной пробел считать дефектом встроенной диагностики: в этом же новом Rust owner/typed protobuf contract добавить автоматический сбор, точную причину отказа (`error_class`), версию установленного ReleaseSet, physical proof и `next_action`. Конечная приёмка: **ChatGPT сам быстро видит все необходимые данные**, локальный агент больше не нужен для штатного цикла.

PASS CI не отменяет обязательный запрос локальной помощи при сомнении; replay запрещён.

## Правило выполнения

**Один интегрированный функциональный PR вместо последовательности исторических recovery-fix PR.** Полный точный CI, merge tested SHA, неизменяемый release, независимые физические проверки. При отказе — одна типизированная причина и минимальное read-only наблюдение локального owner; затем исправление *нового* контрактного слоя, а не возврат к старой операции. Отдельные обходные transports, sleep/polling loops, резервные credentials, ручные копии конфигов и старые профили запрещены. `DONE` — только при полной физической приёмке; иначе назвать точный остающийся разрыв.
