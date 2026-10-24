# Windows — технические границы реализации

**Справочник реализации, не план, не разрешение на включение TUN или изменение Windows.** Единственные нормативные источники: [архитектура](../../edge-platform/ARCHITECTURE.md), [план завершения](../../edge-platform/FINALIZATION-PLAN.md), [три команды](../../edge-platform/COMMAND-INVENTORY.md). Подтверждённые текущие операции и physical evidence — [Issue #26](https://github.com/iamaman11/sing-box/issues/26). Исторические исследования Stage 4B/DNS и прежние версии этого файла доступны в Git history, но не задают новый execution cursor.

## Владелец и пути

```text
protected Git main + immutable ReleaseSet
  → GitHub runner (transport only; NetworkService)
  → bounded SYSTEM activation boundary
  → SCM EdgePlatformController (single runtime owner)
  → edge-controller.exe
  → pinned sing-box.exe / rendered runtime config
```

- **Состояние приёмки:** Windows `sing-box-windows-lab` — `STOPPED / PROXY_ONLY`. Реальный signed SYSTEM HostApply, native receipt, TUN, reboot/rollback и полная эксплуатационная приёмка **НЕ ДОКАЗАНЫ**. Нельзя включать SCM/TUN/DNS/default routes для ускорения VM acceptance.
- Область приложения `C:\sing-box` с `current.pb`, `previous.pb`, `releases/<sha>`, `bin`, `state/secrets`, `runtime`, `logs`, `exchange`; runner отдельно `C:\sing-box-runner`.
- Immutable release и activation — SYSTEM/Admin controlled. Runner не имеет произвольного elevated execution, Docker socket, доступа к plaintext `state/secrets` или прав менять чужой TUN; для привилегированного действия требуется allowlisted typed SYSTEM boundary.
- Контроллер — единственный owner процесса sing-box; `edge-console` — клиент, `edge-diagnostic` — независимое чтение. Никаких дочерних fallback-controller, parallel SCM owner, общего PowerShell/SSH mutating endpoint.
- `current.pb` и `previous.pb` описывают точные принятые releases. Работающая активация не зависит от `gh.exe`, Cargo, изменяемой Git checkout, старых JSON pointers или старого процесса. Legacy config/secrets/startup owner не импортировать; чужой sing-box наблюдать, но не останавливать.

## Рендер, диагностика и переход режима

- Git `infra/production/production.textproto` — целевой источник mode `PROXY_ONLY|MANAGED_TUN`. Mode должен входить в Windows candidate input digest; generated `sing-box.json` — потребительский результат, не альтернативное управление состоянием.
- Один Windows SYSTEM owner проверяет exact binary + release и применяет типизированный runtime projection: render → `sing-box check` → candidate verification → bounded activation → physical readback. Ошибка/unknown ACK — `BLOCKED/UNKNOWN_NO_REPLAY`, не ручной restart. Подписанная physical activation/recovery ещё не принята.
- Bounded read-only диагностика должна идентифицировать SCM service/path/identity/state, process+config owner, release, TUN interface/index/address, DNS per interface, IPv4/IPv6 best routes, endpoint exclusions, WFP ownership когда нужно, functional DIRECT/WARP и безопасные reason/status. Использовать Windows native APIs, не свободный парсинг PowerShell/WMI.
- Managed TUN требует доказать строгую независимость Cloudflare One/Mesh, DHCP/Ethernet и других VPN: отсутствие public plaintext DNS leakage на UDP/TCP 53 и через IPv6, working managed encrypted DNS/DoT, верные endpoint exclusions, сохранность GitHub control transport, safe reboot/start-failure shutdown и offline restore. Успешный offline `sing-box check`, наличие adapter или успешный DNS query **не доказывают** эти свойства.
- Старые Stage 4B.2-C `hijack/native`, WFP/DNS canary и supervisor-последовательности относятся к **непринятому историческому предложению**; не выполнять их как инструкцию. Единственный запуск нового режима — по защищённому Git desired, новому явно разрешённому `/host apply`, с независимым before/after + negative physical witness, signed native receipt и проверяемым восстановлением. Другие сетевые владельцы остаются неизменными.

**Итог:** `PROXY_ONLY` не равен принятому SYSTEM lifecycle; `MANAGED_TUN` не активировать до всех физических gates в [единственном плане](../../edge-platform/FINALIZATION-PLAN.md).
