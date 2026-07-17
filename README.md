# Windows Scheduled Task Persistence (T1053.005)

[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-T1053.005-red)](https://attack.mitre.org/techniques/T1053/005/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-T1053.005-red)](https://www.cisa.gov/eviction-strategies-tool/info-attack/T1053.005)


Кейс по закреплению в Windows через Scheduled Task (schtasks) с обходом PowerShell Execution Policy.  
Red Team — создание механизма persistence. Blue Team — обнаружение, анализ артефактов и ликвидация.

## Быстрый старт

Создание маркерного скрипта:

```powershell
'New-Item -ItemType File -Path "C:\Windows\Tasks\svchost-update.out" -Force -ErrorAction SilentlyContinue' |
  Out-File -FilePath "C:\Windows\Tasks\svchost-update.ps1" -Encoding UTF8
```

Создание задачи планировщика:

```powershell
schtasks /Create /TN "SystemUpdate" /SC ONCE /ST 23:59 /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Windows\Tasks\svchost-update.ps1" /F
```

Проверка persistence:

```powershell
schtasks /Run /TN "SystemUpdate"
Start-Sleep -Seconds 10
Test-Path "C:\Windows\Tasks\svchost-update.out"
```

## Структура

- `red-team/` — скрипты создания persistence (скрипт, задача, проверка).
- `blue-team/` — детект через логи, PowerShell и Sigma‑правило.
- `ir/` — скрипт удаления задачи и артефактов.
- `docs/report.md` — полный технический отчёт (T1053.005).
- `screenshots/` — GUI Task Scheduler и PowerShell‑цепочка.

## Технический отчёт

Подробный разбор техники, артефактов и методов детекта:  
[docs/report.md](docs/report.md)

## Автор

- Портфолио: https://ivan-qa-rgb.github.io/cybersecurity-resume/
- Другие кейсы:
  - https://github.com/Ivan-qa-rgb/powershell-shellcode-case
  - https://github.com/Ivan-qa-rgb/track-forensics-incident
  - https://github.com/Ivan-qa-rgb/incident-reports-ad-wmi-lateral-movement
