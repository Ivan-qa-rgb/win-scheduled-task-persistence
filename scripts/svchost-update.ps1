# Windows Scheduled Task Persistence (schtasks)

Практический кейс по закреплению в Windows через Scheduled Task (`schtasks`) с обходом PowerShell Execution Policy. Репозиторий оформлен как мини‑пример для DFIR / Blue Team / Red Team портфолио.

---

## Сценарий

Атакующий:

- размещает PowerShell‑скрипт в маскирующемся пути `C:\Windows\Tasks\svchost-update.ps1`;
- создаёт задачу `SystemUpdate`, которая запускает `powershell.exe` с обходом Execution Policy и выполняет скрипт;
- скрипт создаёт маркерный файл `C:\Windows\Tasks\svchost-update.out` как артефакт успешного выполнения.

Defender / Blue Team:

- находит и анализирует задачу через `schtasks`;
- определяет подозрительные признаки (имя, команда запуска, путь к скрипту, обход Execution Policy);
- корректно удаляет задачу и артефакты.

---

## Подготовка скрипта (Red Team)

Скрипт создаёт файл‑артефакт в каталоге `C:\Windows\Tasks`.

```powershell
'New-Item -ItemType File -Path "C:\Windows\Tasks\svchost-update.out" -Force -ErrorAction SilentlyContinue' |
  Out-File -FilePath "C:\Windows\Tasks\svchost-update.ps1" -Encoding UTF8
```

Проверка, что скрипт на месте и содержит нужную команду:

```powershell
Test-Path "C:\Windows\Tasks\svchost-update.ps1"
Get-Content "C:\Windows\Tasks\svchost-update.ps1"
```

---

## Обход Execution Policy и проверка скрипта

Запуск скрипта вручную с обходом политики:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Windows\Tasks\svchost-update.ps1"
```

Проверка артефакта:

```powershell
Test-Path "C:\Windows\Tasks\svchost-update.out"
```

Ожидаемый результат: `True`.

---

## Создание задачи (Red Team)

Удаляем старую задачу, если была:

```powershell
schtasks /Delete /TN "SystemUpdate" /F 2>nul
```

Создаём новую задачу с обходом Execution Policy:

```powershell
schtasks /Create ^
 /TN "SystemUpdate" ^
 /SC ONCE ^
 /ST 23:59 ^
 /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Windows\Tasks\svchost-update.ps1" ^
 /F
```

(В PowerShell можно одной строкой, без `^`.)

Проверяем параметры задачи:

```powershell
schtasks /Query /TN "SystemUpdate" /V /FO LIST
```

Ключевые моменты:

- `TaskName` = `\SystemUpdate`;
- `Task To Run` = `powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Windows\Tasks\svchost-update.ps1`.

---

## Проверка persistence через задачу

Удаляем артефакт, чтобы видеть именно результат задачи:

```powershell
Remove-Item "C:\Windows\Tasks\svchost-update.out" -Force -ErrorAction SilentlyContinue
Test-Path "C:\Windows\Tasks\svchost-update.out"   # ожидаем False
```

Запускаем задачу и ждём:

```powershell
schtasks /Run /TN "SystemUpdate"
Start-Sleep -Seconds 10
Test-Path "C:\Windows\Tasks\svchost-update.out"   # ожидаем True
```

Если файл появился, задача успешно реализует persistence‑цепочку:

> Scheduled Task → PowerShell (Bypass) → скрипт → артефакт.

---

## Blue Team: анализ и удаление

Поиск и анализ задачи:

```powershell
schtasks /Query /TN "SystemUpdate" /V /FO LIST
```

Подозрительные признаки:

- имя задачи, маскирующееся под системное (`SystemUpdate`);
- запуск `powershell.exe` вместо штатного бинарника;
- использование `-ExecutionPolicy Bypass`;
- нестандартный путь к скрипту: `C:\Windows\Tasks\svchost-update.ps1`.

Удаление задачи и артефактов:

```powershell
schtasks /Delete /TN "SystemUpdate" /F

Remove-Item "C:\Windows\Tasks\svchost-update.ps1" -Force -ErrorAction SilentlyContinue
Remove-Item "C:\Windows\Tasks\svchost-update.out" -Force -ErrorAction SilentlyContinue
```

Проверка чистоты:

```powershell
schtasks /Query /TN "SystemUpdate"
Test-Path "C:\Windows\Tasks\svchost-update.ps1"
Test-Path "C:\Windows\Tasks\svchost-update.out"
```

---

## Скриншоты

Рекомендуемая структура:

- `screenshots/win_scheduled_task_persistence_systemupdate.png`

Скриншот может показывать:

- вывод `schtasks /Query /TN "SystemUpdate" /V /FO LIST`;
- строку `Task To Run` с `-ExecutionPolicy Bypass` и путём к скрипту;
- наличие файла `C:\Windows\Tasks\svchost-update.out` в проводнике или через PowerShell.

---

## Использование в портфолио

Этот кейс можно использовать как:

- демонстрацию понимания Windows persistence (Scheduled Tasks, Execution Policy);
- пример Red Team подхода (скрипт + задача);
- пример Blue Team/DFIR подхода (поиск задачи, разбор команды запуска, удаление артефактов).

См. также другие мои кейсы по DFIR / Blue Team / Red Team в репозиториях:

- `powershell-shellcode-case`
- `track-forensics-incident`
- `incident-reports-ad-wmi-lateral-movement`
- портфолио‑сайт: `https://ivan-qa-rgb.github.io/cybersecurity-resume/`
