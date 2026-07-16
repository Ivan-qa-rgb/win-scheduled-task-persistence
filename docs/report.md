# Технический отчёт: Scheduled Task Persistence (T1053.005)

## 1. Общие сведения

| Параметр                  | Значение                                         |
|---------------------------|--------------------------------------------------|
| Техника MITRE ATT&CK      | T1053.005 — Scheduled Task/Job: Scheduled Task   |
| Тактика                   | Persistence (TA0003)                             |
| Платформа                 | Windows 10/11                                    |
| Требуемые привилегии      | Локальный администратор                          |
| Вектор                    | Локальный                                        |
| Цель кейса                | Демонстрация механизма закрепления и методов детекта |

## 2. Описание техники

Windows Task Scheduler позволяет планировать выполнение программ по расписанию и по событиям, и часто используется злоумышленниками для persistence и повторного запуска payload после перезагрузки.  
В кейсе используется `schtasks.exe` и запуск PowerShell‑скрипта с `-ExecutionPolicy Bypass`, что позволяет обходить политику выполнения без изменения глобальных настроек.

## 3. Подготовка среды

### 3.1. Система

- ОС: Windows 10/11  
- Учетная запись: локальный администратор  
- PowerShell: 5.1+  

### 3.2. Маркерный скрипт

Скрипт создаёт файл‑индикатор в `C:\Windows\Tasks\` (системная директория, низкая визуальная заметность):

```powershell
'New-Item -ItemType File -Path "C:\Windows\Tasks\svchost-update.out" -Force -ErrorAction SilentlyContinue' |
  Out-File -FilePath "C:\Windows\Tasks\svchost-update.ps1" -Encoding UTF8
```

Назначение `svchost-update.out`: подтверждение фактического выполнения скрипта при срабатывании задачи.

## 4. Реализация атаки (Red Team)

### 4.1. Ручная проверка скрипта

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Windows\Tasks\svchost-update.ps1"
Test-Path "C:\Windows\Tasks\svchost-update.out"  # True
```

Ключевые параметры:

- `-NoProfile` — не загружать профиль пользователя (меньше шума).  
- `-ExecutionPolicy Bypass` — игнорировать текущую политику.  
- `-File` — путь к скрипту.

### 4.2. Создание задачи через GUI

**Общие:**

- Имя: `SystemUpdate`  
- Автор: `DESKTOP-NTKI91N\ivbir`  
- Выполнять с наивысшими правами: да  

**Триггеры:**

- Начать задачу: по расписанию  
- Однократно, время: `16.07.2026 12:30:08`  

**Действия:**

- Программа: `powershell.exe`  
- Аргументы: `-NoProfile -ExecutionPolicy Bypass -File C:\Windows\Tasks\svchost-update.ps1`  

### 4.3. Создание задачи через CLI

```powershell
schtasks /Create /TN "SystemUpdate" /SC ONCE /ST 23:59 /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Windows\Tasks\svchost-update.ps1" /F
```

Параметры:

- `/TN` — имя задачи  
- `/SC ONCE` — однократный запуск  
- `/ST 23:59` — время старта  
- `/TR` — команда для выполнения  
- `/F` — перезаписать существующую  

### 4.4. Проверка persistence

```powershell
schtasks /Run /TN "SystemUpdate"
Start-Sleep -Seconds 10
Test-Path "C:\Windows\Tasks\svchost-update.out"  # True — persistence подтверждён
```

### 4.5. Повторная проверка

```powershell
Remove-Item "C:\Windows\Tasks\svchost-update.out" -Force
Test-Path "C:\Windows\Tasks\svchost-update.out"  # False

schtasks /Run /TN "SystemUpdate"
Test-Path "C:\Windows\Tasks\svchost-update.out"  # True
```
## 4.6. Скриншоты Task Scheduler
Создание задачи в планировщике (General):

https://github.com/Ivan-qa-rgb/win-scheduled-task-persistence/blob/main/screenshots./task-general.png

Настройка триггера (Triggers):

https://github.com/Ivan-qa-rgb/win-scheduled-task-persistence/blob/main/screenshots./task-trigger.png

Действие с PowerShell (Actions):

https://github.com/Ivan-qa-rgb/win-scheduled-task-persistence/blob/main/screenshots./task-action.png

PowerShell — полная цепочка создания / запуска / проверки:
https://github.com/Ivan-qa-rgb/win-scheduled-task-persistence/blob/main/screenshots./powershell-chain.png



## 5. Артефакты атаки

### 5.1. Файловая система

| Путь                                        | Описание                                   |
|--------------------------------------------|--------------------------------------------|
| `C:\Windows\Tasks\svchost-update.ps1`      | PowerShell‑payload                         |
| `C:\Windows\Tasks\svchost-update.out`      | Маркерный файл                             |
| `C:\Windows\System32\Tasks\SystemUpdate`   | XML‑описание задачи планировщика           |

### 5.2. Реестр

```text
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\
```

### 5.3. Журналы событий

| Event ID | Журнал                             | Описание                        |
|----------|------------------------------------|---------------------------------|
| 4698     | Security                           | Создание задачи                 |
| 4702     | Security                           | Изменение задачи                |
| 4699     | Security                           | Удаление задачи                 |
| 4688     | Security                           | Создание нового процесса        |
| 200      | Microsoft-Windows-TaskScheduler/Operational | Задача зарегистрирована |
| 201      | Microsoft-Windows-TaskScheduler/Operational | Задача выполнена        |

## 6. Обнаружение (Blue Team)

### 6.1. Анализ журналов

```powershell
# Создание задач (4698)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4698} |
    Select-Object TimeCreated, Message

# Подозрительные процессы PowerShell (4688)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} |
    Where-Object {$_.Message -like "*ExecutionPolicy Bypass*"}
```

### 6.2. Проверка задач планировщика

```powershell
# Все задачи
schtasks /Query /FO LIST /V

# Конкретная задача
schtasks /Query /TN "SystemUpdate" /V

# Через PowerShell с фильтрацией
Get-ScheduledTask | Where-Object {
    $_.TaskName -like "*Update*" -or $_.TaskName -like "*System*"
}
```

### 6.3. Анализ XML задачи

```powershell
[xml]$xml = Get-Content "C:\Windows\System32\Tasks\SystemUpdate"
$xml.Task.Actions.Exec.Command
$xml.Task.Actions.Exec.Arguments
```

### 6.4. Файловые артефакты

```powershell
# Скрипты в C:\Windows\Tasks
Get-ChildItem "C:\Windows\Tasks\" | Where-Object {
    $_.Extension -in @('.ps1','.bat','.cmd','.vbs','.js')
}
```

### 6.5. Sigma‑правило

```yaml
title: Suspicious Scheduled Task with PowerShell Bypass
status: experimental
description: Обнаружение создания задачи планировщика с обходом Execution Policy

logsource:
  category: process_creation
  product: windows

detection:
  selection_schtasks:
    CommandLine|contains:
      - 'schtasks'
      - '/Create'
  selection_powershell:
    CommandLine|contains:
      - 'powershell'
      - 'powershell.exe'
    CommandLine|contains:
      - '-ExecutionPolicy Bypass'
      - '-ExecutionPolicy Unrestricted'
  condition: selection_schtasks and selection_powershell

falsepositives:
  - Легитимные административные скрипты

level: high

tags:
  - attack.persistence
  - attack.t1053.005
```

## 7. Incident Response

### 7.1. Остановка и удаление задачи

```powershell
schtasks /End /TN "SystemUpdate"
schtasks /Delete /TN "SystemUpdate" /F
```

### 7.2. Удаление файловых артефактов

```powershell
Remove-Item "C:\Windows\Tasks\svchost-update.ps1" -Force -ErrorAction SilentlyContinue
Remove-Item "C:\Windows\Tasks\svchost-update.out" -Force -ErrorAction SilentlyContinue
```

### 7.3. Проверка

```powershell
schtasks /Query /TN "SystemUpdate"  # ожидается ошибка
Test-Path "C:\Windows\Tasks\svchost-update.ps1"  # False
Test-Path "C:\Windows\Tasks\svchost-update.out"  # False
```

## 8. Рекомендации по защите

| Мера                | Реализация                                          |
|---------------------|-----------------------------------------------------|
| AppLocker / SRP     | Блокировка `powershell.exe` из нестандартных путей |
| WDAC                | Политики целостности кода                          |
| Execution Policy    | `AllSigned` / `RemoteSigned` через GPO             |
| GPO: Scheduled Tasks| Ограничение создания задач                         |
| SIEM-корреляция     | Связка 4698 + 4688 с `ExecutionPolicy Bypass`      |
| EDR-правила         | `schtasks /Create` + `powershell` в одной строке   |
| Мониторинг файлов   | `.ps1`, `.bat`, `.vbs` в `C:\Windows\Tasks\`       |
| Least Privilege     | Минимизация локальных администраторов             |

## 9. Выводы

Кейс демонстрирует классический механизм persistence через Scheduled Task с упором на маскировку (имя `SystemUpdate`), обход Execution Policy и использование только встроенных средств Windows.  
Для Blue Team критичны: мониторинг задач планировщика, событий 4698/4702/4699/4688 и анализ командных строк `schtasks` и `powershell.exe`.

## 10. Ссылки

- MITRE ATT&CK T1053.005: https://attack.mitre.org/techniques/T1053/005/
- Репозиторий: https://github.com/Ivan-qa-rgb/win-scheduled-task-persistence
- Портфолио: https://ivan-qa-rgb.github.io/cybersecurity-resume/
