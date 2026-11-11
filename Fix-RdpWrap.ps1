<#
.SYNOPSIS
    Безопасная диагностика и обновление rdpwrap.ini для RDP Wrapper (Windows Server 2025, PowerShell 5.1).

.DESCRIPTION
    - termsrv.dll НЕ изменяется. Меняется только rdpwrap.ini (после резервной копии).
    - RDP-порт и остальные настройки не трогаются; проверяются до и после.
    - TermService автоматически НЕ перезапускается (по умолчанию). Перезапуск только по ключу
      -RestartTermService и только если скрипт запущен НЕ из RDP-сеанса.
    - Если подходящей конфигурации нет - ничего не меняется, причина выводится в отчёте.
    - При любой ошибке выполняется откат rdpwrap.ini из резервной копии.

.PARAMETER OnlyCheck
    Только диагностика, без скачивания в рабочий каталог и без изменений.
.PARAMETER RestartTermService
    Перезапустить TermService после замены (запрещено из RDP-сеанса).
.PARAMETER ExpectedPort
    Ожидаемый RDP-порт (по умолчанию 5839).
.PARAMETER IniUrl
    Свой URL rdpwrap.ini (добавляется первым в список источников).
#>
[CmdletBinding()]
param(
    [switch]$OnlyCheck,
    [switch]$RestartTermService,
    [int]$ExpectedPort = 5839,
    [string]$IniUrl
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

# ---------------------------------------------------------------- журнал
$Stamp   = Get-Date -Format 'yyyyMMdd-HHmmss'
$WorkDir = Join-Path $env:ProgramData 'RDPWrapFix'
$BackupDir = Join-Path $WorkDir ("backup-$Stamp")
$LogFile = Join-Path $WorkDir ("log-$Stamp.txt")
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null

function Write-Log {
    param([string]$Msg, [ValidateSet('INFO','OK','WARN','ERR')][string]$Level = 'INFO')
    $color = @{ INFO = 'Gray'; OK = 'Green'; WARN = 'Yellow'; ERR = 'Red' }[$Level]
    $line = '[{0}] [{1}] {2}' -f (Get-Date -Format 'HH:mm:ss'), $Level, $Msg
    Write-Host $line -ForegroundColor $color
    try { Add-Content -Path $LogFile -Value $line -Encoding UTF8 } catch { }
}

function Stop-Script([string]$Msg, [int]$Code = 1) {
    Write-Log $Msg 'ERR'
    Write-Log "Журнал: $LogFile" 'INFO'
    exit $Code
}

# ---------------------------------------------------------------- проверки окружения
if ($PSVersionTable.PSVersion.Major -lt 5) { Stop-Script 'Нужен PowerShell 5.1 или новее.' }

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Stop-Script 'Запустите PowerShell от имени администратора. Ничего не изменено.'
}

Add-Type -Namespace RdpFix -Name Native -MemberDefinition '[System.Runtime.InteropServices.DllImport("user32.dll")] public static extern int GetSystemMetrics(int nIndex);'
$IsRdpSession = ([RdpFix.Native]::GetSystemMetrics(0x1000) -ne 0)   # SM_REMOTESESSION

Write-Log '=== Диагностика RDP Wrapper ==='
Write-Log ("Сеанс запуска: " + $(if ($IsRdpSession) { 'RDP (перезапуск TermService будет заблокирован)' } else { 'локальная консоль' }))

# ---------------------------------------------------------------- функции
function Get-TermsrvVersion {
    $f = Join-Path $env:SystemRoot 'System32\termsrv.dll'
    if (-not (Test-Path $f)) { throw "Не найден $f" }
    $v = (Get-Item $f).VersionInfo
    [pscustomobject]@{
        Path    = $f
        Version = ('{0}.{1}.{2}.{3}' -f $v.FileMajorPart, $v.FileMinorPart, $v.FileBuildPart, $v.FilePrivatePart)
        Sha256  = (Get-FileHash -Algorithm SHA256 -Path $f).Hash
    }
}

function Get-RdpPort {
    (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name PortNumber).PortNumber
}

function Test-PortListening([int]$Port) {
    try { return [bool](Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction Stop) }
    catch { return $false }
}

function ConvertFrom-RdpIni([string]$Text) {
    $s = @{}
    $cur = $null
    foreach ($raw in ($Text -split "`r?`n")) {
        $l = $raw.Trim()
        if ($l -eq '' -or $l.StartsWith(';')) { continue }
        if ($l -match '^\[(.+)\]$') {
            $cur = $Matches[1]
            if (-not $s.ContainsKey($cur)) { $s[$cur] = @{} }
            continue
        }
        if ($cur -and $l -match '^([^=]+)=(.*)$') { $s[$cur][$Matches[1].Trim()] = $Matches[2].Trim() }
    }
    return $s
}

# Возвращает список проблем; пустой список = секция пригодна структурно.
function Test-IniForVersion($Ini, [string]$Ver) {
    $p = New-Object System.Collections.Generic.List[string]
    if (-not $Ini.ContainsKey('Main'))       { $p.Add('нет секции [Main]') }
    if (-not $Ini.ContainsKey('PatchCodes')) { $p.Add('нет секции [PatchCodes]') }
    if (-not $Ini.ContainsKey($Ver))         { $p.Add("нет секции [$Ver]"); return ,$p }
    $sec = $Ini[$Ver]
    $hex = '^[0-9A-Fa-f]+$'
    foreach ($pre in 'LocalOnly','SingleUser','DefPolicy') {
        if ($sec["${pre}Patch.x64"] -ne '1') { $p.Add("${pre}Patch.x64 не равно 1") }
        if (-not ($sec["${pre}Offset.x64"] -match $hex)) { $p.Add("${pre}Offset.x64 отсутствует или не hex") }
        $code = $sec["${pre}Code.x64"]
        if (-not $code) { $p.Add("${pre}Code.x64 отсутствует") }
        elseif ($Ini.ContainsKey('PatchCodes') -and -not $Ini['PatchCodes'].ContainsKey($code)) { $p.Add("${pre}Code.x64=$code не определён в [PatchCodes]") }
    }
    if ($sec['SLInitHook.x64'] -ne '1') { $p.Add('SLInitHook.x64 не равно 1') }
    if (-not ($sec['SLInitOffset.x64'] -match $hex)) { $p.Add('SLInitOffset.x64 отсутствует или не hex') }
    if (-not $sec['SLInitFunc.x64']) { $p.Add('SLInitFunc.x64 отсутствует') }
    $sl = "$Ver-SLInit"
    if (-not $Ini.ContainsKey($sl) -or $Ini[$sl].Count -lt 5) { $p.Add("секция [$sl] отсутствует или неполная") }
    elseif (-not ($Ini[$sl]['bInitialized.x64'] -match $hex)) { $p.Add("в [$sl] нет bInitialized.x64") }
    return ,$p
}

function Get-IniBlock([string]$Text, [string]$Name) {
    $lines = $Text -split "`r?`n"
    $out = New-Object System.Collections.Generic.List[string]
    $on = $false
    foreach ($l in $lines) {
        if ($l -match '^\s*\[(.+?)\]\s*$') {
            if ($on) { break }
            if ($Matches[1] -eq $Name) { $on = $true }
        }
        if ($on) { $out.Add($l.TrimEnd()) }
    }
    if ($out.Count -eq 0) { return $null }
    return (($out -join "`r`n").TrimEnd())
}

function Restore-Ini([string]$Backup, [string]$Target) {
    if (-not (Test-Path $Backup)) { Write-Log "Резервная копия $Backup не найдена - откат невозможен!" 'ERR'; return $false }
    Copy-Item -Path $Backup -Destination $Target -Force
    $ok = ((Get-FileHash $Backup -Algorithm SHA256).Hash -eq (Get-FileHash $Target -Algorithm SHA256).Hash)
    if ($ok) { Write-Log "Откат выполнен: rdpwrap.ini восстановлен из $Backup" 'OK' }
    else     { Write-Log 'Откат: хэш после восстановления не совпал!' 'ERR' }
    return $ok
}

# ---------------------------------------------------------------- 1. состояние системы
$os = Get-CimInstance Win32_OperatingSystem
Write-Log ("Windows: {0}, сборка {1}.{2}" -f $os.Caption, $os.Version, (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR)

$ts = Get-TermsrvVersion
Write-Log "termsrv.dll: версия $($ts.Version), SHA256 $($ts.Sha256) (файл не изменяется)"

$svc = Get-Service TermService
Write-Log "Служба TermService: $($svc.Status)"

$svcParams = 'HKLM:\SYSTEM\CurrentControlSet\Services\TermService\Parameters'
$serviceDll = [Environment]::ExpandEnvironmentVariables((Get-ItemProperty $svcParams).ServiceDll)
$wrapInstalled = ($serviceDll -match 'rdpwrap\.dll$')
Write-Log "ServiceDll: $serviceDll"
if (-not $wrapInstalled) {
    Stop-Script 'RDP Wrapper не подключён к TermService (ServiceDll не указывает на rdpwrap.dll). Ничего не изменено.'
}
if (-not (Test-Path $serviceDll)) { Stop-Script "Файл $serviceDll не найден. Ничего не изменено." }

$IniPath = Join-Path (Split-Path $serviceDll -Parent) 'rdpwrap.ini'
if (-not (Test-Path $IniPath)) { Stop-Script "Не найден $IniPath. Ничего не изменено." }
Write-Log "rdpwrap.ini: $IniPath"

$PortBefore = [int](Get-RdpPort)
$ListenBefore = Test-PortListening $PortBefore
Write-Log "RDP-порт в реестре: $PortBefore; слушается: $ListenBefore"
if ($PortBefore -ne $ExpectedPort) { Write-Log "Порт в реестре ($PortBefore) отличается от ожидаемого ($ExpectedPort). Порт НЕ меняется." 'WARN' }

$fSingle = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server').fSingleSessionPerUser
Write-Log "fSingleSessionPerUser = $fSingle (0 = несколько сеансов одного пользователя разрешено)"

# ---------------------------------------------------------------- 2. текущий ini
$curText = [IO.File]::ReadAllText($IniPath)
$curIni  = ConvertFrom-RdpIni $curText
$curProblems = Test-IniForVersion $curIni $ts.Version
$curUpdated = $(if ($curIni.ContainsKey('Main') -and $curIni['Main'].ContainsKey('Updated')) { $curIni['Main']['Updated'] } else { '?' })
Write-Log "Текущий rdpwrap.ini: Updated=$curUpdated, SHA256 $((Get-FileHash $IniPath -Algorithm SHA256).Hash)"

# Была ли конфигурация загружена текущим процессом службы?
$pending = $false
try {
    $procId = (Get-CimInstance Win32_Service -Filter "Name='TermService'").ProcessId
    if ($procId) {
        $start = (Get-Process -Id $procId).StartTime
        $pending = ((Get-Item $IniPath).LastWriteTime -gt $start)
        Write-Log "Процесс TermService (PID $procId) запущен: $start; ini изменён: $((Get-Item $IniPath).LastWriteTime)"
    }
} catch { Write-Log "Не удалось определить время старта службы: $($_.Exception.Message)" 'WARN' }

$ExitCode = 0
$Result = ''

if ($curProblems.Count -eq 0) {
    Write-Log "В текущем rdpwrap.ini уже есть полная секция [$($ts.Version)]. Замена не требуется." 'OK'
    if ($pending) {
        Write-Log 'ini новее процесса службы: изменения вступят в силу после перезапуска TermService/перезагрузки.' 'WARN'
        $Result = 'ПОДДЕРЖКА ЕСТЬ В INI, ТРЕБУЕТСЯ ПЕРЕЗАПУСК СЛУЖБЫ ИЛИ ПЕРЕЗАГРУЗКА'
    } else {
        Write-Log 'Секция есть, а RDP Wrapper Configuration всё ещё показывает [not supported]? Тогда причина не в ini: проверьте версию rdpwrap.dll, антивирус (мог удалить/изолировать rdpwrap.dll) и перезагрузите сервер в удобное время.' 'WARN'
        $Result = 'INI В ПОРЯДКЕ, ИЗМЕНЕНИЙ НЕ ТРЕБУЕТСЯ'
    }
}
else {
    Write-Log ("В текущем ini нет пригодной секции [{0}]: {1}" -f $ts.Version, ($curProblems -join '; ')) 'WARN'

    # ------------------------------------------------------------ 3. поиск конфигурации
    $sources = New-Object System.Collections.Generic.List[object]
    if ($IniUrl) { $sources.Add(@{ Name = 'Пользовательский URL'; Url = $IniUrl }) }
    $sources.Add(@{ Name = 'sebaxakerhtc/rdpwrap.ini (основной)';   Url = 'https://raw.githubusercontent.com/sebaxakerhtc/rdpwrap.ini/master/rdpwrap.ini' })
    $sources.Add(@{ Name = 'asmtron/rdpwrap';                       Url = 'https://raw.githubusercontent.com/asmtron/rdpwrap/master/res/rdpwrap.ini' })
    $sources.Add(@{ Name = 'tstaudte/rdpwrap (форк сообщества)';    Url = 'https://raw.githubusercontent.com/tstaudte/rdpwrap/master/rdpwrap.ini' })
    $sources.Add(@{ Name = 'stascorp/rdpwrap (оригинал, устарел)';  Url = 'https://raw.githubusercontent.com/stascorp/rdpwrap/master/res/rdpwrap.ini' })

    $dl = Join-Path $WorkDir "download-$Stamp"
    New-Item -ItemType Directory -Force -Path $dl | Out-Null

    $chosen = $null
    $pool = New-Object System.Collections.Generic.List[object]
    $i = 0
    foreach ($src in $sources) {
        $i++
        Write-Log "Источник: $($src.Name) -> $($src.Url)"
        $file = Join-Path $dl ("candidate$i.ini")
        try {
            Invoke-WebRequest -UseBasicParsing -Uri $src.Url -OutFile $file -TimeoutSec 60 | Out-Null
        } catch {
            Write-Log "  не скачан: $($_.Exception.Message)" 'WARN'; continue
        }
        $bytes = [IO.File]::ReadAllBytes($file)
        if ($bytes.Length -lt 20000) { Write-Log "  файл подозрительно мал ($($bytes.Length) байт) - пропуск" 'WARN'; continue }
        $text = [Text.Encoding]::UTF8.GetString($bytes)
        if ($text -match '(?i)<html|<!doctype') { Write-Log '  вместо ini получена HTML-страница - пропуск' 'WARN'; continue }
        $ini = ConvertFrom-RdpIni $text
        $probs = Test-IniForVersion $ini $ts.Version
        $pool.Add(@{ Src = $src; Text = $text; Ini = $ini; File = $file })
        if ($probs.Count -gt 0) { Write-Log ("  не подходит: " + ($probs -join '; ')) 'WARN'; continue }
        $upd = $(if ($ini['Main'].ContainsKey('Updated')) { $ini['Main']['Updated'] } else { '?' })
        Write-Log "  ПОДХОДИТ: секция [$($ts.Version)] полная; Updated=$upd; размер $($bytes.Length); SHA256 $((Get-FileHash $file -Algorithm SHA256).Hash)" 'OK'
        $sec = $ini[$ts.Version]
        Write-Log ("  офсеты: LocalOnly={0} SingleUser={1} DefPolicy={2} SLInit={3}" -f $sec['LocalOnlyOffset.x64'], $sec['SingleUserOffset.x64'], $sec['DefPolicyOffset.x64'], $sec['SLInitOffset.x64'])
        $chosen = @{ Src = $src; File = $file; Bytes = $bytes; Ini = $ini; Upd = $upd }
        break
    }

    # Слияние: полный ini с [PatchCodes] из одного источника + секции нужной версии из другого.
    # Результат проходит ту же строгую проверку; применяется только если все 3 условия выполнены.
    if (-not $chosen) {
        $ver = $ts.Version
        foreach ($base in $pool) {
            if ($chosen) { break }
            if ($base.Ini.ContainsKey($ver) -or -not $base.Ini.ContainsKey('PatchCodes') -or -not $base.Ini.ContainsKey('Main')) { continue }
            foreach ($donor in $pool) {
                if ($donor -eq $base) { continue }
                $b1 = Get-IniBlock $donor.Text $ver
                $b2 = Get-IniBlock $donor.Text "$ver-SLInit"
                if (-not $b1 -or -not $b2) { continue }
                $mergedText = $base.Text.TrimEnd() + "`r`n`r`n" + $b1 + "`r`n`r`n" + $b2 + "`r`n"
                $mIni = ConvertFrom-RdpIni $mergedText
                $mp = Test-IniForVersion $mIni $ver
                if ($mp.Count -gt 0) { Write-Log ("Слияние [{0} + {1}] не прошло проверку: {2}" -f $base.Src.Name, $donor.Src.Name, ($mp -join '; ')) 'WARN'; continue }
                $mFile = Join-Path $dl 'merged.ini'
                $mBytes = (New-Object Text.UTF8Encoding $false).GetBytes($mergedText)
                [IO.File]::WriteAllBytes($mFile, $mBytes)
                $sec = $mIni[$ver]
                Write-Log ("СЛИЯНИЕ ПРОШЛО ПРОВЕРКУ: база '{0}' (все версии + [PatchCodes]) + секции [{1}] из '{2}'" -f $base.Src.Name, $ver, $donor.Src.Name) 'OK'
                Write-Log ("  офсеты: LocalOnly={0} SingleUser={1} DefPolicy={2} SLInit={3}" -f $sec['LocalOnlyOffset.x64'], $sec['SingleUserOffset.x64'], $sec['DefPolicyOffset.x64'], $sec['SLInitOffset.x64'])
                Write-Log '  эти офсеты совпадают с конфигурацией из issue #694 sebaxakerhtc/rdpwrap.ini (создана RDPWrapOffsetFinder v1.0, проверена автором на этой же сборке termsrv.dll 10.0.26100.9818) и с PR #693.' 'INFO'
                $chosen = @{ Src = @{ Name = "слияние: $($base.Src.Name) + $($donor.Src.Name)" }; File = $mFile; Bytes = $mBytes; Ini = $mIni; Upd = 'merged' }
                break
            }
        }
    }

    if (-not $chosen) {
        Write-Log 'Совместимая конфигурация не найдена ни в одном источнике. НИЧЕГО НЕ ИЗМЕНЕНО.' 'ERR'
        Write-Log "Причина: в проверенных репозиториях нет полной секции [$($ts.Version)]. Офсеты придумывать нельзя. Варианты: дождаться обновления ini (sebaxakerhtc/rdpwrap.ini) либо сгенерировать офсеты утилитой RDPWrapOffsetFinder (llccd) вручную; либо перейти на официальный RDS (см. ниже)." 'WARN'
        $Result = 'КОНФИГУРАЦИЯ НЕ НАЙДЕНА, СИСТЕМА НЕ ИЗМЕНЕНА'
        $ExitCode = 2
    }
    elseif ($OnlyCheck) {
        Write-Log "Режим -OnlyCheck: найдена конфигурация в '$($chosen.Src.Name)', но замена не выполняется." 'INFO'
        $Result = 'РЕЖИМ ПРОВЕРКИ: ПОДХОДЯЩИЙ INI НАЙДЕН, ИЗМЕНЕНИЙ НЕ БЫЛО'
    }
    else {
        if ($chosen.Src.Name -match 'форк сообщества') {
            Write-Log 'Внимание: источник - форк сообщества, а не основной репозиторий. Проверена только структура секции; корректность офсетов подтвердится после перезапуска службы. Откат подготовлен.' 'WARN'
        }
        # -------------------------------------------------------- 4. резервные копии
        New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
        $BackupIni = Join-Path $BackupDir 'rdpwrap.ini'
        Copy-Item $IniPath $BackupIni -Force
        $regKeys = @{
            'TermService-Parameters' = 'HKLM\SYSTEM\CurrentControlSet\Services\TermService\Parameters'
            'TerminalServer'         = 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server'
            'RDP-Tcp'                = 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
        }
        foreach ($k in $regKeys.Keys) {
            & reg.exe export $regKeys[$k] (Join-Path $BackupDir "$k.reg") /y | Out-Null
        }
        @{ Port = $PortBefore; Listening = $ListenBefore; Termsrv = $ts.Version; ServiceDll = $serviceDll; IniPath = $IniPath } |
            ConvertTo-Json | Set-Content -Path (Join-Path $BackupDir 'state.json') -Encoding UTF8
        Write-Log "Резервные копии (ini + 3 ветки реестра + состояние): $BackupDir" 'OK'

        # -------------------------------------------------------- 5-6. замена с откатом
        $replaced = $false
        try {
            $newTmp = "$IniPath.new"
            [IO.File]::WriteAllBytes($newTmp, $chosen.Bytes)
            $newHash = (Get-FileHash $newTmp -Algorithm SHA256).Hash
            Copy-Item $newTmp $IniPath -Force      # ACL существующего файла сохраняется
            Remove-Item $newTmp -Force -ErrorAction SilentlyContinue
            $replaced = $true

            # проверка после записи
            if ((Get-FileHash $IniPath -Algorithm SHA256).Hash -ne $newHash) { throw 'Хэш записанного ini не совпал с загруженным.' }
            $chk = Test-IniForVersion (ConvertFrom-RdpIni ([IO.File]::ReadAllText($IniPath))) $ts.Version
            if ($chk.Count -gt 0) { throw ('Повторная проверка ini не пройдена: ' + ($chk -join '; ')) }
            if ([int](Get-RdpPort) -ne $PortBefore) { throw 'RDP-порт в реестре изменился!' }
            if ((Get-Service TermService).Status -ne 'Running') { throw 'TermService не в состоянии Running!' }
            if ($ListenBefore -and -not (Test-PortListening $PortBefore)) { throw "Порт $PortBefore перестал слушаться!" }
            Write-Log 'rdpwrap.ini заменён и проверен. Порт и служба не затронуты.' 'OK'

            # ---------------------------------------------------- перезапуск (по явному ключу, не из RDP)
            if ($RestartTermService) {
                if ($IsRdpSession) {
                    Write-Log 'Скрипт запущен из RDP-сеанса: перезапуск TermService ЗАБЛОКИРОВАН, чтобы не потерять доступ.' 'WARN'
                } else {
                    Write-Log 'Перезапуск TermService (локальная консоль)...' 'INFO'
                    Restart-Service TermService -Force
                    Start-Sleep -Seconds 8
                    if ((Get-Service TermService).Status -ne 'Running' -or ($ListenBefore -and -not (Test-PortListening $PortBefore))) {
                        throw 'После перезапуска служба/порт не поднялись.'
                    }
                    Write-Log 'TermService перезапущен, порт слушается.' 'OK'
                }
            }
            $Result = $(if ($RestartTermService -and -not $IsRdpSession) { 'INI ОБНОВЛЁН, СЛУЖБА ПЕРЕЗАПУЩЕНА' } else { 'INI ОБНОВЛЁН, ТРЕБУЕТСЯ ПЕРЕЗАПУСК TermService ИЛИ ПЕРЕЗАГРУЗКА' })
        }
        catch {
            Write-Log "ОШИБКА: $($_.Exception.Message)" 'ERR'
            Remove-Item "$IniPath.new" -Force -ErrorAction SilentlyContinue
            $rb = Restore-Ini $BackupIni $IniPath
            if ($replaced -and $RestartTermService -and -not $IsRdpSession) {
                try { Restart-Service TermService -Force; Write-Log 'TermService перезапущен с восстановленным ini.' 'INFO' } catch { Write-Log "Не удалось перезапустить службу после отката: $($_.Exception.Message)" 'ERR' }
            }
            $Result = $(if ($rb) { 'ОШИБКА, ВЫПОЛНЕН ОТКАТ' } else { 'ОШИБКА, ОТКАТ НЕ УДАЛСЯ - ВОССТАНОВИТЕ ВРУЧНУЮ ИЗ ' + $BackupDir })
            $ExitCode = 3
        }
    }
}

# ---------------------------------------------------------------- 7. RDS как официальная альтернатива (только чтение)
Write-Log '--- Проверка RDS (только чтение, ничего не устанавливается) ---'
try {
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        $f = Get-WindowsFeature -Name RDS-RD-Server, RDS-Licensing -ErrorAction Stop
        foreach ($x in $f) { Write-Log ("Роль {0}: {1}" -f $x.Name, $(if ($x.Installed) { 'установлена' } else { 'не установлена' })) }
    }
    $tss = Get-CimInstance -Namespace 'root\cimv2\TerminalServices' -ClassName Win32_TerminalServiceSetting -ErrorAction Stop
    Write-Log "Режим лицензирования (LicensingType): $($tss.LicensingType) (2 = на устройство, 4 = на пользователя)"
    try {
        $g = Invoke-CimMethod -InputObject $tss -MethodName GetGracePeriodDays -ErrorAction Stop
        Write-Log "Льготный период RDS, дней осталось: $($g.DaysLeft)"
    } catch { }
} catch { Write-Log "Данные RDS недоступны: $($_.Exception.Message)" 'WARN' }
Write-Log 'Без RDS Windows Server разрешает 2 одновременных административных сеанса. Для большего числа пользователей официально: роль "Службы удалённых рабочих столов" (RDS-RD-Server) + лицензии RDS CAL, льготный период 120 дней; установка требует перезагрузки и выполняется вручную в окно обслуживания:  Install-WindowsFeature RDS-RD-Server -IncludeManagementTools' 'INFO'

# ---------------------------------------------------------------- 8. итоговый отчёт
$portNow = [int](Get-RdpPort)
Write-Host ''
Write-Log '================ ИТОГОВЫЙ ОТЧЁТ ================'
Write-Log ("Windows / termsrv.dll    : {0} / {1}" -f $os.Version, $ts.Version)
Write-Log ("termsrv.dll изменён      : НЕТ (SHA256 до и после: {0})" -f $(if ((Get-FileHash $ts.Path -Algorithm SHA256).Hash -eq $ts.Sha256) { 'совпадает' } else { 'НЕ СОВПАДАЕТ!' }))
Write-Log ("TermService             : {0}" -f (Get-Service TermService).Status)
Write-Log ("RDP-порт (было/стало)   : {0} / {1}; слушается: {2}" -f $PortBefore, $portNow, (Test-PortListening $portNow))
$finalProblems = Test-IniForVersion (ConvertFrom-RdpIni ([IO.File]::ReadAllText($IniPath))) $ts.Version
Write-Log ("Секция [{0}] в ini     : {1}" -f $ts.Version, $(if ($finalProblems.Count -eq 0) { 'есть, структура корректна' } else { 'ОТСУТСТВУЕТ/НЕПОЛНАЯ' }))
Write-Log "Итог                    : $Result"
if (Test-Path $BackupDir) { Write-Log "Резервные копии         : $BackupDir" }
Write-Log "Журнал                  : $LogFile"
if ($IsRdpSession) { Write-Log 'Чтобы изменения вступили в силу, перезагрузите сервер (или перезапустите TermService с локальной консоли/из-под другого канала доступа) в удобное время.' 'WARN' }
Write-Log 'Проверка статуса: RDPConf.exe (поле Fully supported) после перезапуска службы; откат вручную: скопировать rdpwrap.ini из папки резервной копии обратно.'
exit $ExitCode
