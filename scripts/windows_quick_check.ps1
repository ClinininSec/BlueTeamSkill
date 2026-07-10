<#
.SYNOPSIS
    windows_quick_check.ps1 — On-host forensic collector for HVV blue team (Windows).

.DESCRIPTION
    Purpose:    Collect a snapshot of Windows host state to a zip that the customer
                ships back to the analyst. READ-ONLY: no files are modified,
                nothing is deleted, no external network calls are made.
    Inputs:     -Output   <path>   Output zip path (default C:\Temp\hvv-collect-<host>-<ts>.zip)
                -DryRun            Print the commands that WOULD be executed and exit.
                                   Use this when AV/EDR blocks the script — hand the
                                   command list to the on-site defender to run manually.
                -SkipHeavy         Skip Prefetch / Amcache / full evtx export (heavy IO).
                -Verbose           Verbose logging.
    Outputs:    C:\Temp\hvv-collect-<host>-<ts>.zip   (14 folders + collector.log)

    Red lines (six):
      1. no remote/network calls
      2. no file modifications on customer paths
      3. no deletions
      4. no service restarts
      5. no interactive prompts (fully non-interactive except this -DryRun toggle)
      6. never echoes secrets — findings must be desensitized before sharing off-host

    Coverage (14 categories, mirrors linux_quick_check.sh):
      01 base-info        · 02 accounts        · 03 login-history
      04 processes        · 05 network         · 06 files-recent
      07 persistence-run  · 08 scheduled-tasks · 09 services
      10 wmi-subs         · 11 ps-history      · 12 autoruns
      13 prefetch-amcache · 14 evtx-export

    Runs as Administrator for full coverage; non-admin skips categories 04(partial)/08/10/13/14
    (a WARNING is emitted listing every skipped item).

    Companion parser:  scripts/evtx_hunt.py
      - Feed the exported evtx or CSV under 14-evtx-export/ into `evtx_hunt.py` to get
        machine-checked findings (rules R-WIN-001 .. R-WIN-022+).

.EXAMPLE
    PS> .\windows_quick_check.ps1
    PS> .\windows_quick_check.ps1 -Output D:\ir\case-01.zip -Verbose
    PS> .\windows_quick_check.ps1 -DryRun            # print commands only, do not run
    PS> .\windows_quick_check.ps1 -SkipHeavy         # skip heavy IO categories 13/14

.NOTES
    PowerShell 5.1+ compatible (also runs on PowerShell 7 / Core).
    Author: hvv-defender (v0.3-M1)
#>

[CmdletBinding()]
param(
    [string]$Output,
    [switch]$DryRun,
    [switch]$SkipHeavy
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

# ---------- helpers ------------------------------------------------------------

function Get-IsAdmin {
    try {
        $id  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $prn = New-Object System.Security.Principal.WindowsPrincipal($id)
        return $prn.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Write-Note {
    param([string]$Msg)
    $line = "$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ') $Msg"
    if ($script:CollectorLogPath) {
        Add-Content -Path $script:CollectorLogPath -Value $line -ErrorAction SilentlyContinue
    }
    Write-Verbose $line
}

function Invoke-CollectCommand {
    <#
      Runs a PowerShell scriptblock and captures BOTH the command text and its output
      into a per-category text file. Failures are tolerated (recorded, not thrown).
      In -DryRun mode, only the command text is echoed and NO execution occurs.
    #>
    param(
        [Parameter(Mandatory)][string]$OutFile,
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][scriptblock]$Script
    )
    $cmdText = $Script.ToString().Trim()
    if ($script:DryRunMode) {
        # -DryRun: emit ONLY the command line, one per invocation
        "### [$Label] $cmdText" | Write-Output
        return
    }
    $header = "### $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ') :: $Label"
    Add-Content -Path $OutFile -Value $header -ErrorAction SilentlyContinue
    Add-Content -Path $OutFile -Value "### CMD: $cmdText" -ErrorAction SilentlyContinue
    try {
        $out = & $Script 2>&1
        if ($null -ne $out) {
            $out | Out-String -Width 4096 | Add-Content -Path $OutFile -ErrorAction SilentlyContinue
        }
        Add-Content -Path $OutFile -Value "### exit=0`n" -ErrorAction SilentlyContinue
    } catch {
        Add-Content -Path $OutFile -Value ("### exit=1  ERROR: {0}`n" -f $_.Exception.Message) -ErrorAction SilentlyContinue
    }
}

# ---------- banner + arg setup -------------------------------------------------

$Hostname   = try { [System.Net.Dns]::GetHostName() } catch { $env:COMPUTERNAME }
$Timestamp  = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$IsAdmin    = Get-IsAdmin
$script:DryRunMode = [bool]$DryRun

if (-not $Output -or $Output.Trim() -eq '') {
    $Output = "C:\Temp\hvv-collect-$Hostname-$Timestamp.zip"
}
$OutDir = [System.IO.Path]::ChangeExtension($Output, $null).TrimEnd('.')
$script:CollectorLogPath = Join-Path $OutDir '00-collector.log'

$banner = @"
====================================================================
 hvv-defender · windows_quick_check.ps1 — read-only forensic collector
 - PowerShell 5.1+; runs LOCALLY on customer host
 - no modifications, no deletions, no network calls
 - Administrator recommended (non-admin skips categories 04p/08/10/13/14)
 - output: $Output
====================================================================
"@
Write-Output $banner

if (-not $IsAdmin) {
    Write-Warning "Not running as Administrator. The following categories will be partially or fully skipped:"
    Write-Warning "  04 processes (owner+cmdline may be blank for other users' processes)"
    Write-Warning "  08 scheduled-tasks (some tasks require admin to read XML)"
    Write-Warning "  10 wmi-subscriptions (root\subscription namespace requires admin)"
    Write-Warning "  13 prefetch+amcache (locked files; shadow copy path requires admin)"
    Write-Warning "  14 evtx-export (wevtutil epl on Security log requires admin)"
    Write-Warning "Re-run from an elevated PowerShell for full coverage."
}

if ($script:DryRunMode) {
    Write-Output "[DRY-RUN] no commands will be executed; the list below is what WOULD run."
    Write-Output "[DRY-RUN] hand this list to the on-site defender if AV/EDR blocks the script."
    Write-Output ""
} else {
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
    New-Item -ItemType File      -Path $script:CollectorLogPath -Force | Out-Null
    Write-Note "collector start ts=$Timestamp host=$Hostname user=$env:USERNAME admin=$IsAdmin"
    Write-Note "output dir: $OutDir"
    Write-Note "final zip:  $Output"
    Write-Output "[*] collecting to $OutDir"
}

# helper: bind $OutDir into a per-category file path (only used in real mode)
function _F([string]$name) { return (Join-Path $OutDir $name) }

# ==============================================================================
# 01. Base system info
# ==============================================================================
$f = _F '01-base-info.txt'
Invoke-CollectCommand -OutFile $f -Label 'hostname' -Script { hostname }
Invoke-CollectCommand -OutFile $f -Label 'systeminfo' -Script { systeminfo }
Invoke-CollectCommand -OutFile $f -Label 'Get-ComputerInfo (subset)' -Script {
    Get-ComputerInfo -Property OsName,OsVersion,OsBuildNumber,OsArchitecture,WindowsVersion,BiosSMBIOSBIOSVersion,CsDomain,CsDomainRole,CsManufacturer,CsModel,TimeZone
}
Invoke-CollectCommand -OutFile $f -Label 'Get-HotFix' -Script { Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 60 }
Invoke-CollectCommand -OutFile $f -Label 'ipconfig /all' -Script { ipconfig /all }

# ==============================================================================
# 02. Accounts
# ==============================================================================
$f = _F '02-accounts.txt'
Invoke-CollectCommand -OutFile $f -Label 'Get-LocalUser' -Script { Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordLastSet,PasswordRequired,PasswordExpires,SID,Description | Format-Table -AutoSize | Out-String -Width 4096 }
Invoke-CollectCommand -OutFile $f -Label 'net user' -Script { net user }
Invoke-CollectCommand -OutFile $f -Label 'Get-LocalGroup Administrators members' -Script { Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue }
Invoke-CollectCommand -OutFile $f -Label 'Get-LocalGroup "Remote Desktop Users" members' -Script { Get-LocalGroupMember -Group 'Remote Desktop Users' -ErrorAction SilentlyContinue }
Invoke-CollectCommand -OutFile $f -Label 'hidden accounts ($ suffix)' -Script { Get-LocalUser | Where-Object { $_.Name -like '*$' } }
Invoke-CollectCommand -OutFile $f -Label 'RID hijack check (all local SIDs)' -Script {
    Get-CimInstance -Class Win32_UserAccount -Filter "LocalAccount=True" | Select-Object Name,SID,Disabled,Lockout,PasswordRequired
}
Invoke-CollectCommand -OutFile $f -Label 'net accounts (password policy)' -Script { net accounts }

# ==============================================================================
# 03. Login history (Security log 4624/4625/4634/4672, last 7 days)
# ==============================================================================
$f = _F '03-login-history.txt'
$csvLogins = _F '03-login-history.csv'
$since = (Get-Date).AddDays(-7)
Invoke-CollectCommand -OutFile $f -Label 'Get-WinEvent Security 4624/4625/4634/4672 (last 7d, CSV)' -Script {
    if ($script:DryRunMode) { return "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4634,4672; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 5000 | Export-Csv 03-login-history.csv" }
    $evts = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4634,4672; StartTime=$since} -MaxEvents 5000 -ErrorAction SilentlyContinue
    if ($evts) {
        $rows = foreach ($e in $evts) {
            [PSCustomObject]@{
                TimeCreated = $e.TimeCreated
                Id          = $e.Id
                MachineName = $e.MachineName
                Message     = ($e.Message -replace "`r`n"," | ").Substring(0,[Math]::Min(($e.Message.Length),400))
            }
        }
        $rows | Export-Csv -Path $csvLogins -NoTypeInformation -Encoding UTF8 -ErrorAction SilentlyContinue
        "$($rows.Count) events exported to 03-login-history.csv"
    } else {
        "no events (or access denied — Security channel requires admin)"
    }
}
Invoke-CollectCommand -OutFile $f -Label 'quser (current sessions)' -Script { quser 2>&1 }
Invoke-CollectCommand -OutFile $f -Label 'query user' -Script { query user 2>&1 }

# ==============================================================================
# 04. Processes (with owner + full command line + parent PID)
# ==============================================================================
$f = _F '04-processes.txt'
Invoke-CollectCommand -OutFile $f -Label 'Get-CimInstance Win32_Process (full)' -Script {
    Get-CimInstance -ClassName Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CreationDate,CommandLine,ExecutablePath | Sort-Object ParentProcessId,ProcessId | Format-Table -AutoSize | Out-String -Width 4096
}
Invoke-CollectCommand -OutFile $f -Label 'Get-Process -IncludeUserName (may need admin)' -Script {
    Get-Process -IncludeUserName -ErrorAction SilentlyContinue | Select-Object Id,UserName,ProcessName,Path,StartTime | Format-Table -AutoSize | Out-String -Width 4096
}
Invoke-CollectCommand -OutFile $f -Label 'unsigned processes in Users/Temp/ProgramData' -Script {
    Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -match 'C:\\Users\\|C:\\Windows\\Temp|C:\\ProgramData\\|C:\\Temp' } |
        ForEach-Object {
            $sig = try { Get-AuthenticodeSignature -FilePath $_.ExecutablePath -ErrorAction SilentlyContinue } catch { $null }
            [PSCustomObject]@{
                Pid       = $_.ProcessId
                Path      = $_.ExecutablePath
                Signature = if ($sig) { $sig.Status } else { 'unknown' }
                Signer    = if ($sig) { $sig.SignerCertificate.Subject } else { $null }
                CmdLine   = $_.CommandLine
            }
        } | Format-Table -AutoSize | Out-String -Width 4096
}
Invoke-CollectCommand -OutFile $f -Label 'lsass access candidates (Sysmon Ev10 hint)' -Script {
    Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'lsass|mimikatz|procdump|comsvcs' } | Select-Object ProcessId,ParentProcessId,Name,CommandLine
}

# ==============================================================================
# 05. Network — TCP/UDP + PID -> process name
# ==============================================================================
$f = _F '05-network.txt'
Invoke-CollectCommand -OutFile $f -Label 'Get-NetTCPConnection (all with owning process)' -Script {
    Get-NetTCPConnection | ForEach-Object {
        $p = try { Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue } catch { $null }
        [PSCustomObject]@{
            LocalAddress  = $_.LocalAddress
            LocalPort     = $_.LocalPort
            RemoteAddress = $_.RemoteAddress
            RemotePort    = $_.RemotePort
            State         = $_.State
            Pid           = $_.OwningProcess
            Process       = if ($p) { $p.ProcessName } else { '?' }
        }
    } | Sort-Object State,LocalPort | Format-Table -AutoSize | Out-String -Width 4096
}
Invoke-CollectCommand -OutFile $f -Label 'Get-NetUDPEndpoint' -Script {
    Get-NetUDPEndpoint | ForEach-Object {
        $p = try { Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue } catch { $null }
        [PSCustomObject]@{
            LocalAddress = $_.LocalAddress
            LocalPort    = $_.LocalPort
            Pid          = $_.OwningProcess
            Process      = if ($p) { $p.ProcessName } else { '?' }
        }
    } | Format-Table -AutoSize | Out-String -Width 4096
}
Invoke-CollectCommand -OutFile $f -Label 'netstat -anob (fallback)' -Script { netstat -anob 2>&1 }
Invoke-CollectCommand -OutFile $f -Label 'route print' -Script { route print }
Invoke-CollectCommand -OutFile $f -Label 'Get-DnsClientCache' -Script { Get-DnsClientCache -ErrorAction SilentlyContinue }

# ==============================================================================
# 06. Recent files in high-risk paths (last 7 days, exe/dll/ps1/bat/vbs/hta/jsp)
# ==============================================================================
$f = _F '06-files-recent.txt'
Invoke-CollectCommand -OutFile $f -Label 'recent exe/dll/ps1/bat/vbs/hta in high-risk dirs (last 7d)' -Script {
    $paths = @('C:\Users','C:\ProgramData','C:\Temp','C:\Windows\Temp','C:\Windows\Tasks','C:\Windows\System32\spool\drivers\color')
    $exts  = @('*.exe','*.dll','*.ps1','*.bat','*.vbs','*.hta','*.js','*.jse','*.wsf','*.jsp','*.aspx','*.php','*.scr')
    $since = (Get-Date).AddDays(-7)
    foreach ($p in $paths) {
        if (Test-Path $p) {
            Get-ChildItem -Path $p -Include $exts -Recurse -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -ge $since -and -not $_.PSIsContainer } |
                Select-Object LastWriteTime,Length,FullName |
                Format-Table -AutoSize | Out-String -Width 4096
        }
    }
}

# ==============================================================================
# 07. Persistence — Registry Run keys (HKLM + HKCU, all standard 8 locations)
# ==============================================================================
$f = _F '07-persistence-run.txt'
$runKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
    'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
)
foreach ($k in $runKeys) {
    Invoke-CollectCommand -OutFile $f -Label "reg $k" -Script {
        param($key = $k)
        if (Test-Path $k) {
            Get-ItemProperty -Path $k -ErrorAction SilentlyContinue |
                Select-Object * -ExcludeProperty PS* |
                Format-List | Out-String -Width 4096
        } else { "(not present)" }
    }.GetNewClosure()
}

# ==============================================================================
# 08. Persistence — Scheduled Tasks (full + XML)
# ==============================================================================
$f = _F '08-scheduled-tasks.txt'
Invoke-CollectCommand -OutFile $f -Label 'Get-ScheduledTask (all, brief)' -Script {
    Get-ScheduledTask | Select-Object TaskPath,TaskName,State,Author | Sort-Object TaskPath,TaskName | Format-Table -AutoSize | Out-String -Width 4096
}
Invoke-CollectCommand -OutFile $f -Label 'Get-ScheduledTask (Author != Microsoft, with XML)' -Script {
    Get-ScheduledTask | Where-Object {
        $_.Author -and $_.Author -notmatch 'Microsoft' -and $_.Author -notmatch 'Windows'
    } | ForEach-Object {
        $x = try { Export-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction SilentlyContinue } catch { '(export failed)' }
        [PSCustomObject]@{
            TaskPath = $_.TaskPath
            TaskName = $_.TaskName
            Author   = $_.Author
            State    = $_.State
            XML      = $x
        }
    } | Format-List | Out-String -Width 4096
}
Invoke-CollectCommand -OutFile $f -Label 'schtasks /query /fo list /v (fallback)' -Script {
    schtasks /query /fo LIST /v 2>&1
}

# ==============================================================================
# 09. Persistence — Services with PathName
# ==============================================================================
$f = _F '09-services.txt'
Invoke-CollectCommand -OutFile $f -Label 'Get-CimInstance Win32_Service (full)' -Script {
    Get-CimInstance -ClassName Win32_Service |
        Select-Object Name,DisplayName,State,StartMode,StartName,PathName,ProcessId |
        Sort-Object State,Name | Format-Table -AutoSize | Out-String -Width 4096
}
Invoke-CollectCommand -OutFile $f -Label 'services with suspicious PathName (cmd/powershell/rundll32/regsvr32)' -Script {
    Get-CimInstance -ClassName Win32_Service |
        Where-Object { $_.PathName -match 'cmd\.exe|powershell\.exe|pwsh\.exe|rundll32\.exe|regsvr32\.exe|mshta\.exe|wscript\.exe|cscript\.exe' } |
        Select-Object Name,DisplayName,State,StartName,PathName |
        Format-List | Out-String -Width 4096
}
Invoke-CollectCommand -OutFile $f -Label 'services with unsigned binaries' -Script {
    Get-CimInstance -ClassName Win32_Service | ForEach-Object {
        $path = ($_.PathName -replace '^"([^"]+)".*','$1') -replace '^(\S+).*','$1'
        if ($path -and (Test-Path $path)) {
            $sig = try { Get-AuthenticodeSignature -FilePath $path -ErrorAction SilentlyContinue } catch { $null }
            if ($sig -and $sig.Status -ne 'Valid') {
                [PSCustomObject]@{
                    Name      = $_.Name
                    Path      = $path
                    SigStatus = $sig.Status
                    State     = $_.State
                }
            }
        }
    } | Format-Table -AutoSize | Out-String -Width 4096
}

# ==============================================================================
# 10. Persistence — WMI Subscriptions (root\subscription)
# ==============================================================================
$f = _F '10-wmi-subscriptions.txt'
Invoke-CollectCommand -OutFile $f -Label 'Get-CimInstance __EventFilter' -Script {
    Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventFilter' -ErrorAction SilentlyContinue |
        Select-Object Name,Query,QueryLanguage,EventNamespace | Format-List | Out-String -Width 4096
}
Invoke-CollectCommand -OutFile $f -Label 'Get-CimInstance __EventConsumer' -Script {
    Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventConsumer' -ErrorAction SilentlyContinue |
        Select-Object Name,CommandLineTemplate,ExecutablePath,ScriptFileName,ScriptText | Format-List | Out-String -Width 4096
}
Invoke-CollectCommand -OutFile $f -Label 'Get-CimInstance __FilterToConsumerBinding' -Script {
    Get-CimInstance -Namespace 'root\subscription' -ClassName '__FilterToConsumerBinding' -ErrorAction SilentlyContinue |
        Select-Object Filter,Consumer | Format-List | Out-String -Width 4096
}

# ==============================================================================
# 11. PowerShell history + 4104 script blocks
# ==============================================================================
$f = _F '11-ps-history.txt'
Invoke-CollectCommand -OutFile $f -Label 'PSReadLine HistorySavePath (current user)' -Script {
    $p = (Get-PSReadlineOption -ErrorAction SilentlyContinue).HistorySavePath
    if ($p -and (Test-Path $p)) { "== $p =="; Get-Content -Path $p -Tail 2000 -ErrorAction SilentlyContinue } else { "(no history file)" }
}
Invoke-CollectCommand -OutFile $f -Label 'PSReadLine history for every user profile' -Script {
    Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $p = Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
        if (Test-Path $p) {
            "== $($_.Name): $p =="
            Get-Content -Path $p -Tail 500 -ErrorAction SilentlyContinue
        }
    }
}
Invoke-CollectCommand -OutFile $f -Label 'Get-WinEvent Microsoft-Windows-PowerShell/Operational 4104 (last 1000)' -Script {
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 1000 -ErrorAction SilentlyContinue |
        Select-Object TimeCreated,Id,@{n='ScriptBlockText';e={($_.Message -replace "`r`n"," | ").Substring(0,[Math]::Min(($_.Message.Length),1000))}} |
        Format-Table -AutoSize | Out-String -Width 4096
}

# ==============================================================================
# 12. AutoRuns (8 categories, no Sysinternals dependency)
# ==============================================================================
$f = _F '12-autoruns.txt'

# 12.1 Startup folders (global + per-user)
Invoke-CollectCommand -OutFile $f -Label 'Startup folder — All Users' -Script {
    $p = 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp'
    if (Test-Path $p) { Get-ChildItem $p -Force -ErrorAction SilentlyContinue | Format-List }
}
Invoke-CollectCommand -OutFile $f -Label 'Startup folder — per user' -Script {
    Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $p = Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
        if (Test-Path $p) {
            "== $($_.Name) =="
            Get-ChildItem $p -Force -ErrorAction SilentlyContinue | Format-List
        }
    }
}

# 12.2 IFEO debugger hijacks
Invoke-CollectCommand -OutFile $f -Label 'IFEO Debugger entries (any = suspicious)' -Script {
    $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    if (Test-Path $ifeo) {
        Get-ChildItem $ifeo -ErrorAction SilentlyContinue | ForEach-Object {
            $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
            if ($props.Debugger -or $props.GlobalFlag -match '512') {
                [PSCustomObject]@{
                    Key       = $_.PSChildName
                    Debugger  = $props.Debugger
                    GlobalFlag= $props.GlobalFlag
                }
            }
        } | Format-List
    }
}

# 12.3 AppInit_DLLs / AppCertDlls
Invoke-CollectCommand -OutFile $f -Label 'AppInit_DLLs' -Script {
    Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -Name AppInit_DLLs,LoadAppInit_DLLs,RequireSignedAppInit_DLLs -ErrorAction SilentlyContinue | Format-List
}
Invoke-CollectCommand -OutFile $f -Label 'AppCertDlls' -Script {
    Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls' -ErrorAction SilentlyContinue | Format-List
}

# 12.4 Winlogon Shell / Userinit
Invoke-CollectCommand -OutFile $f -Label 'Winlogon Shell/Userinit' -Script {
    Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name Shell,Userinit,Notify,Taskman,VmApplet -ErrorAction SilentlyContinue | Format-List
}

# 12.5 BootExecute
Invoke-CollectCommand -OutFile $f -Label 'Session Manager BootExecute' -Script {
    Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name BootExecute -ErrorAction SilentlyContinue | Format-List
}

# 12.6 COM hijack candidates (HKCU\Software\Classes\CLSID vs HKCR)
Invoke-CollectCommand -OutFile $f -Label 'HKCU CLSID overrides (COM hijack candidates)' -Script {
    $hkcu = 'HKCU:\Software\Classes\CLSID'
    if (Test-Path $hkcu) {
        Get-ChildItem $hkcu -ErrorAction SilentlyContinue | Select-Object -First 200 | ForEach-Object {
            $inproc = Join-Path $_.PSPath 'InprocServer32'
            if (Test-Path $inproc) {
                [PSCustomObject]@{
                    CLSID   = $_.PSChildName
                    InProc  = (Get-ItemProperty -Path $inproc -ErrorAction SilentlyContinue).'(default)'
                }
            }
        } | Format-Table -AutoSize | Out-String -Width 4096
    }
}

# 12.7 Drivers (unsigned)
Invoke-CollectCommand -OutFile $f -Label 'unsigned drivers' -Script {
    Get-CimInstance Win32_SystemDriver | ForEach-Object {
        $path = $_.PathName -replace '\\\?\?\\',''
        if ($path -and (Test-Path $path)) {
            $sig = try { Get-AuthenticodeSignature -FilePath $path -ErrorAction SilentlyContinue } catch { $null }
            if ($sig -and $sig.Status -ne 'Valid') {
                [PSCustomObject]@{ Name = $_.Name; State = $_.State; Path = $path; SigStatus = $sig.Status }
            }
        }
    } | Format-Table -AutoSize | Out-String -Width 4096
}

# 12.8 Browser extension hooks (Chrome/Edge Native Messaging Hosts)
Invoke-CollectCommand -OutFile $f -Label 'Chrome/Edge Native Messaging Hosts' -Script {
    $keys = @(
        'HKLM:\SOFTWARE\Google\Chrome\NativeMessagingHosts',
        'HKLM:\SOFTWARE\Microsoft\Edge\NativeMessagingHosts',
        'HKCU:\SOFTWARE\Google\Chrome\NativeMessagingHosts',
        'HKCU:\SOFTWARE\Microsoft\Edge\NativeMessagingHosts'
    )
    foreach ($k in $keys) {
        if (Test-Path $k) {
            "== $k =="
            Get-ChildItem $k -ErrorAction SilentlyContinue | Format-List
        }
    }
}

# ==============================================================================
# 13. Prefetch + Amcache (heavy IO; needs admin for locked files via shadow copy)
# ==============================================================================
$f = _F '13-prefetch-amcache.txt'
if ($SkipHeavy) {
    if (-not $script:DryRunMode) { Add-Content -Path $f -Value "### skipped: -SkipHeavy set" }
    if ($script:DryRunMode) { "### [13-prefetch] skipped: -SkipHeavy set" }
} else {
    Invoke-CollectCommand -OutFile $f -Label 'Prefetch listing (metadata only, no copy)' -Script {
        if (Test-Path 'C:\Windows\Prefetch') {
            Get-ChildItem 'C:\Windows\Prefetch\*.pf' -ErrorAction SilentlyContinue |
                Select-Object Name,Length,LastWriteTime,CreationTime |
                Sort-Object LastWriteTime -Descending | Select-Object -First 500 |
                Format-Table -AutoSize | Out-String -Width 4096
        } else { "(Prefetch not enabled or path missing)" }
    }
    Invoke-CollectCommand -OutFile $f -Label 'Amcache.hve metadata (admin + shadow copy needed to copy)' -Script {
        $p = 'C:\Windows\AppCompat\Programs\Amcache.hve'
        if (Test-Path $p) {
            Get-Item $p | Select-Object FullName,Length,LastWriteTime,CreationTime | Format-List
            "NOTE: Amcache.hve is locked while system runs; to acquire, use vshadow / vssadmin then copy from shadow copy path. Requires admin."
        } else { "(Amcache.hve missing)" }
    }
    Invoke-CollectCommand -OutFile $f -Label 'ShimCache indirect (SYSTEM hive path)' -Script {
        "SYSTEM hive path (indirect ShimCache source): C:\Windows\System32\config\SYSTEM"
        "For extraction use: RegRipper / AmcacheParser / AppCompatCacheParser (offline)."
    }
}

# ==============================================================================
# 14. EVTX export (Security / System / Application / PowerShell / Sysmon / TaskScheduler / WMI-Activity)
# ==============================================================================
$f = _F '14-evtx-export.txt'
if ($SkipHeavy) {
    if (-not $script:DryRunMode) { Add-Content -Path $f -Value "### skipped: -SkipHeavy set" }
    if ($script:DryRunMode) { "### [14-evtx-export] skipped: -SkipHeavy set" }
} else {
    $evtxOut = _F '14-evtx-export'
    if (-not $script:DryRunMode) { New-Item -ItemType Directory -Path $evtxOut -Force | Out-Null }
    $channels = @(
        'Security',
        'System',
        'Application',
        'Microsoft-Windows-PowerShell/Operational',
        'Microsoft-Windows-Sysmon/Operational',
        'Microsoft-Windows-TaskScheduler/Operational',
        'Microsoft-Windows-WMI-Activity/Operational',
        'Microsoft-Windows-Windows Defender/Operational'
    )
    foreach ($ch in $channels) {
        Invoke-CollectCommand -OutFile $f -Label "wevtutil epl `"$ch`"" -Script {
            param($chan = $ch, $dir = $evtxOut)
            $safe = ($ch -replace '[\\/:]','_')
            $target = Join-Path $evtxOut ("{0}.evtx" -f $safe)
            $cmd = "wevtutil epl `"$ch`" `"$target`" /ow:true"
            if ($script:DryRunMode) { return $cmd }
            try {
                cmd /c $cmd 2>&1
                if (Test-Path $target) {
                    "$target size=$((Get-Item $target).Length) bytes"
                } else {
                    "$ch export failed (channel missing / access denied — Security & Sysmon need admin)"
                }
            } catch {
                "$ch export ERROR: $($_.Exception.Message)"
            }
        }.GetNewClosure()
    }
}

# ==============================================================================
# Finalize — pack to zip (real mode only)
# ==============================================================================
if (-not $script:DryRunMode) {
    Write-Note "collector end ts=$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')"
    Write-Output "[*] packing $Output"
    try {
        if (Test-Path $Output) { Remove-Item -Path $Output -Force -ErrorAction SilentlyContinue }
        Compress-Archive -Path (Join-Path $OutDir '*') -DestinationPath $Output -Force -ErrorAction Stop
        $sz = (Get-Item $Output -ErrorAction SilentlyContinue).Length
        Write-Output ""
        Write-Output "==> $Output"
        Write-Output "    size: $sz bytes"
        Write-Output ""
        Write-Output "Send the file back to the analyst via your standard secure channel."
        Write-Output "Example:  Copy over WinRM/SMB/SFTP to analyst intake."
        Write-Output "Then feed 14-evtx-export/*.evtx into: python3 evtx_hunt.py --evtx <file> --output findings.jsonl"
    } catch {
        Write-Warning "Compress-Archive failed: $($_.Exception.Message)"
        Write-Warning "Uncompressed collector directory remains at: $OutDir"
    }
} else {
    Write-Output ""
    Write-Output "[DRY-RUN] end. Total commands listed above."
    Write-Output "[DRY-RUN] to actually run: remove -DryRun and re-invoke."
}

exit 0




