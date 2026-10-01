# Optional per-user login task. Invoke explicitly after building and initializing.
param(
    [Parameter(Mandatory=$true)][string]$Binary,
    [Parameter(Mandatory=$true)][string]$StateDir,
    [Parameter(Mandatory=$true)][string]$Config
)
$ErrorActionPreference = "Stop"
$Binary = (Resolve-Path $Binary).Path
$StateDir = (Resolve-Path $StateDir).Path
$Config = (Resolve-Path $Config).Path
if (-not (Test-Path (Join-Path $StateDir "api.token"))) {
    throw "Run galleton init for this state directory first."
}
foreach ($Path in @($Binary, $StateDir, $Config)) {
    if ($Path.Contains('"') -or $Path.Contains("`n") -or $Path.Contains("`r")) {
        throw "Quotes and newlines in paths are not supported."
    }
}
$User = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$Arguments = 'serve --dir "{0}" --config "{1}"' -f $StateDir.TrimEnd('\'), $Config
$Action = New-ScheduledTaskAction -Execute $Binary -Argument $Arguments
$Trigger = New-ScheduledTaskTrigger -AtLogOn -User $User
$Principal = New-ScheduledTaskPrincipal -UserId $User -LogonType Interactive -RunLevel Limited
$Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName "Galleton" -Action $Action -Trigger $Trigger `
    -Principal $Principal -Settings $Settings -Force | Out-Null
Start-ScheduledTask -TaskName "Galleton"
