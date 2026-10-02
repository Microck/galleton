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
function Quote-WindowsArgument([string]$Value) {
    # Backslashes immediately before the closing quote must be doubled for
    # CommandLineToArgvW. This also preserves drive roots such as C:\.
    $TrailingBackslashes = ([regex]::Match($Value, '\\+$')).Value.Length
    $EscapedValue = $Value
    if ($TrailingBackslashes -gt 0) {
        $EscapedValue += '\' * $TrailingBackslashes
    }
    return '"' + $EscapedValue + '"'
}
$Arguments = 'serve --dir {0} --config {1}' -f (Quote-WindowsArgument $StateDir), (Quote-WindowsArgument $Config)
$Action = New-ScheduledTaskAction -Execute $Binary -Argument $Arguments
$LogonTrigger = New-ScheduledTaskTrigger -AtLogOn -User $User
# IgnoreNew makes this a cheap health check while the daemon is running. If it
# exits after exhausting the immediate restart attempts, the recurring trigger
# starts it again without requiring the user to log out and back in.
$RecoveryTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) `
    -RepetitionInterval (New-TimeSpan -Minutes 5)
$Principal = New-ScheduledTaskPrincipal -UserId $User -LogonType Interactive -RunLevel Limited
$Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName "Galleton" -Action $Action -Trigger @($LogonTrigger, $RecoveryTrigger) `
    -Principal $Principal -Settings $Settings -Force | Out-Null
Start-ScheduledTask -TaskName "Galleton"
