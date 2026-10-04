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
$ExistingTask = Get-ScheduledTask -TaskName "Galleton" -ErrorAction SilentlyContinue
$ExistingTaskXML = $null
$ExistingTaskWasEnabled = $false
$ExistingTaskWasRunning = $false
if ($null -ne $ExistingTask) {
    $ExistingTaskXML = Export-ScheduledTask -TaskName "Galleton"
    $ExistingTaskWasEnabled = $ExistingTask.State -ne "Disabled"
    $ExistingTaskWasRunning = $ExistingTask.State -eq "Running"
}
try {
    if ($null -ne $ExistingTask) {
        # Prevent a recovery trigger from racing the replacement while the old
        # process drains.
        Disable-ScheduledTask -TaskName "Galleton" | Out-Null
        $TaskService = New-Object -ComObject "Schedule.Service"
        $TaskService.Connect()
        function Test-GalletonTaskRunning {
            foreach ($RunningTask in @($TaskService.GetRunningTasks(1))) {
                if ($RunningTask.Path -eq "\Galleton") {
                    return $true
                }
            }
            return $false
        }
        if (Test-GalletonTaskRunning) {
            $ExistingArguments = $ExistingTask.Actions[0].Arguments
            if ($ExistingArguments -notmatch '^serve --dir "([^"]+)" --config "') {
                throw "Cannot identify the existing Galleton state directory; stop it manually and rerun."
            }
            $ExistingStateDir = $Matches[1]
            if ($ExistingStateDir.EndsWith('\\')) {
                $ExistingStateDir = $ExistingStateDir.Substring(0, $ExistingStateDir.Length - 1)
            }
            & $Binary shutdown --dir $ExistingStateDir
            if ($LASTEXITCODE -ne 0) {
                throw "The running Galleton did not accept a graceful shutdown; stop it manually and rerun."
            }
            $StopDeadline = (Get-Date).AddSeconds(330)
            while ((Test-GalletonTaskRunning) -and (Get-Date) -lt $StopDeadline) {
                Start-Sleep -Milliseconds 250
            }
            if (Test-GalletonTaskRunning) {
                throw "Timed out waiting for Galleton to flush state and stop."
            }
        }
    }
    Register-ScheduledTask -TaskName "Galleton" -Action $Action -Trigger @($LogonTrigger, $RecoveryTrigger) `
        -Principal $Principal -Settings $Settings -Force | Out-Null
    Start-ScheduledTask -TaskName "Galleton"
}
catch {
    $InstallFailure = $_
    if ($null -ne $ExistingTaskXML) {
        Register-ScheduledTask -TaskName "Galleton" -Xml $ExistingTaskXML -Force | Out-Null
        if ($ExistingTaskWasEnabled) {
            Enable-ScheduledTask -TaskName "Galleton" | Out-Null
        }
        else {
            Disable-ScheduledTask -TaskName "Galleton" | Out-Null
        }
        if ($ExistingTaskWasRunning) {
            Start-ScheduledTask -TaskName "Galleton"
        }
    }
    else {
        $FailedTask = Get-ScheduledTask -TaskName "Galleton" -ErrorAction SilentlyContinue
        if ($null -ne $FailedTask) {
            Unregister-ScheduledTask -TaskName "Galleton" -Confirm:$false
        }
    }
    throw $InstallFailure
}
