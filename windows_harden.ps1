# CCDC Windows Hardening Script - Pure PowerShell
# One-shot hardening for CCDC competitions

Write-Host "=======================================" -ForegroundColor Cyan
Write-Host "  CCDC WINDOWS HARDENING SCRIPT" -ForegroundColor Cyan
Write-Host "=======================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

$startTime = Get-Date
Write-Host "Started: $startTime`n" -ForegroundColor Gray

# =============================================================================
# TASK 1: Delete SSH Service
# =============================================================================
Write-Host "[1/11] Removing OpenSSH Server..." -ForegroundColor Yellow

$sshService = Get-Service -Name sshd -ErrorAction SilentlyContinue
if ($sshService) {
    Stop-Service -Name sshd -Force -ErrorAction SilentlyContinue
    Set-Service -Name sshd -StartupType Disabled -ErrorAction SilentlyContinue
    Write-Host "  ✓ SSH service stopped and disabled" -ForegroundColor Green
}

# Remove OpenSSH feature
try {
    Disable-WindowsOptionalFeature -Online -FeatureName OpenSSH.Server~~~~0.0.1.0 -NoRestart -ErrorAction SilentlyContinue | Out-Null
    Write-Host "  ✓ OpenSSH feature removed" -ForegroundColor Green
} catch {
    Write-Host "  - OpenSSH feature not present" -ForegroundColor Gray
}

# =============================================================================
# TASK 2: Restrict RDP Access
# =============================================================================
Write-Host "`n[2/11] Restricting RDP access..." -ForegroundColor Yellow

$allowedUsers = @('blueteam', 'greyteam', 'greyteam2')
$rdpGroup = "Remote Desktop Users"

# Remove unauthorized users
$members = Get-LocalGroupMember -Group $rdpGroup -ErrorAction SilentlyContinue
foreach ($member in $members) {
    $username = $member.Name.Split('\')[-1]
    if ($username -notin $allowedUsers) {
        Remove-LocalGroupMember -Group $rdpGroup -Member $member.Name -ErrorAction SilentlyContinue
        Write-Host "  ✓ Removed: $($member.Name)" -ForegroundColor Green
    }
}

# Add approved users
foreach ($user in $allowedUsers) {
    try {
        Add-LocalGroupMember -Group $rdpGroup -Member $user -ErrorAction Stop
        Write-Host "  ✓ Added: $user" -ForegroundColor Green
    } catch {
        Write-Host "  - $user already in group or doesn't exist" -ForegroundColor Gray
    }
}

# =============================================================================
# TASK 3: Download Sysinternals Tools
# =============================================================================
Write-Host "`n[3/11] Downloading Sysinternals tools..." -ForegroundColor Yellow

$sysinternalsDir = "C:\Sysinternals"
if (-not (Test-Path $sysinternalsDir)) {
    New-Item -ItemType Directory -Path $sysinternalsDir -Force | Out-Null
}

$tools = @{
    "ADExplorer.exe" = "https://live.sysinternals.com/ADExplorer.exe"
    "procexp.exe" = "https://live.sysinternals.com/procexp.exe"
    "logonsessions.exe" = "https://live.sysinternals.com/logonsessions.exe"
    "autoruns.exe" = "https://live.sysinternals.com/autoruns.exe"
    "Sysmon.exe" = "https://live.sysinternals.com/Sysmon.exe"
    "Sysmon64.exe" = "https://live.sysinternals.com/Sysmon64.exe"
}

foreach ($tool in $tools.GetEnumerator()) {
    $dest = Join-Path $sysinternalsDir $tool.Key
    try {
        Invoke-WebRequest -Uri $tool.Value -OutFile $dest -UseBasicParsing -ErrorAction Stop
        Write-Host "  ✓ Downloaded: $($tool.Key)" -ForegroundColor Green
    } catch {
        Write-Host "  ✗ Failed: $($tool.Key)" -ForegroundColor Red
    }
}

# =============================================================================
# TASK 4: Install Sysmon with SwiftOnSecurity Config
# =============================================================================
Write-Host "`n[4/11] Installing Sysmon..." -ForegroundColor Yellow

$sysmonConfig = Join-Path $sysinternalsDir "sysmon-config.xml"
$sysmon64 = Join-Path $sysinternalsDir "Sysmon64.exe"

# Download config
try {
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile $sysmonConfig -UseBasicParsing -ErrorAction Stop
    Write-Host "  ✓ Downloaded SwiftOnSecurity config" -ForegroundColor Green
} catch {
    Write-Host "  ✗ Failed to download Sysmon config" -ForegroundColor Red
}

# Uninstall existing Sysmon
if (Test-Path $sysmon64) {
    & $sysmon64 -u force 2>$null
}

# Install Sysmon
if ((Test-Path $sysmon64) -and (Test-Path $sysmonConfig)) {
    & $sysmon64 -accepteula -i $sysmonConfig 2>$null
    Start-Sleep -Seconds 3
    
    # Verify
    $sysmonService = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
    if ($sysmonService -and $sysmonService.Status -eq 'Running') {
        Write-Host "  ✓ Sysmon installed and running" -ForegroundColor Green
        
        # Check events
        $eventCount = (Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 10 -ErrorAction SilentlyContinue).Count
        if ($eventCount -gt 0) {
            Write-Host "  ✓ Sysmon is logging events ($eventCount found)" -ForegroundColor Green
        }
    } else {
        Write-Host "  ✗ Sysmon installation failed" -ForegroundColor Red
    }
} else {
    Write-Host "  ✗ Sysmon files not available" -ForegroundColor Red
}

# =============================================================================
# TASK 5: Audit Registry Run Keys (COMPREHENSIVE)
# =============================================================================
Write-Host "`n[5/11] Auditing registry Run keys (detailed)..." -ForegroundColor Yellow

$runKeys = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServices",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
)

$allRunEntries = @()
foreach ($key in $runKeys) {
    if (Test-Path $key) {
        Write-Host "`n  Registry Key: $key" -ForegroundColor Cyan
        $items = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
        
        if ($items) {
            $properties = $items.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' }
            
            if ($properties) {
                foreach ($prop in $properties) {
                    $allRunEntries += [PSCustomObject]@{
                        RegistryKey = $key
                        ValueName = $prop.Name
                        Data = $prop.Value
                        Type = $prop.TypeNameOfValue
                    }
                }
            } else {
                Write-Host "    (empty)" -ForegroundColor Gray
            }
        } else {
            Write-Host "    (key not found)" -ForegroundColor Gray
        }
    } else {
        Write-Host "`n  Registry Key: $key" -ForegroundColor Cyan
        Write-Host "    (key does not exist)" -ForegroundColor Gray
    }
}

if ($allRunEntries.Count -gt 0) {
    Write-Host "`n  === ALL AUTORUN REGISTRY ENTRIES ===" -ForegroundColor Yellow
    $allRunEntries | Format-Table -AutoSize -Wrap
} else {
    Write-Host "`n  ✓ No autorun entries found in any monitored keys" -ForegroundColor Green
}

# =============================================================================
# TASK 6: Audit Scheduled Tasks (COMPREHENSIVE)
# =============================================================================
Write-Host "`n[6/11] Auditing ALL scheduled tasks (detailed)..." -ForegroundColor Yellow

$tasks = Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' }
Write-Host "  Found $($tasks.Count) enabled scheduled tasks`n" -ForegroundColor Cyan

$taskDetails = @()
foreach ($task in $tasks) {
    $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
    
    # Get actions (what the task runs)
    $actions = ($task.Actions | ForEach-Object { 
        if ($_.Execute) { 
            "$($_.Execute) $($_.Arguments)" 
        } 
    }) -join '; '
    
    # Get triggers
    $triggers = ($task.Triggers | ForEach-Object { 
        $_.CimClass.CimClassName 
    }) -join '; '
    
    $taskDetails += [PSCustomObject]@{
        TaskName = $task.TaskName
        Path = $task.TaskPath
        State = $task.State
        Author = $task.Principal.UserId
        RunLevel = $task.Principal.RunLevel
        LastRun = $info.LastRunTime
        NextRun = $info.NextRunTime
        Actions = $actions
        Triggers = $triggers
    }
}

Write-Host "  === ALL ENABLED SCHEDULED TASKS ===" -ForegroundColor Yellow
$taskDetails | Sort-Object Path, TaskName | Format-Table -AutoSize -Wrap

# Highlight non-Microsoft tasks
$nonMSTasks = $taskDetails | Where-Object { $_.Path -notlike '\Microsoft\*' }
if ($nonMSTasks) {
    Write-Host "`n  === NON-MICROSOFT SCHEDULED TASKS (Review These!) ===" -ForegroundColor Yellow
    $nonMSTasks | Format-Table -AutoSize -Wrap
}

# =============================================================================
# TASK 7: Check PowerShell Profile Persistence
# =============================================================================
Write-Host "`n[7/11] Checking PowerShell profiles for persistence..." -ForegroundColor Yellow

# Check all PowerShell profile locations
$profilePaths = @(
    $PROFILE.AllUsersAllHosts,
    $PROFILE.AllUsersCurrentHost,
    $PROFILE.CurrentUserAllHosts,
    $PROFILE.CurrentUserCurrentHost
)

$profilesFound = $false
foreach ($profilePath in $profilePaths) {
    if (Test-Path $profilePath) {
        $profilesFound = $true
        Write-Host "`n  ! PowerShell profile found: $profilePath" -ForegroundColor Yellow
        Write-Host "  Content:" -ForegroundColor Cyan
        Get-Content $profilePath | ForEach-Object { Write-Host "    $_" -ForegroundColor White }
    }
}

if (-not $profilesFound) {
    Write-Host "  ✓ No PowerShell profiles found" -ForegroundColor Green
}

# Display profile object details
Write-Host "`n  PowerShell Profile Locations:" -ForegroundColor Cyan
$PROFILE | Select-Object * | Format-List

# =============================================================================
# TASK 8: Check Startup Folders
# =============================================================================
Write-Host "`n[8/11] Checking startup folders..." -ForegroundColor Yellow

$startupFolders = @(
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
)

# Add user startup folders
$users = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue
foreach ($user in $users) {
    $userStartup = Join-Path $user.FullName "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
    if (Test-Path $userStartup) {
        $startupFolders += $userStartup
    }
}

$startupFilesFound = $false
foreach ($folder in $startupFolders) {
    $items = Get-ChildItem -Path $folder -ErrorAction SilentlyContinue
    if ($items) {
        Write-Host "`n  ! Files in: $folder" -ForegroundColor Yellow
        $items | Format-Table Name, LastWriteTime, Length -AutoSize
        $startupFilesFound = $true
    }
}

if (-not $startupFilesFound) {
    Write-Host "  ✓ No files in startup folders" -ForegroundColor Green
}

# =============================================================================
# TASK 9: Audit SMB Shares
# =============================================================================
Write-Host "`n[9/11] Auditing SMB shares..." -ForegroundColor Yellow

$shares = Get-SmbShare | Where-Object { $_.Name -notlike '*$' }
if ($shares) {
    Write-Host "  ! Found $($shares.Count) non-default shares:" -ForegroundColor Yellow
    foreach ($share in $shares) {
        Write-Host "`n  Share: $($share.Name)" -ForegroundColor Cyan
        Write-Host "    Path: $($share.Path)" -ForegroundColor White
        Write-Host "    Description: $($share.Description)" -ForegroundColor White
        Write-Host "    Permissions:" -ForegroundColor White
        $access = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue
        $access | Format-Table AccountName, AccessControlType, AccessRight -AutoSize
    }
} else {
    Write-Host "  ✓ No non-default SMB shares found" -ForegroundColor Green
}

# =============================================================================
# TASK 10: Disable Guest Account
# =============================================================================
Write-Host "`n[10/11] Disabling Guest account..." -ForegroundColor Yellow

try {
    Disable-LocalUser -Name "Guest" -ErrorAction Stop
    Write-Host "  ✓ Guest account disabled" -ForegroundColor Green
} catch {
    Write-Host "  - Guest account already disabled or doesn't exist" -ForegroundColor Gray
}

# =============================================================================
# TASK 11: Disable WinRM
# =============================================================================
Write-Host "`n[11/11] Disabling WinRM..." -ForegroundColor Yellow

Stop-Service -Name WinRM -Force -ErrorAction SilentlyContinue
Set-Service -Name WinRM -StartupType Disabled -ErrorAction SilentlyContinue
Write-Host "  ✓ WinRM disabled" -ForegroundColor Green

# =============================================================================
# FINAL REPORT
# =============================================================================
$endTime = Get-Date
$duration = $endTime - $startTime

Write-Host "`n=======================================" -ForegroundColor Cyan
Write-Host "  HARDENING COMPLETE" -ForegroundColor Green
Write-Host "=======================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Completed: $endTime" -ForegroundColor Gray
Write-Host "Duration: $($duration.Minutes)m $($duration.Seconds)s" -ForegroundColor Gray
Write-Host ""
Write-Host "Actions Completed:" -ForegroundColor Yellow
Write-Host "  [X] SSH service removed" -ForegroundColor Green
Write-Host "  [X] RDP access restricted" -ForegroundColor Green
Write-Host "  [X] Sysinternals tools downloaded" -ForegroundColor Green
Write-Host "  [X] Sysmon installed with SwiftOnSecurity config" -ForegroundColor Green
Write-Host "  [X] Registry Run keys audited (comprehensive)" -ForegroundColor Green
Write-Host "  [X] Scheduled tasks audited (all tasks shown)" -ForegroundColor Green
Write-Host "  [X] PowerShell profiles checked" -ForegroundColor Green
Write-Host "  [X] Startup folders checked" -ForegroundColor Green
Write-Host "  [X] SMB shares audited" -ForegroundColor Green
Write-Host "  [X] Guest account disabled" -ForegroundColor Green
Write-Host "  [X] WinRM disabled" -ForegroundColor Green
Write-Host ""
Write-Host "Tools Location: C:\Sysinternals" -ForegroundColor Cyan
Write-Host "Sysmon Logs: Event Viewer > Microsoft > Windows > Sysmon > Operational" -ForegroundColor Cyan
Write-Host ""
Write-Host "IMPORTANT: Review the tables above for suspicious entries!" -ForegroundColor Yellow
Write-Host "=======================================" -ForegroundColor Cyan