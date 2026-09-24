#requires -version 5.1
<#
.SYNOPSIS
    Windows Profile Maintenance Utility - Phase 3.1

.DESCRIPTION
    Profile analysis, selective library/desktop purging, Quick Access/Favorites reset, and active cleanup engine.

.NOTES
    Version: 3.1.0
    Run as Administrator.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================
# GLOBALS
# ============================================================

$ScriptVersion = '3.1.0'
$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$LogDirectory = Join-Path $ScriptRoot 'Logs'
$ExportDirectory = Join-Path $ScriptRoot 'Reports'

foreach ($directory in @($LogDirectory, $ExportDirectory)) {
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
}

$LogFile = Join-Path $LogDirectory (
    'ProfileMaintenance_{0}.log' -f (Get-Date -Format 'yyyyMMdd_HHmmss')
)

$script:LastAnalysis = $null

# ============================================================
# UTILITY HELPERS
# ============================================================

function Format-HumanSize {
    param([int64]$Bytes)

    if ($Bytes -ge 1GB) { return ('{0:N2} GB' -f ($Bytes / 1GB)) }
    elseif ($Bytes -ge 1MB) { return ('{0:N2} MB' -f ($Bytes / 1MB)) }
    elseif ($Bytes -ge 1KB) { return ('{0:N2} KB' -f ($Bytes / 1KB)) }
    else { return ('{0} Bytes' -f $Bytes) }
}

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('INFO','SUCCESS','WARNING','ERROR','SECURITY')][string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = '[{0}] [{1}] {2}' -f $timestamp, $Level, $Message

    try { Add-Content -LiteralPath $LogFile -Value $line -Encoding UTF8 } catch {}
}

function Test-IsAdministrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch { return $false }
}

if (-not (Test-IsAdministrator)) {
    Write-Host 'ERROR: This utility must be run as Administrator.' -ForegroundColor Red
    exit 1
}

function Resolve-SidToAccountName {
    param([Parameter(Mandatory = $true)][string]$SID)
    try {
        $sidObject = New-Object System.Security.Principal.SecurityIdentifier($SID)
        return $sidObject.Translate([System.Security.Principal.NTAccount]).Value
    }
    catch { return $SID }
}

function Get-ProfileManagementClassification {
    param(
        [Parameter(Mandatory = $true)][string]$SID,
        [Parameter(Mandatory = $true)][string]$AccountName,
        [Parameter(Mandatory = $true)][string]$ProfilePath,
        [bool]$Special = $false
    )

    $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value

    # 1. Block Well-Known Windows System & Service SIDs
    # S-1-5-18 (Local System), S-1-5-19 (Local Service), S-1-5-20 (Network Service)
    # S-1-5-500 (Built-in Administrator), S-1-5-501 (Guest)
    $protectedSids = @('S-1-5-18', 'S-1-5-19', 'S-1-5-20')
    if ($SID -in $protectedSids -or $SID.EndsWith('-500') -or $SID.EndsWith('-501')) {
        return [PSCustomObject]@{ CanManage = $false; Status = 'Blocked - System Account'; Reason = 'Built-in Windows system or administrator SID.' }
    }

    # 2. Block Protected Account Names & System Profiles
    $normalizedName = $AccountName.Trim()
    $protectedNames = @('Administrator', 'Admin', 'DefaultAccount', 'Guest', 'WDAGUtilityAccount', 'Public', 'Default')
    
    # Strip domain prefix if present (e.g., LAB1-MAIN\Administrator -> Administrator)
    $shortName = if ($normalizedName -contains '\') { $normalizedName.Split('\')[-1] } else { $normalizedName }

    if ($shortName -in $protectedNames) {
        return [PSCustomObject]@{ CanManage = $false; Status = 'Blocked - System Profile'; Reason = 'Built-in Windows administrative or default profile.' }
    }

    # 3. Block Protected Profile Directory Paths
    $normalizedPath = $ProfilePath.ToLowerInvariant().TrimEnd('\')
    if ($normalizedPath -like '*\public' -or $normalizedPath -like '*\default' -or $normalizedPath -like '*\administrator') {
        return [PSCustomObject]@{ CanManage = $false; Status = 'Blocked - System Path'; Reason = 'System directory path reserved by Windows.' }
    }

    # 4. Block Windows "Special" Profiles flag
    if ($Special) {
        return [PSCustomObject]@{ CanManage = $false; Status = 'Blocked - Special Profile'; Reason = 'Flagged as a special profile by Windows OS.' }
    }

    # 5. Block the Currently Active Logged-On Session
    if ($SID -eq $currentSid) {
        return [PSCustomObject]@{ CanManage = $false; Status = 'Blocked - Active User Session'; Reason = 'Currently logged-on active profile.' }
    }

    # 6. Passed all safety rules -> Normal Manageable Standard User
    return [PSCustomObject]@{ CanManage = $true; Status = 'Manageable'; Reason = 'Standard user profile ready for maintenance.' }
}

function Test-IsCompiledExecutable {
    param([Parameter(Mandatory = $true)][System.IO.FileInfo]$FileInfo)

    if ($FileInfo.Extension -ne '.exe') { return $false }

    try {
        $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($FileInfo.FullName)
        $hasCompany = -not [string]::IsNullOrWhiteSpace($versionInfo.CompanyName)
        $hasProduct = -not [string]::IsNullOrWhiteSpace($versionInfo.ProductName)
        $hasDescription = -not [string]::IsNullOrWhiteSpace($versionInfo.FileDescription)

        if (-not ($hasCompany -or $hasProduct) -and -not $hasDescription) { return $true }
        if ($versionInfo.ProductName -match 'Dev-C\+\+|MinGW|GCC|ConsoleApplication' -or $versionInfo.CompanyName -match 'Free Software Foundation') { return $true }
    }
    catch { return $true }

    return $false
}

function Get-DirectoryScan {
    param([Parameter(Mandatory = $true)][string]$Path)

    $startTime = Get-Date
    $totalBytes = [int64]0
    $fileCount = 0
    $directoryCount = 0
    $errorCount = 0
    $reparsePointCount = 0

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        return [PSCustomObject]@{ Path = $Path; Exists = $false; SizeBytes = [int64]0; SizeFormatted = '0 Bytes'; FileCount = 0; DirectoryCount = 0; ErrorCount = 0; ReparsePointCount = 0; DurationSeconds = 0 }
    }

    try {
        $rootDirectory = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        $directories = New-Object System.Collections.Generic.Stack[string]
        $directories.Push($rootDirectory.FullName)

        while ($directories.Count -gt 0) {
            $currentPath = $directories.Pop()
            $directoryCount++

            try { $items = Get-ChildItem -LiteralPath $currentPath -Force -ErrorAction Stop }
            catch { $errorCount++; continue }

            foreach ($item in $items) {
                try {
                    $isReparsePoint = (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
                    if ($isReparsePoint) { $reparsePointCount++; continue }

                    if ($item.PSIsContainer) { $directories.Push($item.FullName) }
                    else { $totalBytes += [int64]$item.Length; $fileCount++ }
                }
                catch { $errorCount++ }
            }
        }
    }
    catch { $errorCount++ }

    $endTime = Get-Date
    [PSCustomObject]@{ Path = $Path; Exists = $true; SizeBytes = $totalBytes; SizeFormatted = Format-HumanSize -Bytes $totalBytes; FileCount = $fileCount; DirectoryCount = $directoryCount; ErrorCount = $errorCount; ReparsePointCount = $reparsePointCount; DurationSeconds = [math]::Round(($endTime - $startTime).TotalSeconds, 2) }
}

function Get-DesktopSelectiveScan {
    param([Parameter(Mandatory = $true)][string]$DesktopPath)

    $totalBytes = [int64]0
    $fileCount = 0
    $targetItems = @()

    if (-not (Test-Path -LiteralPath $DesktopPath -PathType Container)) {
        return [PSCustomObject]@{ SizeBytes = [int64]0; FileCount = 0; Items = @() }
    }

    try {
        $items = Get-ChildItem -LiteralPath $DesktopPath -Force -ErrorAction Stop
        foreach ($item in $items) {
            $isReparsePoint = (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
            if ($isReparsePoint) { continue }

            # Preserve directories, shortcuts, AND desktop.ini
            if ($item.PSIsContainer) {
                $scan = Get-DirectoryScan -Path $item.FullName
                $totalBytes += $scan.SizeBytes
                $fileCount += $scan.FileCount
                $targetItems += $item.FullName
            }
            else {
                # Skip shortcuts and system folder metadata
                if ($item.Extension -in @('.lnk', '.url') -or $item.Name -eq 'desktop.ini') { continue }

                if ($item.Extension -eq '.exe') {
                    if (Test-IsCompiledExecutable -FileInfo $item) {
                        $totalBytes += $item.Length
                        $fileCount++
                        $targetItems += $item.FullName
                    }
                    continue
                }

                # Standard loose user document/file on Desktop
                $totalBytes += $item.Length
                $fileCount++
                $targetItems += $item.FullName
            }
        }
    }
    catch {}

    return [PSCustomObject]@{ SizeBytes = $totalBytes; FileCount = $fileCount; Items = $targetItems }
}

function Get-WindowsUserProfiles {
    Write-Log -Message 'Discovering Windows user profiles.'
    $profileInstances = @(Get-CimInstance -ClassName Win32_UserProfile | Where-Object { -not [string]::IsNullOrWhiteSpace($_.LocalPath) })
    $profileResults = @()

    foreach ($profileInstance in $profileInstances) {
        $profilePath = $profileInstance.LocalPath
        if (-not (Test-Path -LiteralPath $profilePath -PathType Container)) { continue }

        $directoryInfo = try { Get-Item -LiteralPath $profilePath -Force -ErrorAction Stop } catch { $null }
        $lastWriteTime = if ($null -ne $directoryInfo) { $directoryInfo.LastWriteTime } else { $null }
        $accountName = Resolve-SidToAccountName -SID $profileInstance.SID
        # $management = Get-ProfileManagementClassification -SID $profileInstance.SID -Special ([bool]$profileInstance.Special)
        $management = Get-ProfileManagementClassification `
                        -SID $profileInstance.SID `
                        -AccountName $accountName `
                        -ProfilePath $profilePath `
                        -Special ([bool]$profileInstance.Special)
        $profileStatistics = Get-DirectoryScan -Path $profilePath

        $profileResults += [PSCustomObject]@{
            Username = $accountName
            SID = $profileInstance.SID
            ProfilePath = $profilePath
            Loaded = [bool]$profileInstance.Loaded
            Special = [bool]$profileInstance.Special
            SizeBytes = $profileStatistics.SizeBytes
            SizeFormatted = $profileStatistics.SizeFormatted
            FileCount = $profileStatistics.FileCount
            DirectoryCount = $profileStatistics.DirectoryCount
            ScanErrorCount = $profileStatistics.ErrorCount
            LastWriteTime = $lastWriteTime
            ManagementStatus = $management.Status
            ManagementReason = $management.Reason
            CanManage = $management.CanManage
        }
    }

    Write-Log -Message ('Discovered {0} profile(s).' -f $profileResults.Count) -Level SUCCESS
    return $profileResults
}

function Select-Profile {
    param([Parameter(Mandatory = $true)][array]$Profiles)

    if ($Profiles.Count -eq 0) { return $null }

    while ($true) {
        Clear-Host
        Write-Host ''
        Write-Host 'SELECT USER PROFILE' -ForegroundColor Cyan
        Write-Host '============================================'
        Write-Host ''

        for ($index = 0; $index -lt $Profiles.Count; $index++) {
            $profileEntry = $Profiles[$index]
            $status = if ($profileEntry.CanManage) { 'Manageable' } else { $profileEntry.ManagementStatus }
            Write-Host ('[{0}] {1} ({2}) - {3}' -f ($index + 1), $profileEntry.Username, $profileEntry.SizeFormatted, $status)
        }

        Write-Host ''
        $selection = Read-Host 'Enter profile number or Q to cancel'
        if ($selection -match '^[Qq]$') { return $null }

        $number = 0
        if ([int]::TryParse($selection, [ref]$number)) {
            if ($number -ge 1 -and $number -le $Profiles.Count) { return $Profiles[$number - 1] }
        }
    }
}

function Get-PathClassification {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $normalizedPath = $Path.ToLowerInvariant()
    $normalizedName = $Name.ToLowerInvariant()

    if ($normalizedPath -like '*\appdata\local\temp*' -or $normalizedPath -like '*\appdata\local\crashdumps*' -or $normalizedPath -like '*\appdata\local\microsoft\windows\wer*') {
        return 'Safe Cleanup'
    }
    if ($normalizedName -in @('downloads', 'documents', 'pictures', 'videos', 'music', 'saved games') -or $normalizedPath -like '*\appdata\roaming\microsoft\windows\recent*') {
        return 'Purge Candidate'
    }
    if ($normalizedName -eq 'desktop') { return 'Selective Clean' }
    if ($normalizedName -eq 'appdata') { return 'Review' }
    if ($normalizedName -in @('ntuser.dat', 'ntuser.dat.log1', 'ntuser.dat.log2', 'ntuser.ini')) { return 'Protected' }

    return 'Informational'
}

function Get-ProfileTopLevelAnalysis {
    param([Parameter(Mandatory = $true)][string]$ProfilePath)

    $results = @()
    if (-not (Test-Path -LiteralPath $ProfilePath -PathType Container)) { return $results }

    try { $items = Get-ChildItem -LiteralPath $ProfilePath -Force -ErrorAction Stop } catch { return $results }

    foreach ($item in $items) {
        $isReparsePoint = (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)

        if ($isReparsePoint) {
            $results += [PSCustomObject]@{ Name = $item.Name; Path = $item.FullName; Type = if ($item.PSIsContainer) { 'Directory' } else { 'File' }; SizeBytes = [int64]0; SizeFormatted = '0 Bytes'; Classification = 'Protected' }
            continue
        }

        if ($item.PSIsContainer) {
            if ($item.Name -eq 'Desktop') {
                $desktopScan = Get-DesktopSelectiveScan -DesktopPath $item.FullName
                $results += [PSCustomObject]@{ Name = $item.Name; Path = $item.FullName; Type = 'Directory'; SizeBytes = $desktopScan.SizeBytes; SizeFormatted = Format-HumanSize -Bytes $desktopScan.SizeBytes; Classification = 'Selective Clean' }
            }
            else {
                $statistics = Get-DirectoryScan -Path $item.FullName
                $classification = Get-PathClassification -Path $item.FullName -Name $item.Name
                $results += [PSCustomObject]@{ Name = $item.Name; Path = $item.FullName; Type = 'Directory'; SizeBytes = $statistics.SizeBytes; SizeFormatted = $statistics.SizeFormatted; Classification = $classification }
            }
        }
        else {
            $fileSize = try { [int64]$item.Length } catch { [int64]0 }
            $classification = Get-PathClassification -Path $item.FullName -Name $item.Name
            $results += [PSCustomObject]@{ Name = $item.Name; Path = $item.FullName; Type = 'File'; SizeBytes = $fileSize; SizeFormatted = Format-HumanSize -Bytes $fileSize; Classification = $classification }
        }
    }

    return $results
}

function Get-CleanupCandidateAnalysis {
    param([Parameter(Mandatory = $true)][string]$ProfilePath)

    $candidateDefinitions = @(
        @{ Name = 'User Temp'; RelativePath = 'AppData\Local\Temp'; Classification = 'Safe Cleanup'; Level = 'Light'; Reason = 'Temporary application files.' },
        @{ Name = 'Crash Dumps'; RelativePath = 'AppData\Local\CrashDumps'; Classification = 'Safe Cleanup'; Level = 'Light'; Reason = 'Per-user crash log files.' },
        @{ Name = 'Windows Error Reporting'; RelativePath = 'AppData\Local\Microsoft\Windows\WER'; Classification = 'Safe Cleanup'; Level = 'Light'; Reason = 'WER diagnostic reports.' },
        @{ Name = 'Recycle Bin'; RelativePath = 'AppData\Local\Microsoft\Windows\Explorer'; Classification = 'Safe Cleanup'; Level = 'Light'; Reason = 'Empties deleted items from the Recycle Bin.' },
        @{ Name = 'Downloads Library'; RelativePath = 'Downloads'; Classification = 'Purge Candidate'; Level = 'Deep'; Reason = 'Downloaded user files.' },
        @{ Name = 'Documents Library'; RelativePath = 'Documents'; Classification = 'Purge Candidate'; Level = 'Deep'; Reason = 'User documents.' },
        @{ Name = 'Pictures Library'; RelativePath = 'Pictures'; Classification = 'Purge Candidate'; Level = 'Deep'; Reason = 'User pictures and images.' },
        @{ Name = 'Videos Library'; RelativePath = 'Videos'; Classification = 'Purge Candidate'; Level = 'Deep'; Reason = 'User media/video files.' },
        @{ Name = 'Music Library'; RelativePath = 'Music'; Classification = 'Purge Candidate'; Level = 'Deep'; Reason = 'User audio files.' },
        @{ Name = 'Selective Desktop Clean'; RelativePath = 'Desktop'; Classification = 'Selective Clean'; Level = 'Deep'; Reason = 'User docs & compiled .exe files (Shortcuts & App .exe preserved).' },
        @{ Name = 'Quick Access & Favorites Reset'; RelativePath = 'AppData\Roaming\Microsoft\Windows\Recent'; Classification = 'Purge Candidate'; Level = 'Deep'; Reason = 'Resets File Explorer Quick Access pins, Favorites, and Recent items to factory default.' },
        @{ Name = 'Explorer Cache'; RelativePath = 'AppData\Local\Microsoft\Windows\Explorer'; Classification = 'Purge Candidate'; Level = 'Deep'; Reason = 'Explorer thumbnail and icon cache.' }
    )

    $results = @()

    foreach ($definition in $candidateDefinitions) {
        $targetPath = Join-Path -Path $ProfilePath -ChildPath $definition.RelativePath
        if (-not (Test-Path -LiteralPath $targetPath -PathType Container)) { continue }

        if ($definition.Name -eq 'Selective Desktop Clean') {
            $desktopScan = Get-DesktopSelectiveScan -DesktopPath $targetPath
            if ($desktopScan.SizeBytes -gt 0) {
                $results += [PSCustomObject]@{ Name = $definition.Name; Path = $targetPath; SizeBytes = $desktopScan.SizeBytes; SizeFormatted = Format-HumanSize -Bytes $desktopScan.SizeBytes; Classification = $definition.Classification; Reason = $definition.Reason; CleanupLevel = $definition.Level; TargetItems = $desktopScan.Items }
            }
        }
        else {
            $statistics = Get-DirectoryScan -Path $targetPath
            if ($statistics.SizeBytes -gt 0) {
                $results += [PSCustomObject]@{ Name = $definition.Name; Path = $targetPath; SizeBytes = $statistics.SizeBytes; SizeFormatted = $statistics.SizeFormatted; Classification = $definition.Classification; Reason = $definition.Reason; CleanupLevel = $definition.Level; TargetItems = @($targetPath) }
            }
        }
    }

    return $results
}

function Invoke-ProfileAnalysisV30 {
    param([Parameter(Mandatory = $true)][PSCustomObject]$ProfileInfo)

    if (-not $ProfileInfo.CanManage) { return $null }

    $analysisStart = Get-Date
    Write-Log -Message ('Starting Phase 3.1 analysis: {0}' -f $ProfileInfo.Username)

    Write-Host ''
    Write-Host 'Analyzing profile...' -ForegroundColor Cyan
    Write-Host ('User : {0}' -f $ProfileInfo.Username)
    Write-Host ('Path : {0}' -f $ProfileInfo.ProfilePath)
    Write-Host ''

    $topLevel = @(Get-ProfileTopLevelAnalysis -ProfilePath $ProfileInfo.ProfilePath)
    $cleanupCandidates = @(Get-CleanupCandidateAnalysis -ProfilePath $ProfileInfo.ProfilePath)

    $safeCleanupBytes = [int64]0
    $purgeBytes = [int64]0

    foreach ($candidate in $cleanupCandidates) {
        if ($candidate.Classification -eq 'Safe Cleanup') { $safeCleanupBytes += $candidate.SizeBytes }
        else { $purgeBytes += $candidate.SizeBytes }
    }

    $analysisEnd = Get-Date

    $analysis = [PSCustomObject]@{
        Version = '3.1.0'
        Username = $ProfileInfo.Username
        SID = $ProfileInfo.SID
        ProfilePath = $ProfileInfo.ProfilePath
        ProfileSizeFormatted = $ProfileInfo.SizeFormatted
        ProfileLoaded = $ProfileInfo.Loaded
        TopLevel = $topLevel
        CleanupCandidates = $cleanupCandidates
        SafeCleanupBytes = $safeCleanupBytes
        SafeCleanupFormatted = Format-HumanSize -Bytes $safeCleanupBytes
        PurgeBytes = $purgeBytes
        PurgeFormatted = Format-HumanSize -Bytes $purgeBytes
        DurationSeconds = [math]::Round(($analysisEnd - $analysisStart).TotalSeconds, 2)
    }

    $script:LastAnalysis = $analysis
    return $analysis
}

function Invoke-ProfileCleanup {
    param(
        [Parameter(Mandatory = $true)][PSCustomObject]$Analysis,
        [ValidateSet('Light','Deep')][string]$CleanupMode = 'Light'
    )

    Clear-Host
    Write-Host ''
    Write-Host 'ACTIVE PROFILE CLEANUP ENGINE (PHASE 3)' -ForegroundColor Red
    Write-Host '=================================================='
    Write-Host ''
    Write-Host ('Target User : {0}' -f $Analysis.Username)
    Write-Host ('Profile Path: {0}' -f $Analysis.ProfilePath)
    Write-Host ('Mode        : {0}' -f $CleanupMode)
    Write-Host ''

    $eligible = @(
        $Analysis.CleanupCandidates | Where-Object {
            if ($CleanupMode -eq 'Light') { $_.Classification -eq 'Safe Cleanup' }
            else { $true }
        }
    )

    if ($eligible.Count -eq 0) {
        Write-Host 'No cleanup candidates match this mode.' -ForegroundColor Yellow
        return
    }

    $totalReclaimBytes = [int64]0
    foreach ($item in $eligible) { $totalReclaimBytes += $item.SizeBytes }

    Write-Host 'TARGETS TO BE PURGED / CLEANED:' -ForegroundColor Yellow
    foreach ($item in $eligible) {
        Write-Host (' - {0,-32} [{1}]' -f $item.Name, $item.SizeFormatted) -ForegroundColor Cyan
    }

    Write-Host ''
    Write-Host ('Total Potential Space Recovery: {0}' -f (Format-HumanSize -Bytes $totalReclaimBytes)) -ForegroundColor Green
    Write-Host ''
    Write-Host 'WARNING: Selected items will be permanently deleted or reset.' -ForegroundColor Red
    $confirmation = Read-Host 'Type "DELETE" to confirm active cleanup'

    if ($confirmation -ne 'DELETE') {
        Write-Host ''
        Write-Host 'Cleanup action canceled by administrator.' -ForegroundColor Yellow
        return
    }

    Write-Host ''
    Write-Host 'Executing active cleanup...' -ForegroundColor Cyan
    $errorCount = 0

    foreach ($candidate in $eligible) {
        Write-Host ('Processing {0}...' -f $candidate.Name) -ForegroundColor DarkCyan

        if ($candidate.Name -eq 'Selective Desktop Clean') {
            foreach ($itemPath in $candidate.TargetItems) {
                try {
                    if (Test-Path -LiteralPath $itemPath) {
                        Remove-Item -LiteralPath $itemPath -Recurse -Force -ErrorAction Stop
                        Write-Log -Message ('Deleted desktop item: {0}' -f $itemPath) -Level SUCCESS
                    }
                }
                catch {
                    $errorCount++
                    Write-Log -Message ('Failed to delete {0}: {1}' -f $itemPath, $_.Exception.Message) -Level ERROR
                }
            }
        }
        elseif ($candidate.Name -eq 'Recycle Bin') {
            try {
                Clear-RecycleBin -Force -ErrorAction Stop
                Write-Log -Message 'Recycle Bin successfully emptied.' -Level SUCCESS
            }
            catch {
                $errorCount++
                Write-Log -Message ('Failed to empty Recycle Bin: {0}' -f $_.Exception.Message) -Level ERROR
            }
        }
        elseif ($candidate.Name -eq 'Quick Access & Favorites Reset') {
            try {
                $subfolders = @('AutomaticDestinations', 'CustomDestinations')
                foreach ($sub in $subfolders) {
                    $targetFolder = Join-Path $candidate.Path $sub
                    if (Test-Path -LiteralPath $targetFolder) {
                        Remove-Item -Path (Join-Path $targetFolder '*') -Force -Recurse -ErrorAction SilentlyContinue
                    }
                }
                Get-ChildItem -LiteralPath $candidate.Path -Filter '*.lnk' -Force -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
                Write-Log -Message 'Quick Access and Favorites successfully reset to factory default.' -Level SUCCESS
            }
            catch {
                $errorCount++
                Write-Log -Message ('Error resetting Quick Access: {0}' -f $_.Exception.Message) -Level ERROR
            }
        }
        else {
            try {
                $subItems = Get-ChildItem -LiteralPath $candidate.Path -Force -ErrorAction Stop
                foreach ($subItem in $subItems) {
                    try {
                        Remove-Item -LiteralPath $subItem.FullName -Recurse -Force -ErrorAction Stop
                        Write-Log -Message ('Deleted: {0}' -f $subItem.FullName) -Level SUCCESS
                    }
                    catch {
                        $errorCount++
                        Write-Log -Message ('Locked/Skipped: {0}' -f $subItem.FullName) -Level WARNING
                    }
                }
            }
            catch { $errorCount++ }
        }
    }

    Write-Host ''
    Write-Host 'CLEANUP COMPLETE' -ForegroundColor Green
    Write-Host ('Errors / Skipped Files: {0}' -f $errorCount)
}

function Show-ProfileAnalysisV30 {
    param([Parameter(Mandatory = $true)][PSCustomObject]$Analysis)

    Clear-Host
    Write-Host ''
    Write-Host 'WINDOWS PROFILE ANALYZER v3.1' -ForegroundColor Cyan
    Write-Host '=================================================='
    Write-Host ''
    Write-Host ('User              : {0}' -f $Analysis.Username)
    Write-Host ('Profile           : {0}' -f $Analysis.ProfilePath)
    Write-Host ('Profile Size      : {0}' -f $Analysis.ProfileSizeFormatted)
    Write-Host ('Analysis Duration : {0} seconds' -f $Analysis.DurationSeconds)
    Write-Host ''

    Write-Host 'TOP-LEVEL STORAGE BREAKDOWN' -ForegroundColor Cyan
    Write-Host '--------------------------------------------------'

    foreach ($item in ($Analysis.TopLevel | Sort-Object -Property SizeBytes -Descending)) {
        $displayColor = switch ($item.Classification) {
            'Safe Cleanup' { 'Green' }
            'Purge Candidate' { 'Yellow' }
            'Selective Clean' { 'Cyan' }
            'Protected' { 'Magenta' }
            default { 'Gray' }
        }

        Write-Host ('{0,-28} {1,12}   [{2}]' -f $item.Name, $item.SizeFormatted, $item.Classification) -ForegroundColor $displayColor
    }

    Write-Host ''
    Write-Host 'ANALYSIS SUMMARY' -ForegroundColor Cyan
    Write-Host '--------------------------------------------------'
    Write-Host ('Safe Temp Recovery    : {0}' -f $Analysis.SafeCleanupFormatted) -ForegroundColor Green
    Write-Host ('Purge/Clean Recovery  : {0}' -f $Analysis.PurgeFormatted) -ForegroundColor Yellow
    Write-Host ''
}

function Invoke-CleanupDryRun {
    param(
        [Parameter(Mandatory = $true)][PSCustomObject]$Analysis,
        [ValidateSet('Light','Deep')][string]$CleanupMode = 'Light'
    )

    Clear-Host
    Write-Host ''
    Write-Host 'CLEANUP DRY RUN (PREVIEW)' -ForegroundColor Cyan
    Write-Host '=================================================='
    Write-Host ''
    Write-Host ('User    : {0}' -f $Analysis.Username)
    Write-Host ('Profile : {0}' -f $Analysis.ProfilePath)
    Write-Host ('Mode    : {0}' -f $CleanupMode)
    Write-Host ''

    $eligible = @(
        $Analysis.CleanupCandidates | Where-Object {
            if ($CleanupMode -eq 'Light') { $_.Classification -eq 'Safe Cleanup' }
            else { $true }
        }
    )

    if ($eligible.Count -eq 0) {
        Write-Host 'No candidates match this mode.' -ForegroundColor Yellow
        return
    }

    $plannedBytes = [int64]0

    Write-Host 'PLANNED ACTIONS' -ForegroundColor Cyan
    Write-Host '--------------------------------------------------'

    foreach ($item in $eligible) {
        $plannedBytes += $item.SizeBytes
        $color = if ($item.Classification -eq 'Safe Cleanup') { 'Green' } else { 'Yellow' }

        Write-Host ('[{0}] {1,-32} {2,12}' -f $item.Classification, $item.Name, $item.SizeFormatted) -ForegroundColor $color
        Write-Host ('     Reason: {0}' -f $item.Reason) -ForegroundColor DarkGray
    }

    Write-Host ''
    Write-Host ('Potential Space Recovery: {0}' -f (Format-HumanSize -Bytes $plannedBytes)) -ForegroundColor Green
    Write-Host ''
    Write-Host 'DRY RUN ONLY - NO FILES WERE MODIFIED.' -ForegroundColor Green
    Write-Host ''
}

function Show-MainMenu {
    while ($true) {
        Clear-Host
        Write-Host ''
        Write-Host '============================================' -ForegroundColor Cyan
        Write-Host '       WINDOWS PROFILE MAINTENANCE' -ForegroundColor Cyan
        Write-Host ('                 v{0}' -f $ScriptVersion) -ForegroundColor Cyan
        Write-Host '============================================' -ForegroundColor Cyan
        Write-Host ''
        Write-Host ('Administrator : {0}' -f ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name))

        if ($null -ne $script:LastAnalysis) {
            Write-Host ('Last Analysis : {0} ({1})' -f $script:LastAnalysis.Username, $script:LastAnalysis.ProfileSizeFormatted) -ForegroundColor DarkGray
        }

        Write-Host ''
        Write-Host '[1] List User Profiles'
        Write-Host '[2] Analyze Profile'
        Write-Host '[3] Cleanup Dry Run (Preview)'
        Write-Host '[4] Execute Active Cleanup (Phase 3)'
        Write-Host '[5] Export Last Analysis (JSON)'
        Write-Host '[6] Exit'
        Write-Host ''

        $choice = Read-Host 'Select an option'

        switch ($choice) {
            '1' {
                Clear-Host
                Write-Host 'WINDOWS USER PROFILES' -ForegroundColor Cyan
                $profiles = @(Get-WindowsUserProfiles)
                foreach ($p in $profiles) {
                    Write-Host ('User       : {0}' -f $p.Username)
                    Write-Host ('Path       : {0}' -f $p.ProfilePath)
                    Write-Host ('Size       : {0}' -f $p.SizeFormatted)
                    Write-Host ('Management : {0}' -f $p.ManagementStatus)
                    Write-Host '--------------------------------------------'
                }
                Read-Host 'Press Enter to continue'
            }

            '2' {
                $profiles = @(Get-WindowsUserProfiles)
                $selected = Select-Profile -Profiles $profiles
                if ($null -ne $selected) {
                    $analysis = Invoke-ProfileAnalysisV30 -ProfileInfo $selected
                    if ($null -ne $analysis) { Show-ProfileAnalysisV30 -Analysis $analysis }
                }
                Read-Host 'Press Enter to continue'
            }

            '3' {
                if ($null -eq $script:LastAnalysis) {
                    Write-Host 'Run Analyze Profile first.' -ForegroundColor Yellow
                    Read-Host 'Press Enter to continue'
                    continue
                }
                Invoke-CleanupDryRun -Analysis $script:LastAnalysis -CleanupMode Deep
                Read-Host 'Press Enter to continue'
            }

            '4' {
                if ($null -eq $script:LastAnalysis) {
                    Write-Host 'Run Analyze Profile first.' -ForegroundColor Yellow
                    Read-Host 'Press Enter to continue'
                    continue
                }
                Invoke-ProfileCleanup -Analysis $script:LastAnalysis -CleanupMode Deep
                Read-Host 'Press Enter to continue'
            }

            '5' {
                if ($null -ne $script:LastAnalysis) {
                    $safeName = ($script:LastAnalysis.Username -replace '[\\/:*?"<>|]', '_')
                    $filePath = Join-Path $ExportDirectory ('{0}_Analysis_{1}.json' -f $safeName, (Get-Date -Format 'yyyyMMdd_HHmmss'))
                    $script:LastAnalysis | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $filePath -Encoding UTF8
                    Write-Host ('Exported to: {0}' -f $filePath) -ForegroundColor Green
                }
                Read-Host 'Press Enter to continue'
            }

            '6' { return }
        }
    }
}

Write-Log -Message ('Windows Profile Maintenance Utility v{0} started.' -f $ScriptVersion)

try { Show-MainMenu }
finally { Write-Log -Message 'Utility session ended.' }