#requires -version 5.1
<#
.SYNOPSIS
    Windows Profile Maintenance Utility - Phase 2.2

.DESCRIPTION
    Read-only profile analysis and cleanup intelligence with Dry Run.
    NO FILES ARE DELETED OR MODIFIED in this phase.

    Includes:
      - Profile discovery and size calculation
      - Protected profile classification
      - Hierarchical profile analysis
      - Cleanup candidate detection
      - Cleanup policy/risk classification
      - Dry-run cleanup report
      - JSON export of the latest analysis
      - Logging

.NOTES
    Version: 2.2.0
    Run as Administrator.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================
# GLOBALS
# ============================================================

$ScriptVersion = '2.2.0'
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
# LOGGING
# ============================================================

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet('INFO','SUCCESS','WARNING','ERROR','SECURITY')]
        [string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = '[{0}] [{1}] {2}' -f $timestamp, $Level, $Message

    try {
        Add-Content -LiteralPath $LogFile -Value $line -Encoding UTF8
    }
    catch {
        # Logging failure must never terminate the utility.
    }
}

# ============================================================
# ADMINISTRATOR CHECK
# ============================================================

function Test-IsAdministrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)

        return $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator
        )
    }
    catch {
        return $false
    }
}

if (-not (Test-IsAdministrator)) {
    Write-Host ''
    Write-Host 'ERROR: This utility must be run as Administrator.' -ForegroundColor Red
    Write-Host ''
    Write-Host 'Right-click PowerShell and select "Run as administrator".'
    Write-Host ''
    exit 1
}

# ============================================================
# SID / ACCOUNT RESOLUTION
# ============================================================

function Resolve-SidToAccountName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SID
    )

    try {
        $sidObject = New-Object System.Security.Principal.SecurityIdentifier($SID)
        $account = $sidObject.Translate(
            [System.Security.Principal.NTAccount]
        )

        return $account.Value
    }
    catch {
        return $SID
    }
}

# ============================================================
# PROFILE MANAGEMENT CLASSIFICATION
# ============================================================

function Get-ProfileManagementClassification {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SID,

        [bool]$Special = $false
    )

    $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value

    $protectedSids = @(
        'S-1-5-18', # SYSTEM
        'S-1-5-19', # LOCAL SERVICE
        'S-1-5-20'  # NETWORK SERVICE
    )

    if ($SID -eq $currentSid) {
        return [PSCustomObject]@{
            CanManage = $false
            Status = 'Blocked - Current User'
            Reason = 'The currently logged-on profile cannot be reset or destructively managed while in use.'
        }
    }

    if ($SID -in $protectedSids) {
        return [PSCustomObject]@{
            CanManage = $false
            Status = 'Blocked - System Profile'
            Reason = 'Built-in Windows service profile.'
        }
    }

    if ($Special) {
        return [PSCustomObject]@{
            CanManage = $false
            Status = 'Blocked - Special Profile'
            Reason = 'Windows marked this profile as special.'
        }
    }

    return [PSCustomObject]@{
        CanManage = $true
        Status = 'Manageable'
        Reason = 'Profile passed the basic management safety checks.'
    }
}

# ============================================================
# DIRECTORY SCANNER
# ============================================================

function Get-DirectoryScan {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $startTime = Get-Date
    $totalBytes = [int64]0
    $fileCount = 0
    $directoryCount = 0
    $errorCount = 0
    $reparsePointCount = 0

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        return [PSCustomObject]@{
            Path = $Path
            Exists = $false
            SizeBytes = [int64]0
            SizeGB = 0
            FileCount = 0
            DirectoryCount = 0
            ErrorCount = 0
            ReparsePointCount = 0
            DurationSeconds = 0
        }
    }

    try {
        $rootDirectory = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        $directories = New-Object System.Collections.Generic.Stack[string]
        $directories.Push($rootDirectory.FullName)

        while ($directories.Count -gt 0) {
            $currentPath = $directories.Pop()
            $directoryCount++

            try {
                $items = Get-ChildItem -LiteralPath $currentPath -Force -ErrorAction Stop
            }
            catch {
                $errorCount++
                continue
            }

            foreach ($item in $items) {
                try {
                    $isReparsePoint = (
                        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
                    )

                    if ($isReparsePoint) {
                        $reparsePointCount++
                        continue
                    }

                    if ($item.PSIsContainer) {
                        $directories.Push($item.FullName)
                    }
                    else {
                        $totalBytes += [int64]$item.Length
                        $fileCount++
                    }
                }
                catch {
                    $errorCount++
                }
            }
        }
    }
    catch {
        $errorCount++
    }

    $endTime = Get-Date

    [PSCustomObject]@{
        Path = $Path
        Exists = $true
        SizeBytes = $totalBytes
        SizeGB = [math]::Round(($totalBytes / 1GB), 2)
        FileCount = $fileCount
        DirectoryCount = $directoryCount
        ErrorCount = $errorCount
        ReparsePointCount = $reparsePointCount
        DurationSeconds = [math]::Round(($endTime - $startTime).TotalSeconds, 2)
    }
}

# ============================================================
# PROFILE DISCOVERY
# ============================================================

function Get-WindowsUserProfiles {
    Write-Log -Message 'Discovering Windows user profiles.'

    $profileInstances = @(
        Get-CimInstance -ClassName Win32_UserProfile |
        Where-Object {
            -not [string]::IsNullOrWhiteSpace($_.LocalPath)
        }
    )

    $profileResults = @()

    foreach ($profileInstance in $profileInstances) {
        $profilePath = $profileInstance.LocalPath

        if (-not (Test-Path -LiteralPath $profilePath -PathType Container)) {
            continue
        }

        $directoryInfo = $null

        try {
            $directoryInfo = Get-Item -LiteralPath $profilePath -Force -ErrorAction Stop
        }
        catch {
            $directoryInfo = $null
        }

        $lastWriteTime = if ($null -ne $directoryInfo) {
            $directoryInfo.LastWriteTime
        }
        else {
            $null
        }

        $accountName = Resolve-SidToAccountName -SID $profileInstance.SID

        $management = Get-ProfileManagementClassification `
            -SID $profileInstance.SID `
            -Special ([bool]$profileInstance.Special)

        $profileStatistics = Get-DirectoryScan -Path $profilePath

        $profileResults += [PSCustomObject]@{
            Username = $accountName
            SID = $profileInstance.SID
            ProfilePath = $profilePath
            Loaded = [bool]$profileInstance.Loaded
            Special = [bool]$profileInstance.Special
            SizeBytes = $profileStatistics.SizeBytes
            SizeGB = $profileStatistics.SizeGB
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

# ============================================================
# PROFILE SELECTION
# ============================================================

function Select-Profile {
    param(
        [Parameter(Mandatory = $true)]
        [array]$Profiles
    )

    $usableProfiles = @($Profiles)

    if ($usableProfiles.Count -eq 0) {
        Write-Host ''
        Write-Host 'No Windows user profiles were found.' -ForegroundColor Yellow
        return $null
    }

    while ($true) {
        Clear-Host
        Write-Host ''
        Write-Host 'SELECT USER PROFILE' -ForegroundColor Cyan
        Write-Host '============================================'
        Write-Host ''

        for ($index = 0; $index -lt $usableProfiles.Count; $index++) {
            $profileEntry = $usableProfiles[$index]

            $status = if ($profileEntry.CanManage) {
                'Manageable'
            }
            else {
                $profileEntry.ManagementStatus
            }

            Write-Host (
                '[{0}] {1} ({2} GB) - {3}' -f
                ($index + 1),
                $profileEntry.Username,
                $profileEntry.SizeGB,
                $status
            )
        }

        Write-Host ''
        $selection = Read-Host 'Enter profile number or Q to cancel'

        if ($selection -match '^[Qq]$') {
            return $null
        }

        $number = 0

        if ([int]::TryParse($selection, [ref]$number)) {
            if ($number -ge 1 -and $number -le $usableProfiles.Count) {
                return $usableProfiles[$number - 1]
            }
        }

        Write-Host ''
        Write-Host 'Invalid selection.' -ForegroundColor Yellow
        Start-Sleep -Seconds 1
    }
}

# ============================================================
# PATH CLASSIFICATION
# ============================================================

function Get-PathClassification {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $normalizedPath = $Path.ToLowerInvariant()
    $normalizedName = $Name.ToLowerInvariant()

    if (
        $normalizedPath -like '*\appdata\local\temp' -or
        $normalizedPath -like '*\appdata\local\temp\*' -or
        $normalizedPath -like '*\appdata\local\crashdumps' -or
        $normalizedPath -like '*\appdata\local\crashdumps\*' -or
        $normalizedPath -like '*\appdata\local\microsoft\windows\wer' -or
        $normalizedPath -like '*\appdata\local\microsoft\windows\wer\*'
    ) {
        return 'Safe Cleanup'
    }

    if (
        $normalizedPath -like '*\appdata\local\google\*' -or
        $normalizedPath -like '*\appdata\local\microsoft\edge\*' -or
        $normalizedPath -like '*\appdata\local\microsoft\teams\*' -or
        $normalizedPath -like '*\appdata\local\packages\*' -or
        $normalizedPath -like '*\appdata\local\microsoft\windows\explorer\*'
    ) {
        return 'Review'
    }

    if ($normalizedName -eq 'appdata') {
        return 'Review'
    }

    if (
        $normalizedName -in @(
            'desktop',
            'documents',
            'downloads',
            'pictures',
            'videos',
            'music',
            'onedrive'
        )
    ) {
        return 'Preserve'
    }

    if (
        $normalizedName -in @(
            'ntuser.dat',
            'ntuser.dat.log1',
            'ntuser.dat.log2',
            'ntuser.ini'
        )
    ) {
        return 'Protected'
    }

    return 'Informational'
}

# ============================================================
# TOP-LEVEL ANALYSIS
# ============================================================

function Get-ProfileTopLevelAnalysis {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProfilePath
    )

    $results = @()

    if (-not (Test-Path -LiteralPath $ProfilePath -PathType Container)) {
        return $results
    }

    try {
        $items = Get-ChildItem -LiteralPath $ProfilePath -Force -ErrorAction Stop
    }
    catch {
        Write-Log -Message (
            'Unable to enumerate profile root: {0}' -f $_.Exception.Message
        ) -Level WARNING
        return $results
    }

    foreach ($item in $items) {
        $isReparsePoint = (
            ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
        )

        if ($isReparsePoint) {
            $results += [PSCustomObject]@{
                Name = $item.Name
                Path = $item.FullName
                Type = if ($item.PSIsContainer) { 'Directory' } else { 'File' }
                SizeBytes = [int64]0
                SizeGB = 0
                FileCount = 0
                DirectoryCount = 0
                ErrorCount = 0
                Classification = 'Protected'
                ReparsePoint = $true
            }
            continue
        }

        if ($item.PSIsContainer) {
            $statistics = Get-DirectoryScan -Path $item.FullName
            $classification = Get-PathClassification -Path $item.FullName -Name $item.Name

            $results += [PSCustomObject]@{
                Name = $item.Name
                Path = $item.FullName
                Type = 'Directory'
                SizeBytes = $statistics.SizeBytes
                SizeGB = $statistics.SizeGB
                FileCount = $statistics.FileCount
                DirectoryCount = $statistics.DirectoryCount
                ErrorCount = $statistics.ErrorCount
                Classification = $classification
                ReparsePoint = $false
            }
        }
        else {
            $fileSize = [int64]0

            try {
                $fileSize = [int64]$item.Length
            }
            catch {
                $fileSize = [int64]0
            }

            $classification = Get-PathClassification -Path $item.FullName -Name $item.Name

            $results += [PSCustomObject]@{
                Name = $item.Name
                Path = $item.FullName
                Type = 'File'
                SizeBytes = $fileSize
                SizeGB = [math]::Round(($fileSize / 1GB), 2)
                FileCount = 1
                DirectoryCount = 0
                ErrorCount = 0
                Classification = $classification
                ReparsePoint = $false
            }
        }
    }

    return $results
}

# ============================================================
# APPDATA ANALYSIS
# ============================================================

function Get-AppDataAnalysis {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProfilePath
    )

    $appDataPath = Join-Path -Path $ProfilePath -ChildPath 'AppData'
    $results = @()

    if (-not (Test-Path -LiteralPath $appDataPath -PathType Container)) {
        return $results
    }

    foreach ($locationName in @('Local', 'Roaming', 'LocalLow')) {
        $locationPath = Join-Path -Path $appDataPath -ChildPath $locationName

        if (-not (Test-Path -LiteralPath $locationPath -PathType Container)) {
            continue
        }

        $locationStatistics = Get-DirectoryScan -Path $locationPath

        $results += [PSCustomObject]@{
            Level = 1
            Name = $locationName
            Path = $locationPath
            SizeBytes = $locationStatistics.SizeBytes
            SizeGB = $locationStatistics.SizeGB
            FileCount = $locationStatistics.FileCount
            DirectoryCount = $locationStatistics.DirectoryCount
            ErrorCount = $locationStatistics.ErrorCount
            Classification = 'Review'
            Parent = 'AppData'
        }

        try {
            $children = Get-ChildItem `
                -LiteralPath $locationPath `
                -Force `
                -Directory `
                -ErrorAction Stop
        }
        catch {
            Write-Log -Message (
                'Unable to enumerate AppData location {0}: {1}' -f
                $locationPath,
                $_.Exception.Message
            ) -Level WARNING
            continue
        }

        foreach ($child in $children) {
            $isReparsePoint = (
                ($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
            )

            if ($isReparsePoint) {
                continue
            }

            $childStatistics = Get-DirectoryScan -Path $child.FullName
            $classification = Get-PathClassification `
                -Path $child.FullName `
                -Name $child.Name

            $results += [PSCustomObject]@{
                Level = 2
                Name = $child.Name
                Path = $child.FullName
                SizeBytes = $childStatistics.SizeBytes
                SizeGB = $childStatistics.SizeGB
                FileCount = $childStatistics.FileCount
                DirectoryCount = $childStatistics.DirectoryCount
                ErrorCount = $childStatistics.ErrorCount
                Classification = $classification
                Parent = $locationName
            }
        }
    }

    return $results
}

# ============================================================
# CLEANUP CANDIDATE DEFINITIONS
# ============================================================

function Get-CleanupCandidateAnalysis {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProfilePath
    )

    $candidateDefinitions = @(
        @{
            Name = 'User Temp'
            RelativePath = 'AppData\Local\Temp'
            Classification = 'Safe Cleanup'
            Reason = 'Temporary user application data.'
            CleanupLevel = 'Light'
        },
        @{
            Name = 'Crash Dumps'
            RelativePath = 'AppData\Local\CrashDumps'
            Classification = 'Safe Cleanup'
            Reason = 'Per-user application crash dump files.'
            CleanupLevel = 'Light'
        },
        @{
            Name = 'Windows Error Reporting'
            RelativePath = 'AppData\Local\Microsoft\Windows\WER'
            Classification = 'Safe Cleanup'
            Reason = 'Windows Error Reporting data.'
            CleanupLevel = 'Light'
        },
        @{
            Name = 'Explorer Cache'
            RelativePath = 'AppData\Local\Microsoft\Windows\Explorer'
            Classification = 'Review'
            Reason = 'Explorer cache contains operational state and thumbnails.'
            CleanupLevel = 'Deep'
        },
        @{
            Name = 'Google Application Data'
            RelativePath = 'AppData\Local\Google'
            Classification = 'Review'
            Reason = 'Application data may include caches, profiles, extensions, and settings.'
            CleanupLevel = 'Deep'
        },
        @{
            Name = 'Microsoft Edge Application Data'
            RelativePath = 'AppData\Local\Microsoft\Edge'
            Classification = 'Review'
            Reason = 'Browser data can include cache, profile state, extensions, and settings.'
            CleanupLevel = 'Deep'
        },
        @{
            Name = 'Windows Packages'
            RelativePath = 'AppData\Local\Packages'
            Classification = 'Review'
            Reason = 'Packaged application data must be handled selectively.'
            CleanupLevel = 'Deep'
        }
    )

    $results = @()

    foreach ($definition in $candidateDefinitions) {
        $targetPath = Join-Path `
            -Path $ProfilePath `
            -ChildPath $definition.RelativePath

        if (-not (Test-Path -LiteralPath $targetPath -PathType Container)) {
            continue
        }

        $statistics = Get-DirectoryScan -Path $targetPath

        $results += [PSCustomObject]@{
            Name = $definition.Name
            Path = $targetPath
            RelativePath = $definition.RelativePath
            SizeBytes = $statistics.SizeBytes
            SizeGB = $statistics.SizeGB
            FileCount = $statistics.FileCount
            DirectoryCount = $statistics.DirectoryCount
            ErrorCount = $statistics.ErrorCount
            Classification = $definition.Classification
            Reason = $definition.Reason
            CleanupLevel = $definition.CleanupLevel
            ReadOnly = $true
        }
    }

    return $results
}

# ============================================================
# PHASE 2.2 CLEANUP INTELLIGENCE
# ============================================================

function Get-CleanupRecommendations {
    param(
        [Parameter(Mandatory = $true)]
        [array]$Candidates
    )

    $recommendations = @()

    foreach ($candidate in $Candidates) {
        if ($candidate.SizeBytes -le 0) {
            continue
        }

        $action = switch ($candidate.Classification) {
            'Safe Cleanup' { 'Eligible' }
            'Review' { 'Review Required' }
            'Preserve' { 'Preserve' }
            'Protected' { 'Protected' }
            default { 'Informational' }
        }

        $confidence = switch ($candidate.Classification) {
            'Safe Cleanup' { 'High' }
            'Review' { 'Medium' }
            default { 'N/A' }
        }

        $recommendations += [PSCustomObject]@{
            Name = $candidate.Name
            Path = $candidate.Path
            SizeBytes = $candidate.SizeBytes
            SizeGB = $candidate.SizeGB
            Classification = $candidate.Classification
            Action = $action
            Confidence = $confidence
            CleanupLevel = $candidate.CleanupLevel
            Reason = $candidate.Reason
        }
    }

    return $recommendations
}

# ============================================================
# FULL PROFILE ANALYSIS v2.2
# ============================================================

function Invoke-ProfileAnalysisV22 {
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$ProfileInfo
    )

    if (-not $ProfileInfo.CanManage) {
        Write-Log -Message (
            'Profile analysis blocked: {0}; Reason: {1}' -f
            $ProfileInfo.Username,
            $ProfileInfo.ManagementReason
        ) -Level SECURITY
        return $null
    }

    $analysisStart = Get-Date

    Write-Log -Message (
        'Starting Phase 2.2 analysis: {0}' -f $ProfileInfo.Username
    )

    Write-Host ''
    Write-Host 'Analyzing profile...' -ForegroundColor Cyan
    Write-Host ('User : {0}' -f $ProfileInfo.Username)
    Write-Host ('Path : {0}' -f $ProfileInfo.ProfilePath)
    Write-Host ''

    Write-Host '[1/4] Scanning profile structure...' -ForegroundColor DarkCyan
    $topLevel = @(Get-ProfileTopLevelAnalysis -ProfilePath $ProfileInfo.ProfilePath)

    Write-Host '[2/4] Analyzing AppData...' -ForegroundColor DarkCyan
    $appData = @(Get-AppDataAnalysis -ProfilePath $ProfileInfo.ProfilePath)

    Write-Host '[3/4] Detecting cleanup candidates...' -ForegroundColor DarkCyan
    $cleanupCandidates = @(
        Get-CleanupCandidateAnalysis -ProfilePath $ProfileInfo.ProfilePath
    )

    Write-Host '[4/4] Building cleanup recommendations...' -ForegroundColor DarkCyan
    $recommendations = @(
        Get-CleanupRecommendations -Candidates $cleanupCandidates
    )

    $safeCleanupBytes = [int64]0
    $reviewBytes = [int64]0

    foreach ($recommendation in $recommendations) {
        if ($recommendation.Classification -eq 'Safe Cleanup') {
            $safeCleanupBytes += [int64]$recommendation.SizeBytes
        }
        elseif ($recommendation.Classification -eq 'Review') {
            $reviewBytes += [int64]$recommendation.SizeBytes
        }
    }

    $analysisEnd = Get-Date

    $totalErrors = 0

    foreach ($item in $topLevel) {
        $totalErrors += $item.ErrorCount
    }

    foreach ($item in $appData) {
        $totalErrors += $item.ErrorCount
    }

    foreach ($item in $cleanupCandidates) {
        $totalErrors += $item.ErrorCount
    }

    $analysis = [PSCustomObject]@{
        Version = '2.2.0'
        ReadOnly = $true
        Username = $ProfileInfo.Username
        SID = $ProfileInfo.SID
        ProfilePath = $ProfileInfo.ProfilePath
        ProfileSizeGB = $ProfileInfo.SizeGB
        ProfileLoaded = $ProfileInfo.Loaded
        TopLevel = $topLevel
        AppData = $appData
        CleanupCandidates = $cleanupCandidates
        Recommendations = $recommendations
        SafeCleanupBytes = $safeCleanupBytes
        SafeCleanupGB = [math]::Round(($safeCleanupBytes / 1GB), 2)
        ReviewBytes = $reviewBytes
        ReviewGB = [math]::Round(($reviewBytes / 1GB), 2)
        TotalScanErrors = $totalErrors
        Started = $analysisStart
        Completed = $analysisEnd
        DurationSeconds = [math]::Round(($analysisEnd - $analysisStart).TotalSeconds, 2)
    }

    $script:LastAnalysis = $analysis

    Write-Log -Message (
        'Phase 2.2 analysis completed: {0}; Safe: {1} GB; Review: {2} GB; Errors: {3}; Duration: {4}s' -f
        $analysis.Username,
        $analysis.SafeCleanupGB,
        $analysis.ReviewGB,
        $analysis.TotalScanErrors,
        $analysis.DurationSeconds
    ) -Level SUCCESS

    return $analysis
}

# ============================================================
# DRY RUN
# ============================================================

function Invoke-CleanupDryRun {
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Analysis,

        [ValidateSet('Light','Deep')]
        [string]$CleanupMode = 'Light'
    )

    Clear-Host

    Write-Host ''
    Write-Host 'CLEANUP DRY RUN' -ForegroundColor Cyan
    Write-Host '=================================================='
    Write-Host ''

    Write-Host ('User       : {0}' -f $Analysis.Username)
    Write-Host ('Profile    : {0}' -f $Analysis.ProfilePath)
    Write-Host ('Mode       : {0}' -f $CleanupMode)
    Write-Host ''

    $eligible = @(
        $Analysis.Recommendations |
        Where-Object {
            if ($CleanupMode -eq 'Light') {
                $_.Classification -eq 'Safe Cleanup' -and
                $_.CleanupLevel -eq 'Light'
            }
            else {
                $_.Classification -in @('Safe Cleanup','Review')
            }
        }
    )

    if ($eligible.Count -eq 0) {
        Write-Host 'No cleanup candidates match this mode.' -ForegroundColor Yellow
        Write-Host ''
        Write-Host 'DRY RUN ONLY - NO FILES WERE MODIFIED.' -ForegroundColor Green
        Write-Host ''
        return
    }

    $plannedBytes = [int64]0

    Write-Host 'PLANNED ACTIONS' -ForegroundColor Cyan
    Write-Host '--------------------------------------------------'

    foreach ($item in $eligible) {
        $plannedBytes += [int64]$item.SizeBytes

        $displayColor = if ($item.Classification -eq 'Safe Cleanup') {
            'Green'
        }
        else {
            'Yellow'
        }

        Write-Host (
            '[{0}] {1,-34} {2,8} GB' -f
            $item.Classification,
            $item.Name,
            $item.SizeGB
        ) -ForegroundColor $displayColor

        Write-Host (
            '     Path: {0}' -f
            $item.Path
        ) -ForegroundColor DarkGray

        Write-Host (
            '     Reason: {0}' -f
            $item.Reason
        ) -ForegroundColor DarkGray
    }

    Write-Host ''
    Write-Host 'DRY RUN SUMMARY' -ForegroundColor Cyan
    Write-Host '--------------------------------------------------'

    Write-Host (
        'Candidate Items : {0}' -f
        $eligible.Count
    )

    Write-Host (
        'Potential Space : {0} GB' -f
        ([math]::Round(($plannedBytes / 1GB), 2))
    ) -ForegroundColor Green

    Write-Host ''
    Write-Host 'IMPORTANT:' -ForegroundColor Yellow
    Write-Host 'This is a preview only.'
    Write-Host 'No files, folders, registry keys, or profiles were modified.'
    Write-Host ''
}

# ============================================================
# ANALYSIS REPORT
# ============================================================

function Show-ProfileAnalysisV22 {
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Analysis
    )

    Clear-Host

    Write-Host ''
    Write-Host 'WINDOWS PROFILE ANALYZER v2.2' -ForegroundColor Cyan
    Write-Host '=================================================='
    Write-Host ''

    Write-Host ('User              : {0}' -f $Analysis.Username)
    Write-Host ('Profile           : {0}' -f $Analysis.ProfilePath)
    Write-Host ('Profile Size      : {0} GB' -f $Analysis.ProfileSizeGB)
    Write-Host ('Profile Loaded    : {0}' -f $Analysis.ProfileLoaded)
    Write-Host ('Analysis Duration : {0} seconds' -f $Analysis.DurationSeconds)
    Write-Host ('Scan Errors       : {0}' -f $Analysis.TotalScanErrors)
    Write-Host ''

    Write-Host 'TOP-LEVEL STORAGE' -ForegroundColor Cyan
    Write-Host '--------------------------------------------------'

    $topLevelDirectories = @(
        $Analysis.TopLevel |
        Where-Object { $_.Type -eq 'Directory' } |
        Sort-Object -Property SizeBytes -Descending
    )

    foreach ($item in $topLevelDirectories) {
        $displayColor = switch ($item.Classification) {
            'Safe Cleanup' { 'Green' }
            'Review' { 'Yellow' }
            'Preserve' { 'White' }
            'Protected' { 'Magenta' }
            default { 'Gray' }
        }

        Write-Host (
            '{0,-24} {1,8} GB   [{2}]' -f
            $item.Name,
            $item.SizeGB,
            $item.Classification
        ) -ForegroundColor $displayColor
    }

    Write-Host ''
    Write-Host 'APPDATA STORAGE' -ForegroundColor Cyan
    Write-Host '--------------------------------------------------'

    $appDataLocations = @(
        $Analysis.AppData |
        Where-Object { $_.Level -eq 1 } |
        Sort-Object -Property SizeBytes -Descending
    )

    foreach ($location in $appDataLocations) {
        Write-Host (
            '+-- {0,-20} {1,8} GB' -f
            $location.Name,
            $location.SizeGB
        ) -ForegroundColor Yellow

        $children = @(
            $Analysis.AppData |
            Where-Object {
                $_.Level -eq 2 -and $_.Parent -eq $location.Name
            } |
            Sort-Object -Property SizeBytes -Descending
        )

        $displayChildren = @($children | Select-Object -First 10)

        foreach ($child in $displayChildren) {
            $displayColor = switch ($child.Classification) {
                'Safe Cleanup' { 'Green' }
                'Review' { 'Yellow' }
                'Preserve' { 'White' }
                'Protected' { 'Magenta' }
                default { 'Gray' }
            }

            Write-Host (
                '|   +-- {0,-18} {1,8} GB   [{2}]' -f
                $child.Name,
                $child.SizeGB,
                $child.Classification
            ) -ForegroundColor $displayColor
        }

        if ($children.Count -gt 10) {
            Write-Host (
                '|   `-- ... {0} additional directories' -f
                ($children.Count - 10)
            ) -ForegroundColor DarkGray
        }
    }

    Write-Host ''
    Write-Host 'CLEANUP INTELLIGENCE' -ForegroundColor Cyan
    Write-Host '--------------------------------------------------'

    $recommendations = @(
        $Analysis.Recommendations |
        Sort-Object -Property SizeBytes -Descending
    )

    if ($recommendations.Count -eq 0) {
        Write-Host 'No known cleanup candidates detected.' -ForegroundColor Gray
    }
    else {
        foreach ($item in $recommendations) {
            $displayColor = switch ($item.Classification) {
                'Safe Cleanup' { 'Green' }
                'Review' { 'Yellow' }
                default { 'Gray' }
            }

            Write-Host (
                '{0,-34} {1,8} GB   [{2}]' -f
                $item.Name,
                $item.SizeGB,
                $item.Classification
            ) -ForegroundColor $displayColor
        }
    }

    Write-Host ''
    Write-Host 'ANALYSIS SUMMARY' -ForegroundColor Cyan
    Write-Host '--------------------------------------------------'

    Write-Host (
        'Potential Safe Cleanup : {0} GB' -f
        $Analysis.SafeCleanupGB
    ) -ForegroundColor Green

    Write-Host (
        'Potential Review       : {0} GB' -f
        $Analysis.ReviewGB
    ) -ForegroundColor Yellow

    Write-Host (
        'Scan Errors            : {0}' -f
        $Analysis.TotalScanErrors
    )

    Write-Host ''
    Write-Host 'READ-ONLY ANALYSIS - NO FILES WERE MODIFIED.' -ForegroundColor Green
    Write-Host ''
}

# ============================================================
# EXPORT ANALYSIS
# ============================================================

function Export-LastAnalysis {
    if ($null -eq $script:LastAnalysis) {
        Write-Host ''
        Write-Host 'No analysis is currently available to export.' -ForegroundColor Yellow
        return
    }

    $safeName = ($script:LastAnalysis.Username -replace '[\\/:*?"<>|]', '_')
    $filePath = Join-Path $ExportDirectory (
        '{0}_Analysis_{1}.json' -f
        $safeName,
        (Get-Date -Format 'yyyyMMdd_HHmmss')
    )

    try {
        $script:LastAnalysis |
            ConvertTo-Json -Depth 10 |
            Set-Content -LiteralPath $filePath -Encoding UTF8

        Write-Log -Message (
            'Analysis exported: {0}' -f $filePath
        ) -Level SUCCESS

        Write-Host ''
        Write-Host 'Analysis exported successfully.' -ForegroundColor Green
        Write-Host $filePath
    }
    catch {
        Write-Log -Message (
            'Analysis export failed: {0}' -f $_.Exception.Message
        ) -Level ERROR

        Write-Host ''
        Write-Host (
            'Export failed: {0}' -f $_.Exception.Message
        ) -ForegroundColor Red
    }
}

# ============================================================
# SYSTEM INFORMATION
# ============================================================

function Show-SystemInformation {
    Clear-Host

    Write-Host ''
    Write-Host 'SYSTEM INFORMATION' -ForegroundColor Cyan
    Write-Host '=================================================='
    Write-Host ''

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $computer = Get-CimInstance -ClassName Win32_ComputerSystem

        Write-Host ('Computer Name : {0}' -f $env:COMPUTERNAME)
        Write-Host ('Current User  : {0}' -f $env:USERNAME)
        Write-Host ('OS            : {0}' -f $os.Caption)
        Write-Host ('Version       : {0}' -f $os.Version)
        Write-Host ('Build         : {0}' -f $os.BuildNumber)
        Write-Host ('Architecture  : {0}' -f $os.OSArchitecture)
        Write-Host ('Manufacturer  : {0}' -f $computer.Manufacturer)
        Write-Host ('Model         : {0}' -f $computer.Model)
    }
    catch {
        Write-Host (
            'Unable to retrieve system information: {0}' -f
            $_.Exception.Message
        ) -ForegroundColor Red
    }

    Write-Host ''
}

# ============================================================
# MAIN MENU
# ============================================================

function Show-MainMenu {
    while ($true) {
        Clear-Host

        Write-Host ''
        Write-Host '============================================' -ForegroundColor Cyan
        Write-Host '       WINDOWS PROFILE MAINTENANCE' -ForegroundColor Cyan
        Write-Host ('                 v{0}' -f $ScriptVersion) -ForegroundColor Cyan
        Write-Host '============================================' -ForegroundColor Cyan
        Write-Host ''

        Write-Host ('Administrator : {0}' -f (
            [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        ))

        if ($null -ne $script:LastAnalysis) {
            Write-Host (
                'Last Analysis : {0} ({1} GB)' -f
                $script:LastAnalysis.Username,
                $script:LastAnalysis.ProfileSizeGB
            ) -ForegroundColor DarkGray
        }

        Write-Host ''
        Write-Host '[1] System Information'
        Write-Host '[2] List User Profiles'
        Write-Host '[3] Profile Details'
        Write-Host '[4] Analyze Profile'
        Write-Host '[5] Cleanup Dry Run'
        Write-Host '[6] Export Last Analysis'
        Write-Host '[7] Exit'
        Write-Host ''

        $choice = Read-Host 'Select an option'

        switch ($choice) {
            '1' {
                Show-SystemInformation
                Read-Host 'Press Enter to continue'
            }

            '2' {
                Clear-Host
                Write-Host ''
                Write-Host 'WINDOWS USER PROFILES' -ForegroundColor Cyan
                Write-Host '============================================'
                Write-Host ''

                $profiles = @(Get-WindowsUserProfiles)

                foreach ($profileEntry in $profiles) {
                    $status = if ($profileEntry.Loaded) { 'LOADED' } else { 'Not Loaded' }

                    Write-Host ('User          : {0}' -f $profileEntry.Username)
                    Write-Host ('Path          : {0}' -f $profileEntry.ProfilePath)
                    Write-Host ('SID           : {0}' -f $profileEntry.SID)
                    Write-Host ('Size          : {0} GB' -f $profileEntry.SizeGB)
                    Write-Host ('Status        : {0}' -f $status)
                    Write-Host ('Management    : {0}' -f $profileEntry.ManagementStatus)
                    Write-Host ('Scan Errors   : {0}' -f $profileEntry.ScanErrorCount)
                    Write-Host '--------------------------------------------'
                }

                Read-Host 'Press Enter to continue'
            }

            '3' {
                $profiles = @(Get-WindowsUserProfiles)
                $selectedProfile = Select-Profile -Profiles $profiles

                if ($null -ne $selectedProfile) {
                    Clear-Host
                    Write-Host ''
                    Write-Host 'PROFILE DETAILS' -ForegroundColor Cyan
                    Write-Host '============================================'
                    Write-Host ''
                    Write-Host ('Username          : {0}' -f $selectedProfile.Username)
                    Write-Host ('SID               : {0}' -f $selectedProfile.SID)
                    Write-Host ('Path              : {0}' -f $selectedProfile.ProfilePath)
                    Write-Host ('Size              : {0} GB' -f $selectedProfile.SizeGB)
                    Write-Host ('Files             : {0:N0}' -f $selectedProfile.FileCount)
                    Write-Host ('Directories       : {0:N0}' -f $selectedProfile.DirectoryCount)
                    Write-Host ('Scan Errors       : {0:N0}' -f $selectedProfile.ScanErrorCount)
                    Write-Host ('Loaded            : {0}' -f $selectedProfile.Loaded)
                    Write-Host ('Special           : {0}' -f $selectedProfile.Special)
                    Write-Host ('Last Write        : {0}' -f $selectedProfile.LastWriteTime)
                    Write-Host ('Management Status : {0}' -f $selectedProfile.ManagementStatus)
                    Write-Host ('Management Reason : {0}' -f $selectedProfile.ManagementReason)
                    Write-Host ('Can Manage        : {0}' -f $selectedProfile.CanManage)
                    Write-Host ''
                }

                Read-Host 'Press Enter to continue'
            }

            '4' {
                $profiles = @(Get-WindowsUserProfiles)
                $selectedProfile = Select-Profile -Profiles $profiles

                if ($null -ne $selectedProfile) {
                    $analysis = Invoke-ProfileAnalysisV22 -ProfileInfo $selectedProfile

                    if ($null -ne $analysis) {
                        Show-ProfileAnalysisV22 -Analysis $analysis
                    }
                }

                Read-Host 'Press Enter to continue'
            }

            '5' {
                if ($null -eq $script:LastAnalysis) {
                    Write-Host ''
                    Write-Host 'Run Analyze Profile first.' -ForegroundColor Yellow
                    Read-Host 'Press Enter to continue'
                    continue
                }

                Clear-Host
                Write-Host ''
                Write-Host 'CLEANUP DRY RUN' -ForegroundColor Cyan
                Write-Host '=================================================='
                Write-Host ''
                Write-Host '[1] Light Cleanup Preview'
                Write-Host '[2] Deep Cleanup Preview'
                Write-Host '[Q] Cancel'
                Write-Host ''

                $dryRunChoice = Read-Host 'Select an option'

                switch ($dryRunChoice) {
                    '1' {
                        Invoke-CleanupDryRun `
                            -Analysis $script:LastAnalysis `
                            -CleanupMode Light
                        Read-Host 'Press Enter to continue'
                    }

                    '2' {
                        Invoke-CleanupDryRun `
                            -Analysis $script:LastAnalysis `
                            -CleanupMode Deep
                        Read-Host 'Press Enter to continue'
                    }

                    default {
                        # Cancel
                    }
                }
            }

            '6' {
                Export-LastAnalysis
                Read-Host 'Press Enter to continue'
            }

            '7' {
                Write-Log -Message 'Utility exited by administrator.'
                return
            }

            default {
                Write-Host ''
                Write-Host 'Invalid option.' -ForegroundColor Yellow
                Start-Sleep -Seconds 1
            }
        }
    }
}

# ============================================================
# START
# ============================================================

Write-Log -Message (
    'Windows Profile Maintenance Utility v{0} started.' -f
    $ScriptVersion
)

try {
    Show-MainMenu
}
catch {
    Write-Log -Message (
        'Unhandled error: {0}' -f $_.Exception.Message
    ) -Level ERROR

    Write-Host ''
    Write-Host 'An unexpected error occurred.' -ForegroundColor Red
    Write-Host ''
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ''
    Read-Host 'Press Enter to exit'
}
finally {
    Write-Log -Message 'Utility session ended.'
}
