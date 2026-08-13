#requires -Version 5.1

<#
.SYNOPSIS
    Windows Profile Maintenance & Reset Utility

.DESCRIPTION
    Phase 1 provides safe Windows user-profile discovery,
    management classification, system information,
    administrator validation, safety checks, and logging.

    IMPORTANT:
    Phase 1 is completely NON-DESTRUCTIVE.
    No profiles, files, registry keys, or user data are deleted.

.VERSION
    1.0.3

.PHASE
    1 - Discovery, Safety, Classification & Logging
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false)]
    [string]$User,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Menu", "Analyze")]
    [string]$Mode = "Menu"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ============================================================
# CONFIGURATION
# ============================================================

$Script:AppName = "WindowsProfileMaintenance"
$Script:Version = "1.0.3"

$Script:BaseDirectory = Join-Path `
    -Path $env:ProgramData `
    -ChildPath $Script:AppName

$Script:LogDirectory = Join-Path `
    -Path $Script:BaseDirectory `
    -ChildPath "Logs"

$Script:LogFile = Join-Path `
    -Path $Script:LogDirectory `
    -ChildPath ("{0}.log" -f (Get-Date -Format "yyyy-MM-dd"))

# ============================================================
# INITIALIZATION
# ============================================================

function Initialize-Environment {

    if (-not (Test-Path -LiteralPath $Script:BaseDirectory)) {

        New-Item `
            -Path $Script:BaseDirectory `
            -ItemType Directory `
            -Force |
            Out-Null
    }

    if (-not (Test-Path -LiteralPath $Script:LogDirectory)) {

        New-Item `
            -Path $Script:LogDirectory `
            -ItemType Directory `
            -Force |
            Out-Null
    }
}

# ============================================================
# LOGGING
# ============================================================

function Write-Log {

    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet(
            "INFO",
            "WARNING",
            "ERROR",
            "SUCCESS",
            "SECURITY"
        )]
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $logLine = "[{0}] [{1}] {2}" -f `
        $timestamp,
        $Level,
        $Message

    Add-Content `
        -LiteralPath $Script:LogFile `
        -Value $logLine `
        -Encoding UTF8

    switch ($Level) {

        "ERROR" {
            Write-Host $logLine -ForegroundColor Red
        }

        "WARNING" {
            Write-Host $logLine -ForegroundColor Yellow
        }

        "SUCCESS" {
            Write-Host $logLine -ForegroundColor Green
        }

        "SECURITY" {
            Write-Host $logLine -ForegroundColor Magenta
        }

        default {
            Write-Host $logLine -ForegroundColor Gray
        }
    }
}

# ============================================================
# ADMINISTRATOR VALIDATION
# ============================================================

function Test-IsAdministrator {

    $windowsIdentity = `
        [Security.Principal.WindowsIdentity]::GetCurrent()

    $windowsPrincipal = `
        New-Object Security.Principal.WindowsPrincipal(
            $windowsIdentity
        )

    return $windowsPrincipal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Assert-Administrator {

    if (-not (Test-IsAdministrator)) {

        Write-Host ""
        Write-Host `
            "ERROR: Administrator privileges are required." `
            -ForegroundColor Red

        Write-Host ""
        Write-Host `
            "Start PowerShell using:" `
            -ForegroundColor Yellow

        Write-Host `
            "Run as administrator" `
            -ForegroundColor Yellow

        Write-Host ""

        exit 1
    }

    Write-Log `
        -Message "Administrator privileges confirmed." `
        -Level "SUCCESS"
}

# ============================================================
# CURRENT WINDOWS IDENTITY
# ============================================================

function Get-CurrentIdentityInfo {

    $windowsIdentity = `
        [Security.Principal.WindowsIdentity]::GetCurrent()

    $accountName = $windowsIdentity.Name

    $accountParts = $accountName -split "\\", 2

    $domainName = ""
    $userName = $accountName

    if ($accountParts.Count -eq 2) {

        $domainName = $accountParts[0]
        $userName = $accountParts[1]
    }

    $userSid = ""

    if ($null -ne $windowsIdentity.User) {

        $userSid = $windowsIdentity.User.Value
    }

    [PSCustomObject]@{

        Name = $accountName

        Domain = $domainName

        Username = $userName

        SID = $userSid
    }
}

# ============================================================
# SYSTEM INFORMATION
# ============================================================

function Get-SystemInformation {

    $operatingSystem = Get-CimInstance `
        -ClassName Win32_OperatingSystem

    $computerSystem = Get-CimInstance `
        -ClassName Win32_ComputerSystem

    $currentIdentity = Get-CurrentIdentityInfo

    [PSCustomObject]@{

        ComputerName = $env:COMPUTERNAME

        WindowsVersion = $operatingSystem.Caption

        WindowsVersionNumber = $operatingSystem.Version

        WindowsBuild = $operatingSystem.BuildNumber

        Architecture = $operatingSystem.OSArchitecture

        PowerShellVersion = $PSVersionTable.PSVersion.ToString()

        CurrentUser = $currentIdentity.Name

        TotalMemoryGB = [math]::Round(
            ($computerSystem.TotalPhysicalMemory / 1GB),
            2
        )

        LastBootTime = $operatingSystem.LastBootUpTime
    }
}

function Show-SystemInformation {

    $systemInfo = Get-SystemInformation

    Write-Host ""
    Write-Host `
        "SYSTEM INFORMATION" `
        -ForegroundColor Cyan

    Write-Host "========================================"

    Write-Host (
        "Computer          : {0}" -f
        $systemInfo.ComputerName
    )

    Write-Host (
        "Windows           : {0}" -f
        $systemInfo.WindowsVersion
    )

    Write-Host (
        "Windows Version   : {0}" -f
        $systemInfo.WindowsVersionNumber
    )

    Write-Host (
        "Build             : {0}" -f
        $systemInfo.WindowsBuild
    )

    Write-Host (
        "Architecture      : {0}" -f
        $systemInfo.Architecture
    )

    Write-Host (
        "PowerShell        : {0}" -f
        $systemInfo.PowerShellVersion
    )

    Write-Host (
        "Current User      : {0}" -f
        $systemInfo.CurrentUser
    )

    Write-Host (
        "Memory            : {0} GB" -f
        $systemInfo.TotalMemoryGB
    )

    Write-Host (
        "Last Boot         : {0}" -f
        $systemInfo.LastBootTime
    )

    Write-Host ""
}

# ============================================================
# DIRECTORY SIZE
# ============================================================

function Get-DirectorySizeGB {

    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (
        Test-Path `
            -LiteralPath $Path `
            -PathType Container
    )) {

        return 0
    }

    try {

        $measurement = Get-ChildItem `
            -LiteralPath $Path `
            -Force `
            -File `
            -Recurse `
            -ErrorAction SilentlyContinue |
            Measure-Object `
                -Property Length `
                -Sum

        if ($null -eq $measurement) {
            return 0
        }

        if ($null -eq $measurement.Sum) {
            return 0
        }

        return [math]::Round(
            ($measurement.Sum / 1GB),
            2
        )
    }
    catch {

        return 0
    }
}

# ============================================================
# SID TO ACCOUNT NAME
# ============================================================

function Resolve-SidToAccountName {

    param(
        [Parameter(Mandatory = $true)]
        [string]$SID
    )

    try {

        $securityIdentifier = `
            New-Object System.Security.Principal.SecurityIdentifier(
                $SID
            )

        $account = $securityIdentifier.Translate(
            [System.Security.Principal.NTAccount]
        )

        return $account.Value
    }
    catch {

        return "Unknown"
    }
}

# ============================================================
# PROFILE MANAGEMENT CLASSIFICATION
# ============================================================

function Get-ProfileManagementClassification {

    param(
        [Parameter(Mandatory = $true)]
        [string]$SID,

        [Parameter(Mandatory = $true)]
        [bool]$Special
    )

    $currentIdentity = Get-CurrentIdentityInfo

    # --------------------------------------------------------
    # CURRENT USER
    # --------------------------------------------------------

    if ($SID -eq $currentIdentity.SID) {

        return [PSCustomObject]@{

            Status = "Blocked"

            Reason = "Current User"

            CanManage = $false
        }
    }

    # --------------------------------------------------------
    # WINDOWS SPECIAL / SYSTEM PROFILE
    # --------------------------------------------------------

    if ($Special) {

        return [PSCustomObject]@{

            Status = "Blocked"

            Reason = "System Profile"

            CanManage = $false
        }
    }

    # --------------------------------------------------------
    # NORMAL MANAGEABLE PROFILE
    # --------------------------------------------------------

    return [PSCustomObject]@{

        Status = "Manageable"

        Reason = "Eligible"

        CanManage = $true
    }
}

# ============================================================
# PROFILE DISCOVERY
# ============================================================

function Get-WindowsUserProfiles {

    Write-Log `
        -Message "Discovering Windows user profiles."

    $profileInstances = @(
        Get-CimInstance `
            -ClassName Win32_UserProfile |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace(
                    $_.LocalPath
                )
            }
    )

    $profileResults = @()

    foreach ($profileInstance in $profileInstances) {

        $profilePath = $profileInstance.LocalPath

        if (-not (
            Test-Path `
                -LiteralPath $profilePath `
                -PathType Container
        )) {

            continue
        }

        $directoryInfo = $null

        try {

            $directoryInfo = Get-Item `
                -LiteralPath $profilePath `
                -ErrorAction Stop
        }
        catch {

            $directoryInfo = $null
        }

        $lastWriteTime = $null

        if ($null -ne $directoryInfo) {

            $lastWriteTime = $directoryInfo.LastWriteTime
        }

        $profileSizeGB = Get-DirectorySizeGB `
            -Path $profilePath

        $accountName = Resolve-SidToAccountName `
            -SID $profileInstance.SID

        $management = Get-ProfileManagementClassification `
            -SID $profileInstance.SID `
            -Special ([bool]$profileInstance.Special)

        # ----------------------------------------------------
        # Security events are logged ONCE during discovery.
        # ----------------------------------------------------

        if (-not $management.CanManage) {

            Write-Log `
                -Message (
                    "Blocked profile: {0}; Reason: {1}; SID: {2}" -f
                    $accountName,
                    $management.Reason,
                    $profileInstance.SID
                ) `
                -Level "SECURITY"
        }

        $profileResults += [PSCustomObject]@{

            Username = $accountName

            SID = $profileInstance.SID

            ProfilePath = $profilePath

            Loaded = [bool]$profileInstance.Loaded

            Special = [bool]$profileInstance.Special

            SizeGB = $profileSizeGB

            LastWriteTime = $lastWriteTime

            ManagementStatus = $management.Status

            ManagementReason = $management.Reason

            CanManage = $management.CanManage
        }
    }

    Write-Log `
        -Message (
            "Discovered {0} profile(s)." -f
            $profileResults.Count
        ) `
        -Level "SUCCESS"

    return $profileResults
}

# ============================================================
# PROFILE TABLE
# ============================================================

function Show-ProfileTable {

    param(
        [Parameter(Mandatory = $true)]
        [array]$Profiles
    )

    Write-Host ""
    Write-Host `
        "WINDOWS USER PROFILES" `
        -ForegroundColor Cyan

    Write-Host "========================================"
    Write-Host ""

    if ($Profiles.Count -eq 0) {

        Write-Host `
            "No profiles found." `
            -ForegroundColor Yellow

        Write-Host ""

        return
    }

    $displayIndex = 1

    foreach ($profileInfo in $Profiles) {

        # ----------------------------------------------------
        # Status text
        # ----------------------------------------------------

        $loadedText = if ($profileInfo.Loaded) {
            "LOADED"
        }
        else {
            "Not Loaded"
        }

        # ----------------------------------------------------
        # Management display
        # ----------------------------------------------------

        if ($profileInfo.CanManage) {

            $managementText = "Manageable"
            $managementColor = "Green"
        }
        else {

            $managementText = "Blocked - {0}" -f `
                $profileInfo.ManagementReason

            $managementColor = "DarkYellow"
        }

        Write-Host (
            "[{0}] {1}" -f
            $displayIndex,
            $profileInfo.Username
        ) -ForegroundColor White

        Write-Host (
            "    Path       : {0}" -f
            $profileInfo.ProfilePath
        )

        Write-Host (
            "    SID        : {0}" -f
            $profileInfo.SID
        )

        Write-Host (
            "    Size       : {0} GB" -f
            $profileInfo.SizeGB
        )

        Write-Host (
            "    Last Write : {0}" -f
            $profileInfo.LastWriteTime
        )

        Write-Host (
            "    Status     : {0}" -f
            $loadedText
        )

        if ($profileInfo.Special) {

            Write-Host `
                "    Type       : SPECIAL"
        }

        Write-Host `
            ("    Management : {0}" -f $managementText) `
            -ForegroundColor $managementColor

        Write-Host ""

        $displayIndex++
    }
}

# ============================================================
# PROFILE DETAILS
# ============================================================

function Show-ProfileDetails {

    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$ProfileInfo
    )

    Write-Host ""
    Write-Host `
        "PROFILE ANALYSIS" `
        -ForegroundColor Cyan

    Write-Host "========================================"

    Write-Host (
        "Username           : {0}" -f
        $ProfileInfo.Username
    )

    Write-Host (
        "SID                : {0}" -f
        $ProfileInfo.SID
    )

    Write-Host (
        "Profile Path       : {0}" -f
        $ProfileInfo.ProfilePath
    )

    Write-Host (
        "Profile Size       : {0} GB" -f
        $ProfileInfo.SizeGB
    )

    Write-Host (
        "Last Write         : {0}" -f
        $ProfileInfo.LastWriteTime
    )

    Write-Host (
        "Loaded             : {0}" -f
        $ProfileInfo.Loaded
    )

    Write-Host (
        "Special            : {0}" -f
        $ProfileInfo.Special
    )

    Write-Host (
        "Management Status  : {0}" -f
        $ProfileInfo.ManagementStatus
    )

    Write-Host (
        "Management Reason  : {0}" -f
        $ProfileInfo.ManagementReason
    )

    Write-Host (
        "Can Manage         : {0}" -f
        $ProfileInfo.CanManage
    )

    Write-Host (
        "Current User       : {0}" -f
        (Get-CurrentIdentityInfo).Name
    )

    Write-Host ""

    if ($ProfileInfo.CanManage) {

        Write-Host `
            "Management Status : SAFE TO TARGET" `
            -ForegroundColor Green
    }
    else {

        Write-Host `
            "Management Status : BLOCKED" `
            -ForegroundColor Red
    }

    Write-Host ""
}

# ============================================================
# PROFILE RESOLUTION
# ============================================================

function Resolve-TargetProfile {

    param(
        [Parameter(Mandatory = $true)]
        [array]$Profiles,

        [Parameter(Mandatory = $true)]
        [string]$TargetUser
    )

    $normalizedUser = $TargetUser.Trim()

    $matchedProfile = $Profiles |
        Where-Object {

            $_.Username -ieq $normalizedUser -or
            $_.Username -like "*\$normalizedUser"
        } |
        Select-Object -First 1

    if ($null -eq $matchedProfile) {

        Write-Log `
            -Message (
                "Profile not found for user: {0}" -f
                $TargetUser
            ) `
            -Level "ERROR"

        return $null
    }

    return $matchedProfile
}

# ============================================================
# INTERACTIVE PROFILE SELECTION
# ============================================================

function Select-Profile {

    param(
        [Parameter(Mandatory = $true)]
        [array]$Profiles
    )

    $selectableProfiles = @(
        $Profiles |
            Where-Object {
                $_.CanManage
            }
    )

    if ($selectableProfiles.Count -eq 0) {

        Write-Host ""
        Write-Host `
            "No manageable profiles were found." `
            -ForegroundColor Yellow

        return $null
    }

    Write-Host ""
    Write-Host `
        "SELECT USER PROFILE" `
        -ForegroundColor Cyan

    Write-Host "========================================"

    for (
        $index = 0;
        $index -lt $selectableProfiles.Count;
        $index++
    ) {

        $profileInfo = $selectableProfiles[$index]

        Write-Host (
            "[{0}] {1} ({2} GB)" -f
            ($index + 1),
            $profileInfo.Username,
            $profileInfo.SizeGB
        )
    }

    Write-Host ""

    while ($true) {

        $selection = Read-Host `
            "Enter profile number or Q to cancel"

        if ($selection -match "^[Qq]$") {

            return $null
        }

        $selectionNumber = 0

        $isNumber = [int]::TryParse(
            $selection,
            [ref]$selectionNumber
        )

        if (
            $isNumber -and
            $selectionNumber -ge 1 -and
            $selectionNumber -le $selectableProfiles.Count
        ) {

            return $selectableProfiles[
                $selectionNumber - 1
            ]
        }

        Write-Host `
            "Invalid selection." `
            -ForegroundColor Yellow
    }
}

# ============================================================
# DIRECT ANALYSIS
# ============================================================

function Invoke-DirectAnalysis {

    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetUser
    )

    Write-Log `
        -Message (
            "Direct analysis requested for user: {0}" -f
            $TargetUser
        )

    $profiles = @(Get-WindowsUserProfiles)

    $profileInfo = Resolve-TargetProfile `
        -Profiles $profiles `
        -TargetUser $TargetUser

    if ($null -eq $profileInfo) {

        return
    }

    Show-ProfileDetails `
        -ProfileInfo $profileInfo
}

# ============================================================
# MAIN MENU
# ============================================================

function Show-MainMenu {

    while ($true) {

        Clear-Host

        Write-Host ""
        Write-Host `
            "==================================================" `
            -ForegroundColor Cyan

        Write-Host `
            "       WINDOWS PROFILE MAINTENANCE" `
            -ForegroundColor Cyan

        Write-Host (
            "                    v{0}" -f
            $Script:Version
        ) -ForegroundColor DarkCyan

        Write-Host `
            "==================================================" `
            -ForegroundColor Cyan

        Write-Host ""

        Write-Host (
            "Administrator : {0}" -f
            (Get-CurrentIdentityInfo).Name
        )

        Write-Host ""

        Write-Host "[1] System Information"
        Write-Host "[2] List User Profiles"
        Write-Host "[3] Analyze User Profile"
        Write-Host "[4] Exit"

        Write-Host ""

        $menuSelection = Read-Host "Select an option"

        switch ($menuSelection) {

            "1" {

                Show-SystemInformation

                Read-Host `
                    "Press Enter to continue"
            }

            "2" {

                $profiles = @(Get-WindowsUserProfiles)

                Show-ProfileTable `
                    -Profiles $profiles

                Read-Host `
                    "Press Enter to continue"
            }

            "3" {

                $profiles = @(Get-WindowsUserProfiles)

                $profileInfo = Select-Profile `
                    -Profiles $profiles

                if ($null -ne $profileInfo) {

                    Show-ProfileDetails `
                        -ProfileInfo $profileInfo
                }

                Read-Host `
                    "Press Enter to continue"
            }

            "4" {

                Write-Log `
                    -Message "Administrator exited utility."

                return
            }

            default {

                Write-Host ""

                Write-Host `
                    "Invalid option." `
                    -ForegroundColor Yellow

                Start-Sleep -Seconds 1
            }
        }
    }
}

# ============================================================
# APPLICATION ENTRY POINT
# ============================================================

try {

    Initialize-Environment

    Write-Log `
        -Message (
            "Starting {0} version {1}." -f
            $Script:AppName,
            $Script:Version
        )

    Assert-Administrator

    $systemInfo = Get-SystemInformation

    Write-Log `
        -Message (
            "Computer: {0}; Windows: {1}; Build: {2}" -f
            $systemInfo.ComputerName,
            $systemInfo.WindowsVersion,
            $systemInfo.WindowsBuild
        )

    $currentIdentity = Get-CurrentIdentityInfo

    Write-Log `
        -Message (
            "Current administrator: {0}" -f
            $currentIdentity.Name
        )

    if (-not [string]::IsNullOrWhiteSpace($User)) {

        Invoke-DirectAnalysis `
            -TargetUser $User
    }
    else {

        Show-MainMenu
    }

    Write-Log `
        -Message "Utility terminated normally." `
        -Level "SUCCESS"
}
catch {

    $errorMessage = $_.Exception.Message

    try {

        Write-Log `
            -Message (
                "Unhandled error: {0}" -f
                $errorMessage
            ) `
            -Level "ERROR"
    }
    catch {
        # Logging may not be available during very early startup.
    }

    Write-Host ""
    Write-Host `
        "An unexpected error occurred." `
        -ForegroundColor Red

    Write-Host ""
    Write-Host `
        $errorMessage `
        -ForegroundColor Red

    Write-Host ""

    exit 1
}