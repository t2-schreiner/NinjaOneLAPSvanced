<#
.SYNOPSIS
    NinjaOne LAPS + local administrator audit / reporting script.

.DESCRIPTION
    This script is designed to be executed from NinjaOne RMM as a
    PowerShell automation. It performs three tasks:

      1. LAPS password rotation
         - Creates (or updates) a dedicated local administrator account.
         - Generates a complex random password using a cryptographically
           secure RNG with rejection sampling (no modulo bias).
         - Writes the resulting username and password to NinjaOne
           custom fields so they can be retrieved from the device record.

      2. Local administrator audit report (WYSIWYG)
         - Enumerates every member of the local "Administrators" group.
         - Builds a styled HTML report and writes it to a NinjaOne
           WYSIWYG custom field.
         - Authorized admins (defined in a separate custom field as a
           comma separated list) are highlighted in green.
         - Unauthorized admins are highlighted in red.

      3. Alert flag
         - When at least one unauthorized administrator is detected, a
           checkbox custom field is set to TRUE so that a NinjaOne
           condition can raise an alarm.
         - On script failure the same flag is set so monitoring is never
           silently broken.

.NOTES
    Required NinjaOne custom fields (names are configurable below):

        LAPSuser                      (Text)         - secure / role scoped
        LAPSpw                        (Secure)       - secure / role scoped
        LAPSlocalAdminsReport         (WYSIWYG)
        LAPSauthorizedLocalAdmins     (Text)         - comma separated list
        LAPSunauthorizedAdminsFound   (Checkbox)     - used to trigger alarm
        LAPSchangelog                 (Multi-line)   - automation must have
                                                       READ + WRITE permission
                                                       (per-device run history)

    The script must run as SYSTEM (the default for NinjaOne scripts)
    or as a local administrator.

    Audit log:
        A structured audit log of every relevant action is mirrored to
        %ProgramData%\NinjaOneLAPS\audit.log (rotated at 1 MB, last
        5 files retained) so security events stay traceable even if the
        NinjaOne activity feed is unavailable.
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region ====================== Script variables ==============================
# You can modify these settings as needed.

# --- LAPS account ---------------------------------------------------------
# The script always manages a dedicated local administrator account
# (named below). The built-in Administrator (RID 500) is intentionally
# never used as the LAPS-managed account; it is disabled instead when
# DisableNativeAdmin is on (see below).
$NewAdminUsername        = 'LAPSadmin'
$PasswordLength          = 20           # total password length (>= 12)

# --- NinjaOne custom field names -----------------------------------------
$CF_LapsUsername      = 'LAPSuser'             # text / secure
$CF_LapsPassword      = 'LAPSpw'             # secure
$CF_AdminsReport      = 'LAPSlocalAdminsReport'        # WYSIWYG
$CF_AuthorizedAdmins  = 'LAPSauthorizedLocalAdmins'    # text (comma separated)
$CF_UnauthorizedFlag  = 'LAPSunauthorizedAdminsFound'  # checkbox (alert trigger)
$CF_Changelog         = 'LAPSchangelog'                # multiline text (per-device run history)

# --- Changelog -----------------------------------------------------------
# Append a short, human-readable history of the actions performed by
# each run to the NinjaOne multiline custom field $CF_Changelog. The
# automation must have *read and write* permission on this field
# because every run reads the previous content, appends the new
# entries from the current run, trims to $ChangelogMaxLines and writes
# the result back.
#
# $ChangelogEnabled        - master on/off switch.
# $ChangelogCategories     - whitelist of event categories that are
#                            written to the changelog. Categories not
#                            listed here are silently dropped. Known
#                            categories (case-insensitive):
#                              PasswordRotation     - LAPS password rotated
#                              RemovedAdmin         - account removed from
#                                                     local Administrators
#                              DisabledNativeAdmin  - built-in Administrator
#                                                     (RID 500) disabled
#                              UnauthorizedDetected - at least one
#                                                     unauthorized local
#                                                     admin still present
#                              Error                - unhandled exception
# $ChangelogMaxLines       - maximum number of entry lines kept in the
#                            field. When the combined (existing + new)
#                            line count exceeds the limit, the OLDEST
#                            lines are trimmed first so the field never
#                            grows unbounded.
$ChangelogEnabled    = $true
$ChangelogCategories = @(
    'PasswordRotation'
    'RemovedAdmin'
    'DisabledNativeAdmin'
    'UnauthorizedDetected'
    'Error'
)
$ChangelogMaxLines   = 50

# --- Audit log -----------------------------------------------------------
$AuditLogDirectory  = Join-Path $env:ProgramData 'NinjaOneLAPS'
$AuditLogPath       = Join-Path $AuditLogDirectory 'audit.log'
$AuditLogMaxBytes   = 1MB
$AuditLogMaxBackups = 5

# --- Well-known SIDs (used for localization-safe checks) -----------------
$Script:SID_BuiltinAdministrators = 'S-1-5-32-544'  # local Administrators group
$Script:WellKnownAdminGroupRids   = @(
    '512'  # Domain Admins
    '519'  # Enterprise Admins
    '518'  # Schema Admins
)

# Cache for the localized name of the built-in Administrators group.
# Initialized here so the StrictMode "variable not set" error cannot
# fire when Get-AdministratorsGroupName probes the cache on first call.
$Script:__AdminsGroupName = $null

# --- NinjaOne script variables (set in the script editor) ----------------
# "Mode" is a dropdown script variable with the following options:
#     All Functions     (default - runs everything)
#     Report Only       (only enumerates local admins and updates the report)
#     Password Rotate   (only rotates the LAPS password)
# If the variable is missing or empty, "All Functions" is assumed.
#
# "RemoveUnauthorizedAdminsScope" is a dropdown script variable that
# controls which kinds of unauthorized local admins are eligible for
# automatic removal from the local Administrators group:
#     Disabled         - never remove, only report
#     Local Only       - (default) remove only local SAM accounts/groups
#     Local and Domain - remove local + Active Directory principals
#     All              - remove local + AD + Entra ID + Microsoft Account principals
# Principals whose scope cannot be determined ('Unknown') are NEVER
# auto-removed regardless of this setting. The built-in Domain/Enterprise/
# Schema Admins groups and the managed LAPS account are always protected
# from automatic removal. The built-in Administrator (RID 500) is never
# removed from the local Administrators group either - it is *disabled*
# instead when "DisableNativeAdmin" is on (see below).
#
# "DisableNativeAdmin" is a checkbox script variable. When checked
# (default: ON) and the built-in Administrator account (RID 500) is
# enabled, the script disables it. An active built-in Administrator is
# a recurring finding in security audits (CIS Benchmark "Accounts:
# Administrator account status"). The built-in is never the LAPS-managed
# account, so disabling it is always safe.
$Mode                          = $env:Mode
$RemoveUnauthorizedAdminsScope = $env:RemoveUnauthorizedAdminsScope
$DisableNativeAdmin            = $env:DisableNativeAdmin
#endregion ===================================================================


#region ====================== Audit logging =================================

function Initialize-AuditLog {
    <#
        Ensures the audit log directory exists and rotates the log file
        when it exceeds $AuditLogMaxBytes. Rotation keeps at most
        $AuditLogMaxBackups historical files (audit.log.1 .. .N).
    #>
    if (-not (Test-Path -LiteralPath $AuditLogDirectory)) {
        try   { New-Item -ItemType Directory -Path $AuditLogDirectory -Force | Out-Null }
        catch { return }  # logging is best-effort; never fail the script
    }

    if (-not (Test-Path -LiteralPath $AuditLogPath)) { return }

    try {
        $size = (Get-Item -LiteralPath $AuditLogPath).Length
        if ($size -lt $AuditLogMaxBytes) { return }

        for ($i = $AuditLogMaxBackups; $i -ge 1; $i--) {
            $src = "$AuditLogPath.$i"
            $dst = "$AuditLogPath.$($i + 1)"
            if (Test-Path -LiteralPath $src) {
                if ($i -eq $AuditLogMaxBackups) { Remove-Item -LiteralPath $src -Force -ErrorAction SilentlyContinue }
                else                            { Move-Item   -LiteralPath $src -Destination $dst -Force -ErrorAction SilentlyContinue }
            }
        }
        Move-Item -LiteralPath $AuditLogPath -Destination "$AuditLogPath.1" -Force -ErrorAction SilentlyContinue
    }
    catch {
        # Logging must never break the script.
        $null = $_
    }
}

function Write-AuditLog {
    <#
        Structured audit log writer. Emits to the console using the
        appropriate stream and mirrors the message to the audit log file.
        Severity is one of: INFO, WARN, ERROR, SECURITY.
    #>
    param(
        [Parameter(Mandatory = $true)] [string] $Message,
        [ValidateSet('INFO','WARN','ERROR','SECURITY')]
        [string] $Severity = 'INFO'
    )

    $timestamp = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffzzz')
    $line      = '{0} [{1,-8}] [{2}] {3}' -f $timestamp, $Severity, $env:COMPUTERNAME, $Message

    switch ($Severity) {
        'INFO'     { Write-Host    $line -ForegroundColor Gray }
        'WARN'     { Write-Warning $Message }
        'ERROR'    { Write-Host    $line -ForegroundColor Red }
        'SECURITY' { Write-Host    $line -ForegroundColor Yellow }
    }

    try {
        Add-Content -LiteralPath $AuditLogPath -Value $line -Encoding UTF8 -ErrorAction Stop
    }
    catch {
        # Best-effort. Do not throw from the logger.
        $null = $_
    }
}
#endregion ===================================================================


#region ====================== Changelog =====================================
# Per-device, per-run history that is mirrored to a NinjaOne multi-line
# custom field ($CF_Changelog). Entries are buffered in memory during
# the run and flushed once at the end (also on failure, from the
# finally block) so we touch the custom field exactly once per run.

# Buffer of changelog entries collected during the current run.
# Initialized here so StrictMode does not trip when the buffer is
# probed before the first Add-ChangelogEntry call.
$Script:__ChangelogEntries = New-Object System.Collections.Generic.List[string]

function Add-ChangelogEntry {
    <#
        Records a single changelog event for the current run. The entry
        is dropped silently when:
          * the changelog feature is disabled, or
          * the supplied -Category is not in $ChangelogCategories.

        The format is intentionally plain text (one line per event) so
        it renders well in NinjaOne's multi-line text custom field:
            [yyyy-MM-dd HH:mm:ss] [Category] message

        Never throws - logging-style helpers must not break the script.
    #>
    param(
        [Parameter(Mandatory = $true)] [string] $Category,
        [Parameter(Mandatory = $true)] [string] $Message
    )

    try {
        if (-not $ChangelogEnabled) { return }
        if (-not $ChangelogCategories -or $ChangelogCategories.Count -eq 0) { return }

        $match = $false
        foreach ($c in $ChangelogCategories) {
            if ($c -and ($c -ieq $Category)) { $match = $true; break }
        }
        if (-not $match) { return }

        # Collapse newlines so a single event always occupies a single
        # line in the multi-line custom field (keeps the trim-by-line
        # semantics deterministic).
        $flat = ($Message -replace '\r?\n', ' ').Trim()
        $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        $line  = '[{0}] [{1}] {2}' -f $stamp, $Category, $flat

        $null = $Script:__ChangelogEntries.Add($line)
    }
    catch {
        $null = $_
    }
}

function Write-LapsChangelog {
    <#
        Reads the existing $CF_Changelog content, appends the entries
        buffered for the current run, trims the result to
        $ChangelogMaxLines (oldest lines drop off the top) and writes
        it back to NinjaOne.

        The buffer is cleared after a successful write so a second call
        within the same process does not duplicate entries.

        Returns silently when the feature is disabled, when the buffer
        is empty, or when neither Ninja-Property-Get nor Ninja-Property-Set
        is available (e.g. local debugging).
    #>
    if (-not $ChangelogEnabled) { return }
    if (-not $Script:__ChangelogEntries -or $Script:__ChangelogEntries.Count -eq 0) { return }

    try {
        # Read existing content (best-effort - a missing/empty field is
        # treated as "start fresh").
        $existing = $null
        try { $existing = Read-LapsCustomField -Name $CF_Changelog } catch { $null = $_ }

        $existingLines = @()
        if ($existing) {
            # Ninja-Property-Get returns multi-line custom field values as
            # a string[] (one element per line). A naive [string] cast
            # would join the array using $OFS (default: a single space),
            # collapsing all previously stored entries onto a single line
            # before the split-on-newline below. Join on a real newline so
            # the subsequent split correctly separates each entry, and
            # also handle the case where a single string with embedded
            # newlines is returned.
            if ($existing -is [array]) {
                $existingText = [string]::Join("`n", @($existing | ForEach-Object { [string]$_ }))
            }
            else {
                $existingText = [string]$existing
            }
            $existingLines = @($existingText -split "`r?`n" | Where-Object { $_ -ne $null -and $_.Length -gt 0 })
        }

        $combined = New-Object System.Collections.Generic.List[string]
        foreach ($l in $existingLines)              { $null = $combined.Add($l) }
        foreach ($l in $Script:__ChangelogEntries)  { $null = $combined.Add($l) }

        # Cap the on-disk size: drop the oldest lines first so the most
        # recent run is always preserved.
        $maxLines = [int]$ChangelogMaxLines
        if ($maxLines -le 0) { $maxLines = 500 }
        if ($combined.Count -gt $maxLines) {
            $skip = $combined.Count - $maxLines
            $combined.RemoveRange(0, $skip)
        }

        Write-LapsCustomField -Name $CF_Changelog -Value ($combined -join "`r`n")

        $Script:__ChangelogEntries.Clear()
    }
    catch {
        Write-AuditLog -Severity WARN -Message "Failed to write changelog custom field '$CF_Changelog': $($_.Exception.Message)"
    }
}
#endregion ===================================================================


#region ====================== Helper functions ==============================

# Cryptographically secure random number generator, created once and
# reused across the script. Disposed in the finally block of Main.
$Script:Rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()

function Get-SecureIndex {
    <#
        Returns a uniformly distributed integer in [0, Max) using the
        process-wide CSPRNG with rejection sampling on a 4-byte unsigned
        integer to avoid modulo bias.
    #>
    param([Parameter(Mandatory = $true)][int] $Max)

    if ($Max -le 0) { throw "Get-SecureIndex: Max must be > 0 (got $Max)." }

    $buffer = New-Object byte[] 4
    $limit  = [uint32]([math]::Floor([uint32]::MaxValue / $Max) * $Max)
    while ($true) {
        $Script:Rng.GetBytes($buffer)
        $value = [System.BitConverter]::ToUInt32($buffer, 0)
        if ($value -lt $limit) { return [int]($value % [uint32]$Max) }
    }
}

function Get-SecureChar {
    param([Parameter(Mandatory = $true)][char[]] $Pool)
    return $Pool[(Get-SecureIndex -Max $Pool.Length)]
}

function New-ComplexPassword {
    <#
        Generates a random alphanumeric password of the requested length
        and guarantees at least one uppercase, one lowercase, one digit
        and one special character so that Windows complexity rules are
        always satisfied.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [ValidateRange(12, 256)]
        [int] $Length
    )

    $upper   = [char[]]'ABCDEFGHJKLMNPQRSTUVWXYZ'
    $lower   = [char[]]'abcdefghijkmnpqrstuvwxyz'
    $digits  = [char[]]'23456789'
    $special = [char[]]'!@#$%&*-_=+?'
    $all     = $upper + $lower + $digits + $special

    # Guarantee at least one character from each pool.
    $required = @(
        (Get-SecureChar -Pool $upper)
        (Get-SecureChar -Pool $lower)
        (Get-SecureChar -Pool $digits)
        (Get-SecureChar -Pool $special)
    )

    $remaining = for ($i = 0; $i -lt ($Length - $required.Count); $i++) {
        Get-SecureChar -Pool $all
    }

    # Fisher-Yates shuffle using the CSPRNG so the required characters
    # are not always at the front and order is unbiased.
    $chars = @($required + $remaining)
    for ($i = $chars.Length - 1; $i -gt 0; $i--) {
        $j         = Get-SecureIndex -Max ($i + 1)
        $tmp       = $chars[$i]
        $chars[$i] = $chars[$j]
        $chars[$j] = $tmp
    }

    return -join $chars
}

function Write-LapsCustomField {
    <#
        Thin wrapper around Ninja-Property-Set / Ninja-Property-Set-Piped
        that gracefully degrades when the script is executed outside of a
        NinjaOne agent (for local testing).

        Note: Deliberately *not* named "Set-NinjaProperty" because the
        NinjaOne agent ships its own command with that name whose
        parameter set does not include -Piped, which would shadow this
        function and break the WYSIWYG report write.
    #>
    param (
        [Parameter(Mandatory = $true)] [string] $Name,
        [Parameter(Mandatory = $true)] [AllowEmptyString()] [object] $Value,
        [switch] $Piped
    )

    if (-not (Get-Command Ninja-Property-Set -ErrorAction SilentlyContinue)) {
        $valueTypeName = if ($null -eq $Value) { 'null' } else { $Value.GetType().Name }
        Write-AuditLog -Severity INFO -Message "[DryRun] Ninja-Property-Set $Name = <$valueTypeName>"
        return
    }

    try {
        if ($Piped) {
            $Value | Ninja-Property-Set-Piped $Name | Out-Null
        }
        else {
            Ninja-Property-Set $Name $Value | Out-Null
        }
    }
    catch {
        Write-AuditLog -Severity WARN -Message "Failed to write NinjaOne custom field '$Name': $($_.Exception.Message)"
    }
}

function Read-LapsCustomField {
    param ([Parameter(Mandatory = $true)] [string] $Name)

    if (-not (Get-Command Ninja-Property-Get -ErrorAction SilentlyContinue)) {
        Write-AuditLog -Severity INFO -Message "[DryRun] Ninja-Property-Get $Name"
        return $null
    }

    try   { return (Ninja-Property-Get $Name) }
    catch {
        Write-AuditLog -Severity WARN -Message "Failed to read NinjaOne custom field '$Name': $($_.Exception.Message)"
        return $null
    }
}

function ConvertTo-HtmlEncoded {
    <#
        HTML-encodes a string for inclusion in the WYSIWYG report.
        Uses [System.Net.WebUtility]::HtmlEncode which ships with both
        Windows PowerShell 5.1 (.NET Framework) and PowerShell 7+
        (.NET Core), avoiding a dependency on the legacy System.Web
        assembly that is not available on PS Core.
    #>
    param([string] $Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}

function ConvertTo-Bool {
    <#
        NinjaOne checkbox script variables are passed as the literal
        strings "true" / "false" (sometimes "1" / "0"). Convert defensively.
    #>
    param([string] $Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    switch ($Value.Trim().ToLowerInvariant()) {
        'true'    { return $true }
        '1'       { return $true }
        'yes'     { return $true }
        'on'      { return $true }
        'checked' { return $true }
        default   { return $false }
    }
}

function Get-AdministratorsGroupName {
    <#
        Resolves the name of the built-in local Administrators group via
        its well-known SID (S-1-5-32-544) so the script keeps working on
        non-English Windows installs where the group name is localized
        (e.g. "Administratoren", "Administradores"). The resolved name
        is cached in a script-scope variable so subsequent calls are
        cheap.
    #>
    if ($Script:__AdminsGroupName) { return $Script:__AdminsGroupName }

    $resolved = $null
    try {
        $sid      = New-Object System.Security.Principal.SecurityIdentifier $Script:SID_BuiltinAdministrators
        $resolved = $sid.Translate([System.Security.Principal.NTAccount]).Value
        # Translation returns "BUILTIN\Administrators" - we only want the
        # group name component for *-LocalGroupMember cmdlets.
        if ($resolved -match '\\') { $resolved = ($resolved -split '\\', 2)[1] }
    }
    catch {
        try {
            $grp = Get-CimInstance -ClassName Win32_Group `
                                   -Filter "LocalAccount=TRUE AND SID='$($Script:SID_BuiltinAdministrators)'" `
                                   -ErrorAction Stop
            if ($grp) { $resolved = $grp.Name }
        }
        catch {
            # ignore - fall through to default below
            $null = $_
        }
    }

    if ([string]::IsNullOrWhiteSpace($resolved)) { $resolved = 'Administrators' }

    $Script:__AdminsGroupName = $resolved
    return $resolved
}

function Resolve-RunMode {
    <#
        Normalizes the Mode dropdown script variable into one of the
        canonical modes: 'All', 'Report', 'Rotate'. Missing / unknown
        values fall back to 'All' as required by the script contract.
    #>
    param([string] $Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return 'All' }

    switch -Regex ($Value.Trim().ToLowerInvariant()) {
        '^(all|all functions|alle|alle funktionen)$'        { return 'All' }
        '^(report|report only|reportonly|nur report)$'      { return 'Report' }
        '^(rotate|password rotate|passwordrotate|nur passwort.*|passwort.*rotat.*)$' { return 'Rotate' }
        default {
            Write-AuditLog -Severity WARN -Message "Unknown Mode value '$Value' - falling back to 'All Functions'."
            return 'All'
        }
    }
}

function Resolve-RemovalScope {
    <#
        Normalizes the RemoveUnauthorizedAdminsScope dropdown into one of
        'Disabled', 'LocalOnly', 'LocalAndDomain', 'All'. Missing /
        empty values default to 'LocalOnly' to match the dropdown's
        default selection.
    #>
    param(
        [string] $ScopeValue
    )

    if ([string]::IsNullOrWhiteSpace($ScopeValue)) { return 'LocalOnly' }

    switch -Regex ($ScopeValue.Trim().ToLowerInvariant()) {
        '^(disabled|off|none|aus|deaktiviert)$'                                 { return 'Disabled' }
        '^(local|localonly|local only|nur lokal|lokal)$'                        { return 'LocalOnly' }
        '^(localanddomain|local and domain|local\+domain|lokal und domain|lokal\+domain|domain)$' { return 'LocalAndDomain' }
        '^(all|alle|everything|local\+domain\+entra)$'                          { return 'All' }
        default {
            Write-AuditLog -Severity WARN -Message "Unknown RemoveUnauthorizedAdminsScope value '$ScopeValue' - falling back to 'LocalOnly'."
            return 'LocalOnly'
        }
    }
}

function Get-EligibleRemovalScopes {
    <#
        Returns the set of principal Scope strings that are eligible for
        automatic removal under the configured removal mode. 'Unknown'
        principals are intentionally NEVER eligible.
    #>
    param([string] $RemovalScope)

    switch ($RemovalScope) {
        'LocalOnly'      { return @('Local') }
        'LocalAndDomain' { return @('Local','Domain') }
        'All'            { return @('Local','Domain','Azure AD','Microsoft Account') }
        default          { return @() }
    }
}

function Resolve-DisableNativeAdmin {
    <#
        Normalizes the DisableNativeAdmin checkbox script variable.
        Defaults to $true (hardening on) when the variable is missing or
        empty - this matches the recommended posture from the CIS
        Benchmark for the built-in Administrator account.
    #>
    param([string] $Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $true }
    switch ($Value.Trim().ToLowerInvariant()) {
        'true'    { return $true }
        '1'       { return $true }
        'yes'     { return $true }
        'on'      { return $true }
        'checked' { return $true }
        default   { return $false }
    }
}

function Test-IsWellKnownAdminSid {
    <#
        Returns $true if the supplied SID string identifies a built-in
        privileged principal that must NEVER be removed from the local
        Administrators group: the built-in Administrator user (RID 500)
        or one of the well-known privileged AD groups (Domain Admins,
        Enterprise Admins, Schema Admins).
    #>
    param([string] $Sid)

    if ([string]::IsNullOrWhiteSpace($Sid)) { return $false }
    $sid = $Sid.Trim()

    # Built-in local Administrators group itself.
    if ($sid -ieq $Script:SID_BuiltinAdministrators) { return $true }

    # Built-in Administrator account always ends in '-500'.
    if ($sid -match '-500$') { return $true }

    foreach ($rid in $Script:WellKnownAdminGroupRids) {
        if ($sid -match "-$rid$") { return $true }
    }

    return $false
}
function Test-IsBuiltinAdministratorSid {
    <#
        Returns $true if the supplied SID string identifies the built-in
        local Administrator account (RID 500). Centralized so the
        report, the disable step, and the authorization check stay in
        sync about what counts as "the native Administrator".
    #>
    param([string] $Sid)
    if ([string]::IsNullOrWhiteSpace($Sid)) { return $false }
    return ($Sid.Trim() -match '-500$')
}

$Script:__SidNameUseInteropLoaded = $false
$Script:__SidNameUseCache         = @{}

# Canonical, locale-independent SID_NAME_USE keywords that the rest
# of the script understands. Kept as a single source of truth so the
# producer (Resolve-SidNameUseInvariant) and the gatekeeper
# (ConvertTo-InvariantObjectClass) cannot drift apart.
$Script:KnownObjectClassKeywords = @(
    'User','Group','Domain','Alias','WellKnownGroup',
    'DeletedAccount','Invalid','Unknown','Computer','Other'
)

function Initialize-SidNameUseInterop {
    <#
        Compiles the LookupAccountSid P/Invoke wrapper on first use.
        We need this because Get-LocalGroupMember (and Win32_Account on
        some paths) expose a *localized* ObjectClass string ('Benutzer'
        on de-DE, 'Utilisateur' on fr-FR, 'Andere' for "Other", ...).
        LookupAccountSid returns the locale-independent SID_NAME_USE
        enum, which we map to canonical English keywords so the rest of
        the script can compare against 'User' / 'Group' / ... safely.
    #>
    if ($Script:__SidNameUseInteropLoaded) { return }
    try {
        Add-Type -Namespace 'NinjaLAPS' -Name 'SidNameUse' -MemberDefinition @'
[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern bool LookupAccountSid(
    string lpSystemName,
    [MarshalAs(UnmanagedType.LPArray)] byte[] Sid,
    System.Text.StringBuilder lpName,
    ref uint cchName,
    System.Text.StringBuilder ReferencedDomainName,
    ref uint cchReferencedDomainName,
    out int peUse);
'@ -ErrorAction Stop
        $Script:__SidNameUseInteropLoaded = $true
    }
    catch {
        # Intentionally not fatal: callers degrade to the original
        # (possibly localized) ObjectClass string. The audit log gets a
        # single warning so the failure is visible.
        Write-AuditLog -Severity WARN -Message "Failed to load LookupAccountSid interop for locale-safe ObjectClass resolution: $($_.Exception.Message)"
    }
}

function Resolve-SidNameUseInvariant {
    <#
        Returns the canonical English SID_NAME_USE for the given SID
        ('User', 'Group', 'Domain', 'Alias', 'WellKnownGroup',
        'DeletedAccount', 'Invalid', 'Unknown', 'Computer'), or $null
        if the SID could not be looked up (typical for AAD principals
        that have never signed in to the device).

        Results are cached per-SID for the lifetime of the script run.
    #>
    param([string] $Sid)

    if ([string]::IsNullOrWhiteSpace($Sid)) { return $null }
    if ($Script:__SidNameUseCache.ContainsKey($Sid)) {
        return $Script:__SidNameUseCache[$Sid]
    }

    Initialize-SidNameUseInterop
    if (-not $Script:__SidNameUseInteropLoaded) {
        $Script:__SidNameUseCache[$Sid] = $null
        return $null
    }

    try {
        $sidObj   = [System.Security.Principal.SecurityIdentifier]::new($Sid)
        $sidBytes = New-Object byte[] $sidObj.BinaryLength
        $sidObj.GetBinaryForm($sidBytes, 0)

        $nameLen   = [uint32]256
        $domainLen = [uint32]256
        $name      = New-Object System.Text.StringBuilder ([int]$nameLen)
        $domain    = New-Object System.Text.StringBuilder ([int]$domainLen)
        $use       = 0

        $ok = [NinjaLAPS.SidNameUse]::LookupAccountSid(
            $null, $sidBytes, $name, [ref]$nameLen, $domain, [ref]$domainLen, [ref]$use)
        if (-not $ok) {
            $Script:__SidNameUseCache[$Sid] = $null
            return $null
        }

        $result = switch ([int]$use) {
            1       { 'User' }
            2       { 'Group' }
            3       { 'Domain' }
            4       { 'Alias' }
            5       { 'WellKnownGroup' }
            6       { 'DeletedAccount' }
            7       { 'Invalid' }
            8       { 'Unknown' }
            9       { 'Computer' }
            default { $null }
        }
        $Script:__SidNameUseCache[$Sid] = $result
        return $result
    }
    catch {
        $Script:__SidNameUseCache[$Sid] = $null
        return $null
    }
}

function ConvertTo-InvariantObjectClass {
    <#
        Returns a locale-independent ObjectClass for a principal. If
        the input value is already a known English keyword (as produced
        by the WMI fallback path or by an English-locale OS), it is
        returned unchanged. Otherwise we look the SID up via
        LookupAccountSid to obtain the canonical SID_NAME_USE value.

        If neither check yields a known keyword, the original value is
        returned so the report can still display *something* meaningful
        for principals the OS itself could not classify (e.g. AAD
        members that have never signed in - those typically come back
        as the localized "Other" string).
    #>
    param(
        [string] $ObjectClass,
        [string] $Sid
    )

    if (-not [string]::IsNullOrWhiteSpace($ObjectClass) -and
        ($Script:KnownObjectClassKeywords -contains $ObjectClass)) {
        return $ObjectClass
    }

    $resolved = Resolve-SidNameUseInvariant -Sid $Sid
    if ($resolved) { return $resolved }

    return $ObjectClass
}

function Test-IsResolvedEntraUserAccount {
    <#
        Returns $true only for Entra ID principals that we can identify
        as a real, named user account — i.e. an account whose short name
        Windows actually resolved into something a human would recognise
        (typically the UPN, e.g. 'alice@contoso.com').

        This is the safety net that prevents the cleanup step from
        ripping anything else out of the local Administrators group when
        RemovalScope=All:

          * Entra directory-role principals (Global Administrator, AAD
            Joined Device Local Administrator, Cloud Device
            Administrator) — Windows manages those automatically and
            removing them only causes churn / lockout risk.
          * Entra security groups — the script has no authoritative view
            of group membership, so removing the group could silently
            revoke admin rights from many users at once.
          * "Raw SID only" members whose ShortName is just the SID, the
            decoded Entra Object ID, or any other GUID. These are
            principals (often groups or roles) that have never signed in
            on the device, so the OS could not translate them to a
            friendly name. We deliberately refuse to remove anything we
            cannot positively identify as a user account.

        Operators can still remove any of the above by explicitly adding
        them to the authorized list and then removing them out-of-band;
        the script will simply not auto-remove them.
    #>
    param([object] $Admin)

    if (-not $Admin) { return $false }
    if ([string]$Admin.Scope -ne 'Azure AD') { return $false }

    # Must be a user object — never auto-remove groups/roles/etc.
    if ([string]$Admin.ObjectClass -ne 'User') { return $false }

    $short = [string]$Admin.ShortName
    if ([string]::IsNullOrWhiteSpace($short)) { return $false }

    # ShortName must not be the bare SID (unresolved member).
    if ($Admin.SID -and ($short -ieq [string]$Admin.SID)) { return $false }

    # ShortName must not be the decoded Entra Object ID (the
    # 'AzureAD\<oid>' fallback Resolve-PrincipalDisplayName produces
    # when Translate() fails — i.e. a never-signed-in principal).
    if ($Admin.EntraObjectId -and ($short -ieq [string]$Admin.EntraObjectId)) { return $false }

    # ShortName must not be any other bare GUID — same rationale as
    # above for the rare case where the OID was not decoded but the
    # name still looks like a GUID.
    if ($short -match '^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$') { return $false }

    return $true
}

function ConvertTo-EntraObjectId {
    <#
        Decodes an Entra ID (Azure AD) user SID of the form
        'S-1-12-1-a-b-c-d' into the corresponding Entra Object ID GUID.

        AAD user SIDs encode the 16 bytes of the directory objectId as
        four little-endian 32-bit sub-authorities, so the conversion is
        deterministic and works fully offline. This is what lets the
        report identify AAD principals that have never signed in to the
        device (and therefore are not present in the IdentityStore
        LogonCache, so SecurityIdentifier.Translate() fails for them).

        Returns $null for any SID that is not in the AAD user-SID form.
    #>
    param([string] $Sid)

    if ([string]::IsNullOrWhiteSpace($Sid)) { return $null }
    if ($Sid -notmatch '^S-1-12-1-(\d+)-(\d+)-(\d+)-(\d+)$') { return $null }

    try {
        $parts = @(
            [uint32]$Matches[1],
            [uint32]$Matches[2],
            [uint32]$Matches[3],
            [uint32]$Matches[4]
        )
        $bytes = New-Object byte[] 16
        [BitConverter]::GetBytes($parts[0]).CopyTo($bytes,  0)
        [BitConverter]::GetBytes($parts[1]).CopyTo($bytes,  4)
        [BitConverter]::GetBytes($parts[2]).CopyTo($bytes,  8)
        [BitConverter]::GetBytes($parts[3]).CopyTo($bytes, 12)
        return ([Guid]::new($bytes)).ToString()
    }
    catch {
        return $null
    }
}

function Resolve-PrincipalDisplayName {
    <#
        Best-effort resolution of a principal's display name from its
        SID. Used to upgrade "raw SID only" rows (typical for Entra ID
        members that have never signed in to the device) into something
        a human can recognize.

        Returns a hashtable with:
            .Name           - resolved display name (e.g. 'AzureAD\<oid>'
                              or 'DOMAIN\user') or the original raw name
                              if nothing better could be found.
            .EntraObjectId  - decoded Entra Object ID GUID for AAD SIDs,
                              or $null otherwise.

        Resolution order:
          1. If the raw name is already a friendly DOMAIN\Account form
             (i.e. it differs from the SID), keep it.
          2. Try SecurityIdentifier.Translate([NTAccount]). Succeeds for
             local/AD principals and for AAD principals whose
             IdentityStore LogonCache has been populated by a prior
             interactive logon.
          3. For AAD user SIDs (S-1-12-1-...), decode the Entra Object
             ID and return 'AzureAD\<oid>'. The Object ID is searchable
             directly in the Entra portal and uniquely identifies the
             user even without a Microsoft Graph lookup.
    #>
    param(
        [string] $RawName,
        [string] $Sid
    )

    $result = @{
        Name          = $RawName
        EntraObjectId = $null
    }

    # Always compute the AAD Object ID when applicable - useful even
    # when the name was already resolved (callers may want to display
    # both). It's a cheap pure-string operation.
    if ($Sid) {
        $result.EntraObjectId = ConvertTo-EntraObjectId -Sid $Sid
    }

    # If the raw name is empty or equals the SID, the OS could not
    # resolve it for us. Try harder.
    $needsResolution = [string]::IsNullOrWhiteSpace($RawName) -or
                       ($Sid -and ($RawName -ieq $Sid))
    if (-not $needsResolution) { return $result }

    if ($Sid) {
        try {
            $sidObj = New-Object System.Security.Principal.SecurityIdentifier $Sid
            $translated = $sidObj.Translate([System.Security.Principal.NTAccount]).Value
            if (-not [string]::IsNullOrWhiteSpace($translated) -and $translated -ine $Sid) {
                $result.Name = $translated
                return $result
            }
        }
        catch {
            # Translation failed (typical for never-signed-in AAD
            # principals: their IdentityStore LogonCache entry is
            # missing). Fall through to the AAD object-ID fallback.
            Write-Verbose "Resolve-PrincipalDisplayName: Translate() failed for SID '$Sid': $($_.Exception.Message)"
        }

        if ($result.EntraObjectId) {
            $result.Name = "AzureAD\$($result.EntraObjectId)"
        }
    }

    return $result
}

function Get-BuiltinAdministratorAccount {
    <#
        Returns a small descriptor for the local built-in Administrator
        account (RID 500): Name, SID, Enabled. Locale-safe (the account
        is found by SID suffix, not by name) and uses a WMI fallback in
        case Get-LocalUser is unavailable.

        Returns $null when the account cannot be located - callers must
        treat that as "do not touch" rather than as "missing".
    #>
    try {
        $user = Get-LocalUser -ErrorAction Stop |
                Where-Object { $_.SID -and (Test-IsBuiltinAdministratorSid -Sid $_.SID.Value) } |
                Select-Object -First 1
        if ($user) {
            return [pscustomobject]@{
                Name    = [string]$user.Name
                SID     = [string]$user.SID.Value
                Enabled = [bool]$user.Enabled
            }
        }
    }
    catch {
        Write-AuditLog -Severity WARN -Message "Get-LocalUser failed when locating built-in Administrator: $($_.Exception.Message). Falling back to WMI."
    }

    try {
        $wmi = Get-CimInstance -ClassName Win32_UserAccount `
                               -Filter "LocalAccount=TRUE" `
                               -ErrorAction Stop |
               Where-Object { Test-IsBuiltinAdministratorSid -Sid $_.SID } |
               Select-Object -First 1
        if ($wmi) {
            return [pscustomobject]@{
                Name    = [string]$wmi.Name
                SID     = [string]$wmi.SID
                Enabled = -not [bool]$wmi.Disabled
            }
        }
    }
    catch {
        Write-AuditLog -Severity WARN -Message "WMI fallback for built-in Administrator lookup failed: $($_.Exception.Message)"
    }

    return $null
}

function Disable-BuiltinAdministrator {
    <#
        Disables the built-in Administrator account (RID 500). Returns
        $true on success, $false on failure. Caller is responsible for
        deciding whether the disable is appropriate (see the safety
        guards in the main flow).
    #>
    param(
        [Parameter(Mandatory = $true)] $BuiltinAdmin
    )

    try {
        $sid = New-Object System.Security.Principal.SecurityIdentifier $BuiltinAdmin.SID
        Disable-LocalUser -SID $sid -ErrorAction Stop
        Write-AuditLog -Severity SECURITY -Message "Disabled built-in Administrator account '$($BuiltinAdmin.Name)' (SID $($BuiltinAdmin.SID))."
        Add-ChangelogEntry -Category 'DisabledNativeAdmin' -Message ("Disabled built-in Administrator '{0}'." -f $BuiltinAdmin.Name)
        return $true
    }
    catch {
        Write-AuditLog -Severity ERROR -Message "Failed to disable built-in Administrator '$($BuiltinAdmin.Name)' (SID $($BuiltinAdmin.SID)): $($_.Exception.Message)"
        return $false
    }
}
#endregion ===================================================================


#region ====================== LAPS rotation =================================

function Get-LocalUserAdsiState {
    <#
        ADSI WinNT fallback for resolving the Enabled flag and the
        LastLogin timestamp of a local user account. Used when
        Get-LocalUser is unavailable or returns incomplete data - the
        LastLogon property is documented as unreliable on several
        Windows builds, and Get-LocalUser occasionally fails to
        enumerate the built-in Administrator on locale-altered or
        domain-joined hosts.

        Returns a [pscustomobject] with Enabled and LastLogon, both of
        which can be $null when the lookup did not yield a value.
    #>
    param([Parameter(Mandatory = $true)][string] $Name)

    $result = [pscustomobject]@{
        Enabled   = $null
        LastLogon = $null
    }

    try {
        $user = [ADSI]("WinNT://./{0},user" -f $Name)
        # Touch a property to force the bind; if the account does not
        # exist this throws synchronously rather than returning a stub.
        $null = $user.Name

        $flagsRaw = $null
        try { $flagsRaw = $user.Properties['UserFlags'].Value } catch { $flagsRaw = $null }
        if ($null -ne $flagsRaw) {
            # ADS_UF_ACCOUNTDISABLE = 0x0002
            $flags = [int]$flagsRaw
            $result.Enabled = -not ([bool]($flags -band 0x0002))
        }

        try {
            $ll = $user.Properties['LastLogin'].Value
            if ($ll -is [datetime]) {
                # ADSI surfaces "never logged on" as 1601-01-01 (epoch)
                # on some builds - drop obviously bogus values.
                if ($ll.Year -gt 1900) { $result.LastLogon = $ll }
            }
        } catch { $null = $_ }
    } catch { $null = $_ }

    return $result
}

function Get-LocalUserSafe {
    <#
        Returns the matching Get-LocalUser object for $Name or $null
        without throwing when the account does not exist.
    #>
    param([Parameter(Mandatory = $true)][string] $Name)
    try   { return (Get-LocalUser -Name $Name -ErrorAction Stop) }
    catch [Microsoft.PowerShell.Commands.UserNotFoundException] { return $null }
    catch { return $null }
}

function Add-AccountToAdministrators {
    <#
        Adds an account to the local Administrators group. Treats the
        "already a member" error (HRESULT 0x80070562 / 1378) as success.
    #>
    param(
        [Parameter(Mandatory = $true)] [string] $AccountName,
        [string] $GroupName = (Get-AdministratorsGroupName)
    )

    try {
        Add-LocalGroupMember -Group $GroupName -Member $AccountName -ErrorAction Stop
        Write-AuditLog -Severity SECURITY -Message "Added '$AccountName' to local group '$GroupName'."
    }
    catch {
        $msg = $_.Exception.Message
        # "is already a member" - localized; check both message text and
        # the typed exception name.
        if ($_.FullyQualifiedErrorId -match 'MemberExists' -or
            $msg -match 'already a member' -or
            $msg -match 'bereits Mitglied') {
            Write-AuditLog -Severity INFO -Message "'$AccountName' is already a member of '$GroupName'."
            return
        }
        throw
    }
}

function Invoke-LapsRotation {
    <#
        Rotates the password of the managed local admin account and
        writes the new credentials to NinjaOne custom fields.

        Returns the username that was managed, so the caller can pass it
        on to the audit report (where it should always be considered
        authorized).
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSAvoidUsingConvertToSecureStringWithPlainText', '',
        Justification = 'Plaintext password is generated locally with a CSPRNG, required by the LAPS contract to persist into the NinjaOne custom field, and scrubbed from memory in the finally block.')]
    param (
        [string] $TargetUser          = 'LAPSAdmin',
        [int]    $PwLength            = 36
    )

    if ([string]::IsNullOrWhiteSpace($TargetUser)) {
        throw "Invoke-LapsRotation: TargetUser must not be empty."
    }

    $newPassword = $null
    $securePw    = $null
    try {
        $newPassword = New-ComplexPassword -Length $PwLength
        $securePw    = ConvertTo-SecureString -String $newPassword -AsPlainText -Force
        $adminsGroup = Get-AdministratorsGroupName

        $existing = Get-LocalUserSafe -Name $TargetUser

        if (-not $existing) {
            Write-AuditLog -Severity SECURITY -Message "Creating local user '$TargetUser'."
            New-LocalUser -Name $TargetUser `
                          -Password $securePw `
                          -PasswordNeverExpires:$true `
                          -FullName 'NinjaOne LAPS managed account' `
                          -Description 'Managed by NinjaOne LAPS' `
                          -ErrorAction Stop | Out-Null
        }
        else {
            Write-AuditLog -Severity SECURITY -Message "Updating password for local user '$TargetUser'."
            Set-LocalUser -Name $TargetUser -Password $securePw -PasswordNeverExpires:$true -ErrorAction Stop

            if (-not $existing.Enabled) {
                Enable-LocalUser -Name $TargetUser -ErrorAction Stop
                Write-AuditLog -Severity SECURITY -Message "Enabled local user '$TargetUser'."
            }
        }

        # Make sure the account is a member of the Administrators group.
        # Compare by SID (locale-safe and unambiguous) rather than name.
        $userSid = (Get-LocalUserSafe -Name $TargetUser).SID.Value
        $isMember = $false
        try {
            $members = Get-LocalGroupMember -Group $adminsGroup -ErrorAction Stop
            foreach ($m in $members) {
                if ($m.SID -and $m.SID.Value -eq $userSid) { $isMember = $true; break }
            }
        }
        catch {
            # Get-LocalGroupMember can fail on machines with orphaned
            # SIDs; in that case we attempt the add unconditionally and
            # rely on the "already a member" handler.
            $null = $_
            $isMember = $false
        }

        if (-not $isMember) {
            Add-AccountToAdministrators -AccountName $TargetUser -GroupName $adminsGroup
        }

        # Persist credentials to NinjaOne custom fields ONLY after the
        # local account changes have succeeded.
        Write-LapsCustomField -Name $CF_LapsUsername -Value $TargetUser
        Write-LapsCustomField -Name $CF_LapsPassword -Value $newPassword

        Write-AuditLog -Severity SECURITY -Message "Password rotation for '$TargetUser' completed and stored in NinjaOne."
        Add-ChangelogEntry -Category 'PasswordRotation' -Message ("Rotated LAPS password for local user '{0}'." -f $TargetUser)
        return $TargetUser
    }
    finally {
        # Best-effort scrub of the plaintext password from memory.
        if ($newPassword) {
            try { Remove-Variable -Name newPassword -Scope 0 -Force -ErrorAction SilentlyContinue } catch { $null = $_ }
        }
        if ($securePw -and ($securePw -is [System.Security.SecureString])) {
            try { $securePw.Dispose() } catch { $null = $_ }
        }
    }
}
#endregion ===================================================================


#region ====================== Local admin audit =============================

function Get-LocalAdministrators {
    <#
        Returns a list of objects describing every member of the local
        Administrators group, with the original raw name plus a
        normalized "short" account name suitable for comparison against
        the authorized list.
    #>

    $members = @()

    try {
        $members = Get-LocalGroupMember -Group (Get-AdministratorsGroupName) -ErrorAction Stop
    }
    catch {
        # Get-LocalGroupMember can fail on machines with orphaned SIDs.
        # Fall back to WMI in that case so we still produce a report.
        Write-AuditLog -Severity WARN -Message "Get-LocalGroupMember failed ($($_.Exception.Message)). Falling back to WMI."
        try {
            $group = Get-CimInstance -ClassName Win32_Group `
                                     -Filter "LocalAccount=TRUE AND SID='$($Script:SID_BuiltinAdministrators)'" `
                                     -ErrorAction Stop
            if ($group) {
                $assoc   = Get-CimAssociatedInstance -InputObject $group -ResultClassName Win32_Account -ErrorAction Stop
                $members = $assoc | ForEach-Object {
                    [pscustomobject]@{
                        Name            = "$($_.Domain)\$($_.Name)"
                        SID             = $_.SID
                        PrincipalSource = if ($_.Domain -eq $env:COMPUTERNAME) { 'Local' } else { 'ActiveDirectory' }
                        ObjectClass     = switch ([int]$_.SIDType) {
                            1 { 'User' }
                            2 { 'Group' }
                            3 { 'Domain' }
                            4 { 'Alias' }
                            5 { 'WellKnownGroup' }
                            6 { 'DeletedAccount' }
                            7 { 'Invalid' }
                            8 { 'Unknown' }
                            9 { 'Computer' }
                            default { 'Unknown' }
                        }
                    }
                }
            }
        }
        catch {
            Write-AuditLog -Severity ERROR -Message "WMI fallback for local admin enumeration failed: $($_.Exception.Message)"
            throw
        }
    }

    # Build a SID-keyed cache of local user state (Enabled / LastLogon)
    # so we can annotate local user members without one Get-LocalUser
    # call per row. Only meaningful for ObjectClass=User and Scope=Local
    # - groups and non-local principals don't expose these fields here.
    $localUserState = @{}
    try {
        Get-LocalUser -ErrorAction Stop | ForEach-Object {
            $key = if ($_.SID) { [string]$_.SID.Value } else { '' }
            if ($key) {
                $localUserState[$key] = [pscustomobject]@{
                    Enabled   = [bool]$_.Enabled
                    LastLogon = $_.LastLogon
                }
            }
        }
    }
    catch {
        # Get-LocalUser may be unavailable (older systems) - fall back to
        # WMI Win32_UserAccount, which exposes 'Disabled' but not the
        # last-logon timestamp.
        Write-AuditLog -Severity WARN -Message "Get-LocalUser failed ($($_.Exception.Message)). Falling back to WMI for account state."
        try {
            Get-CimInstance -ClassName Win32_UserAccount `
                            -Filter "LocalAccount=TRUE" `
                            -ErrorAction Stop | ForEach-Object {
                if ($_.SID) {
                    $localUserState[[string]$_.SID] = [pscustomobject]@{
                        Enabled   = -not [bool]$_.Disabled
                        LastLogon = $null
                    }
                }
            }
        }
        catch {
            Write-AuditLog -Severity WARN -Message "WMI fallback for local user state failed: $($_.Exception.Message)"
        }
    }

    return @($members | ForEach-Object {
        $raw      = [string]$_.Name
        $sidValue = if ($_.SID) {
            if ($_.SID -is [System.Security.Principal.SecurityIdentifier]) { $_.SID.Value } else { [string]$_.SID }
        } else { '' }

        # Upgrade "raw SID only" rows (typical for Entra ID members
        # that have never signed in to the device, where Get-LocalGroupMember
        # returns the SID string in the Name column and the
        # IdentityStore LogonCache has no entry to translate it back to
        # a friendly name) into something a human can recognize. For
        # AAD user SIDs we fall back to decoding the Entra Object ID
        # and rendering it as 'AzureAD\<oid>', which is directly
        # searchable in the Entra portal.
        $resolved      = Resolve-PrincipalDisplayName -RawName $raw -Sid $sidValue
        $raw           = $resolved.Name
        $entraObjectId = $resolved.EntraObjectId

        # Normalize ObjectClass to a locale-independent keyword. The
        # in-box LocalAccounts module returns this property as a
        # *localized* string (e.g. 'Benutzer' instead of 'User',
        # 'Andere' instead of 'Other'), which would otherwise break
        # every downstream comparison against English keywords -
        # including the safety net in Test-IsResolvedEntraUserAccount.
        $objectClass = ConvertTo-InvariantObjectClass -ObjectClass ([string]$_.ObjectClass) -Sid $sidValue

        $short    = ($raw -split '\\')[-1]
        $scope    = Get-PrincipalScope -PrincipalSource $_.PrincipalSource -FullName $raw -SID $sidValue
        $category = Get-PrincipalCategory -Scope $scope -ObjectClass $objectClass

        # Enabled / LastLogon are only known for local user accounts.
        # Leave them $null for groups and non-local principals so the
        # report can render an em-dash.
        $enabled   = $null
        $lastLogon = $null
        if ($scope -eq 'Local' -and $objectClass -eq 'User' -and $sidValue -and $localUserState.ContainsKey($sidValue)) {
            $enabled   = $localUserState[$sidValue].Enabled
            $lastLogon = $localUserState[$sidValue].LastLogon
        }

        # Defensive fallback: when Get-LocalUser / WMI did not yield a
        # state for this local user (or LastLogon stayed $null - a
        # well-known PowerShell quirk), probe ADSI WinNT directly. This
        # is the path that ensures the built-in Administrator's
        # Enabled flag is always reported correctly even when the
        # primary enumeration sources skip it.
        if ($scope -eq 'Local' -and $objectClass -eq 'User' -and ($null -eq $enabled -or $null -eq $lastLogon)) {
            $adsi = Get-LocalUserAdsiState -Name $short
            if ($null -eq $enabled   -and $null -ne $adsi.Enabled)   { $enabled   = $adsi.Enabled }
            if ($null -eq $lastLogon -and $null -ne $adsi.LastLogon) { $lastLogon = $adsi.LastLogon }
        }

        # Last-resort guarantee for the built-in Administrator (RID 500):
        # its Enabled state drives the security banner and the
        # authorization decision, so we MUST resolve it. Use the
        # locale-safe lookup that already powers the disable step.
        if ($null -eq $enabled -and $sidValue -and (Test-IsBuiltinAdministratorSid -Sid $sidValue)) {
            $builtin = Get-BuiltinAdministratorAccount
            if ($builtin -and ([string]$builtin.SID -ieq $sidValue)) {
                $enabled = [bool]$builtin.Enabled
            }
        }

        [pscustomobject]@{
            FullName        = $raw
            ShortName       = $short
            SID             = $sidValue
            EntraObjectId   = $entraObjectId
            PrincipalSource = $_.PrincipalSource
            ObjectClass     = $objectClass
            Scope           = $scope
            Category        = $category
            Enabled         = $enabled
            LastLogon       = $lastLogon
        }
    })
}

function Get-PrincipalScope {
    <#
        Returns a friendly scope label for a principal: 'Local', 'Domain'
        (Active Directory), 'Azure AD', 'Microsoft Account', or 'Unknown'.
        Falls back to inspecting the FullName / SID when the
        PrincipalSource property is missing (e.g. WMI fallback path).
    #>
    param(
        [string] $PrincipalSource,
        [string] $FullName,
        [string] $SID
    )

    switch -Regex ([string]$PrincipalSource) {
        '^Local$'              { return 'Local' }
        '^ActiveDirectory$'    { return 'Domain' }
        '^AzureAD$'            { return 'Azure AD' }
        '^MicrosoftAccount$'   { return 'Microsoft Account' }
    }

    # Fallback: derive from the DOMAIN\Account prefix.
    if ($FullName -match '^([^\\]+)\\') {
        $domain = $Matches[1]
        if ($domain -ieq $env:COMPUTERNAME)            { return 'Local' }
        if ($domain -ieq 'BUILTIN' -or
            $domain -ieq 'NT AUTHORITY' -or
            $domain -ieq 'NT-AUTORITÄT')               { return 'Local' }
        if ($domain -ieq 'AzureAD')                    { return 'Azure AD' }
        if ($domain -ieq 'MicrosoftAccount')           { return 'Microsoft Account' }
        return 'Domain'
    }

    # SID-based last resort: built-in / well-known prefixes are local.
    # Note: the S-1-5-21- prefix is shared by local SAM and domain
    # accounts, so we cannot safely classify it here without comparing
    # against the machine SID. Return 'Unknown' rather than guessing.
    if ($SID -match '^S-1-5-(18|19|20|32-)') { return 'Local' }
    return 'Unknown'
}

function Get-PrincipalCategory {
    <#
        Combines Scope and ObjectClass into a single human-readable
        category like 'Local User', 'Local Group', 'Domain User',
        'Domain Group'. Used for the local-admin report.
    #>
    param(
        [string] $Scope,
        [string] $ObjectClass
    )

    $kind = switch -Regex ([string]$ObjectClass) {
        '^User$'           { 'User' ; break }
        '^Group$'          { 'Group'; break }
        '^Alias$'          { 'Group'; break }
        '^WellKnownGroup$' { 'Group'; break }
        '^Computer$'       { 'Computer'; break }
        default            { if ($ObjectClass) { [string]$ObjectClass } else { 'Principal' } }
    }

    $scopeLabel = if ([string]::IsNullOrWhiteSpace($Scope)) { 'Unknown' } else { $Scope }
    return "$scopeLabel $kind"
}

function ConvertFrom-AuthorizedEntry {
    <#
        Parses a single entry from the authorized-admins custom field
        into a structured descriptor. Operators may optionally tag an
        entry with one of the case-insensitive prefixes

            role:<oid|name>   - Entra ID directory role principal
            group:<oid|name>  - Entra ID / AD group
            user:<oid|upn|name> - user principal
            sid:<S-1-...>     - explicit SID
            name:<DOMAIN\foo> - explicit name

        The prefix is purely a hint for the report rendering and a way
        for the operator to declare intent. Authorization matching
        always uses the stripped value (matched against ShortName,
        FullName, SID and EntraObjectId in Test-AdminAuthorized), so a
        prefixed and an unprefixed entry with the same value are
        functionally equivalent.

        Returns a PSCustomObject with:
            .Raw   - original entry as written by the operator
            .Kind  - 'role' | 'group' | 'user' | 'sid' | 'name' | 'other'
            .Value - entry with the prefix stripped (used for matching)
    #>
    param([string] $Entry)

    $kind  = 'other'
    $value = [string]$Entry

    if ($Entry -and ($Entry -match '^\s*(?<k>role|group|user|sid|name)\s*:\s*(?<v>.+?)\s*$')) {
        $kind  = $Matches.k.ToLowerInvariant()
        $value = $Matches.v.Trim()
    }
    else {
        $value = ([string]$Entry).Trim()
    }

    return [pscustomobject]@{
        Raw   = $Entry
        Kind  = $kind
        Value = $value
    }
}

function Get-AuthorizedAdmins {
    <#
        Reads the comma separated list of authorized administrators from
        the configured custom field and returns a structured breakdown:

            .Operator       - distinct raw entries supplied by the
                              operator via the LAPSauthorizedLocalAdmins
                              custom field (prefixes preserved).
            .OperatorParsed - the same entries parsed with
                              ConvertFrom-AuthorizedEntry (Raw / Kind /
                              Value) for typed rendering in the report.
            .Fixed          - entries that are always authorized regardless
                              of the custom field: the LAPS-managed account
                              plus the built-in safe names (Administrator,
                              Domain Admins, Enterprise Admins).
            .All            - the union (sorted, de-duplicated) of the
                              stripped operator values plus the fixed
                              entries - the flat allow-list consumed by
                              Test-AdminAuthorized.
    #>
    param ([string[]] $AlwaysAuthorized = @())

    $raw      = Read-LapsCustomField -Name $CF_AuthorizedAdmins
    $operator = @()

    if ($raw) {
        $operator = @($raw -split ',' |
                      ForEach-Object { $_.Trim() } |
                      Where-Object   { $_ -ne '' })
    }
    $operator = @($operator | Sort-Object -Unique)

    # Parse prefixes (role:/group:/user:/sid:/name:) so the report can
    # render typed sub-sections, and so authorization matching uses the
    # stripped value rather than the prefixed form.
    $operatorParsed = @($operator | ForEach-Object { ConvertFrom-AuthorizedEntry -Entry $_ })
    $operatorValues = @($operatorParsed |
                        ForEach-Object { $_.Value } |
                        Where-Object   { $_ } |
                        Sort-Object -Unique)

    # Localized name fallbacks - SID checks (Test-IsWellKnownAdminSid)
    # are the primary defence; these names cover environments where SIDs
    # are not available on the membership object.
    $fixed = @()
    if ($AlwaysAuthorized) { $fixed += $AlwaysAuthorized }
    $fixed += 'Administrator'        # built-in Administrator
    $fixed += 'Domain Admins'        # AD group commonly nested into local Administrators
    $fixed += 'Enterprise Admins'
    $fixed = @($fixed | Where-Object { $_ } | Sort-Object -Unique)

    $all = @(@($operatorValues + $fixed) | Sort-Object -Unique)

    return [pscustomobject]@{
        Operator       = $operator
        OperatorParsed = $operatorParsed
        Fixed          = $fixed
        All            = $all
    }
}

function Test-AdminAuthorized {
    <#
        Decides whether a given local Administrators-group member is
        considered authorized.

        Built-in Administrator (RID 500) is special: it is authorized
        ONLY when it is currently disabled. An enabled built-in
        Administrator is unauthorized so that the report flags it and
        the alert checkbox fires.

        Other well-known privileged SIDs (Domain/Enterprise/Schema
        Admins) remain unconditionally authorized.
    #>
    param (
        [Parameter(Mandatory = $true)] $Admin,
        [Parameter(Mandatory = $true)] [string[]] $Authorized
    )

    # Built-in Administrator (RID 500): authorized iff it has been
    # disabled. Checked before the generic well-known-SID short-circuit
    # below so we can downgrade it.
    if (Test-IsBuiltinAdministratorSid -Sid $Admin.SID) {
        if ($null -ne $Admin.Enabled -and -not $Admin.Enabled) { return $true }
        return $false
    }

    # Other well-known privileged SIDs (Domain Admins, Enterprise Admins,
    # Schema Admins, the local Administrators group itself) are always
    # authorized regardless of the operator-supplied list.
    if (Test-IsWellKnownAdminSid -Sid $Admin.SID) { return $true }

    foreach ($entry in $Authorized) {
        if ([string]::IsNullOrWhiteSpace($entry)) { continue }
        if ($Admin.ShortName -ieq $entry) { return $true }
        if ($Admin.FullName  -ieq $entry) { return $true }
        # Allow operators to authorize an Entra ID member by SID or by
        # decoded Object ID. This keeps existing whitelists that pinned
        # never-signed-in AAD principals by their raw SID working after
        # the report started rendering them as 'AzureAD\<oid>'.
        if ($Admin.SID -and ($Admin.SID -ieq $entry)) { return $true }
        if ($Admin.EntraObjectId -and ($Admin.EntraObjectId -ieq $entry)) { return $true }
    }
    return $false
}

function Get-ScopeMeta {
    <#
        Returns the metadata used to render a scope group: a stable short
        key, the user-facing display label, the Font Awesome icon class,
        and the sort order. Centralizing this here keeps the report
        consistent and makes it easy to add new scopes later.
    #>
    param([string] $Scope)

    switch ([string]$Scope) {
        'Local'             { return @{ Key = 'local'; Label = 'Local';             Icon = 'fa-solid fa-desktop';        Order = 0 } }
        'Domain'            { return @{ Key = 'ad';    Label = 'Active Directory';  Icon = 'fa-solid fa-network-wired';  Order = 1 } }
        'Azure AD'          { return @{ Key = 'entra'; Label = 'Entra ID';          Icon = 'fa-solid fa-cloud';          Order = 2 } }
        'Microsoft Account' { return @{ Key = 'msa';   Label = 'Microsoft Account'; Icon = 'fa-solid fa-user';           Order = 3 } }
        default             { return @{ Key = 'unk';   Label = 'Unknown';           Icon = 'fa-solid fa-circle-question'; Order = 9 } }
    }
}

function New-LocalAdminsReport {
    <#
        Builds an HTML report of the local administrators group,
        suitable for a NinjaOne WYSIWYG custom field. Uses NinjaOne's
        native styling primitives (cards, info-cards, stat-cards, tags,
        and table row classes) so the output blends in with the agent
        UI. The report visually differentiates Local, Active Directory,
        Entra ID and Microsoft Account principals via dedicated scope
        cards, each with its own Font Awesome icon.

        -EligibleScopes drives the per-row "Action" column: principals
        whose scope is in the eligible set will be flagged "Will remove"
        (or "Removed" if -RemovedSids is provided), out-of-scope
        unauthorized principals are flagged "Report only" so the
        operator can tell at a glance whether the configured cleanup
        will touch them.

        The built-in Administrator (RID 500) is never removed from the
        local Administrators group; instead, when it is enabled, the
        action column shows "Will disable" (DisableNativeAdmin on),
        "Should disable" (off), or "Disabled" once the disable just
        happened (-DisabledNativeAdminSid).
    #>
    param (
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [object[]] $Admins,
        [Parameter(Mandatory = $true)] [string[]] $Authorized,
        [string]   $RemovalScope            = 'Disabled',
        [string[]] $EligibleScopes          = @(),
        [AllowEmptyCollection()] [string[]] $RemovedSids             = @(),
        [bool]     $DisableNativeAdmin      = $true,
        [string]   $DisabledNativeAdminSid  = '',
        [AllowEmptyCollection()] [string[]] $AuthorizedFixed        = @(),
        [AllowEmptyCollection()] [string[]] $AuthorizedOperator     = @()
    )

    $unauthorized   = @()
    $authorizedHits = @()
    $removedSet     = @{}
    foreach ($s in $RemovedSids) {
        if ($s) { $removedSet[$s] = $true }
    }

    # Annotate every admin with its authorization state and the action
    # the script will / would take. Doing this once up-front keeps the
    # per-scope rendering loop simple.
    $annotated = @($Admins | ForEach-Object {
        $isOk     = Test-AdminAuthorized -Admin $_ -Authorized $Authorized
        $scope    = [string]$_.Scope
        $eligible = ($EligibleScopes -and ($scope -in $EligibleScopes))
        $isBuiltin = Test-IsBuiltinAdministratorSid -Sid $_.SID

        if ($isOk) {
            # Authorized - either the operator allowed it, or (for the
            # built-in Administrator) the account is disabled / managed.
            # When we just disabled it on this very run, surface that
            # explicitly with a "Disabled" action tag instead of '—'.
            $authorizedHits += $_
            if ($isBuiltin -and $DisabledNativeAdminSid -and ([string]$_.SID -ieq $DisabledNativeAdminSid)) {
                $action = 'Disabled'
            }
            else {
                $action = '—'
            }
        }
        elseif ($isBuiltin) {
            # Built-in Administrator is never removed from the group.
            # The remediation is to disable the account instead.
            $unauthorized += $_
            if ($DisabledNativeAdminSid -and ([string]$_.SID -ieq $DisabledNativeAdminSid)) {
                $action = 'Disabled'
            }
            elseif ($DisableNativeAdmin) {
                $action = 'Will disable'
            }
            else {
                $action = 'Should disable'
            }
        }
        else {
            $unauthorized += $_
            # Mirror the Entra ID safety net from Remove-UnauthorizedAdmins:
            # even with RemovalScope=All, only resolved Entra user
            # accounts are auto-removable. Groups, directory roles and
            # raw-SID/OID-only members stay as "Report only" so the
            # action column matches what cleanup will actually do.
            $entraNonRemovable = ($scope -eq 'Azure AD' -and -not (Test-IsResolvedEntraUserAccount -Admin $_))
            if ($removedSet.ContainsKey([string]$_.SID))           { $action = 'Removed' }
            elseif ($RemovalScope -eq 'Disabled')                  { $action = 'Report only' }
            elseif ($eligible -and -not $entraNonRemovable)        { $action = 'Will remove' }
            else                                                   { $action = 'Report only' }
        }

        [pscustomobject]@{
            Admin      = $_
            Authorized = $isOk
            Action     = $action
        }
    })

    # Bucket by scope so we can render one card per category.
    $buckets = @{}
    foreach ($entry in $annotated) {
        $scope = [string]$entry.Admin.Scope
        if (-not $buckets.ContainsKey($scope)) { $buckets[$scope] = New-Object System.Collections.Generic.List[object] }
        $buckets[$scope].Add($entry)
    }

    $sortedScopes = @($buckets.Keys | Sort-Object @{ Expression = { (Get-ScopeMeta -Scope $_).Order } }, @{ Expression = { $_ } })

    $scopeCards = New-Object System.Text.StringBuilder

    foreach ($scope in $sortedScopes) {
        $meta    = Get-ScopeMeta -Scope $scope
        $entries = @($buckets[$scope] | Sort-Object `
                        @{ Expression = { -not $_.Authorized } }, `
                        @{ Expression = { $_.Admin.Category } }, `
                        @{ Expression = { $_.Admin.FullName } })

        # Enabled / LastLogon are only meaningful for principals backed
        # by the local SAM. For Active Directory and Entra ID members
        # the local endpoint cannot resolve those attributes, so the
        # columns are suppressed entirely on those scope cards rather
        # than rendered as a meaningless dash.
        $showStatusCols = $scope -notin @('Domain', 'Azure AD')

        $rows = New-Object System.Text.StringBuilder
        foreach ($entry in $entries) {
            $admin = $entry.Admin

            $unauthorizedTag = '<div class="tag expired">UNAUTHORIZED</div>'

            if ($entry.Authorized) {
                $rowClass = 'success'
                $statusTag = '<div class="tag">AUTHORIZED</div>'
            }
            elseif ($entry.Action -eq 'Removed' -or $entry.Action -eq 'Will remove' -or
                    $entry.Action -eq 'Disabled' -or $entry.Action -eq 'Will disable') {
                $rowClass  = 'danger'
                $statusTag = $unauthorizedTag
            }
            else {
                # Unauthorized but not eligible for removal under the
                # current scope - highlight it as a warning so the
                # operator can decide manually.
                $rowClass  = 'warning'
                $statusTag = $unauthorizedTag
            }

            switch ($entry.Action) {
                'Removed'        { $actionTag = '<div class="tag expired">REMOVED</div>' }
                'Will remove'    { $actionTag = '<div class="tag expired">WILL REMOVE</div>' }
                'Report only'    { $actionTag = '<div class="tag disabled">REPORT ONLY</div>' }
                'Disabled'       { $actionTag = '<div class="tag">DISABLED</div>' }
                'Will disable'   { $actionTag = '<div class="tag expired">WILL DISABLE</div>' }
                'Should disable' { $actionTag = '<div class="tag disabled">SHOULD DISABLE</div>' }
                default          { $actionTag = '<span>—</span>' }
            }

            $sidCell = if ($admin.SID) { ConvertTo-HtmlEncoded ([string]$admin.SID) } else { '<span>—</span>' }

            $statusCells = ''
            if ($showStatusCols) {
                if ($null -eq $admin.Enabled) {
                    $enabledCell = '<span>—</span>'
                }
                elseif ($admin.Enabled) {
                    $enabledCell = '<div class="tag">ENABLED</div>'
                }
                else {
                    $enabledCell = '<div class="tag disabled">DISABLED</div>'
                }

                if ($admin.LastLogon -is [datetime]) {
                    $lastLogonCell = ConvertTo-HtmlEncoded ($admin.LastLogon.ToString('yyyy-MM-dd HH:mm:ss'))
                }
                elseif ($admin.Scope -eq 'Local' -and $admin.ObjectClass -eq 'User') {
                    # Known local user but no recorded logon yet.
                    $lastLogonCell = '<span>Never</span>'
                }
                else {
                    $lastLogonCell = '<span>—</span>'
                }

                $statusCells = "    <td>$enabledCell</td>`r`n    <td>$lastLogonCell</td>`r`n"
            }

            $null = $rows.AppendLine(@"
<tr class="$rowClass">
    <td>$(ConvertTo-HtmlEncoded $admin.FullName)</td>
    <td>$(ConvertTo-HtmlEncoded $admin.Category)</td>
    <td><span style="font-family: monospace; font-size: 11px;">$sidCell</span></td>
$statusCells    <td>$statusTag</td>
    <td>$actionTag</td>
</tr>
"@)
        }

        $scopeAuthorizedCount   = @($entries | Where-Object { $_.Authorized }).Count
        $scopeUnauthorizedCount = @($entries | Where-Object { -not $_.Authorized }).Count
        $scopeSubtitle          = "{0} member(s) &middot; {1} authorized &middot; {2} unauthorized" -f $entries.Count, $scopeAuthorizedCount, $scopeUnauthorizedCount

        # Entra ID directory roles (Global Administrator, AAD Joined
        # Device Local Administrator, Cloud Device Administrator) are
        # added to the local Administrators group automatically by
        # Windows on Entra-joined devices. The endpoint cannot enumerate
        # who actually holds those roles - that information lives in
        # Entra ID. Surface this caveat directly on the Entra ID scope
        # card so the operator never assumes the script is auditing or
        # controlling role membership.
        $scopeNotice = ''
        if ($scope -eq 'Azure AD') {
            $scopeNotice = @"
<div class="info-card" style="margin-bottom: 12px;">
    <p>
        <i class="fa-solid fa-circle-info" style="margin-right: 4px;"></i>
        <strong>Note:</strong> Membership of Entra ID directory roles (e.g. <em>Global Administrator</em>, <em>Azure AD Joined Device Local Administrator</em>, <em>Cloud Device Administrator</em>) cannot be controlled by this script. Role assignments are managed exclusively in Entra ID. If you want to authorize a directory-role principal in the report, add its Object ID to the authorized list using the <code>role:</code> prefix. Even with removal scope <code>All</code>, only resolved Entra user accounts are auto-removed &mdash; groups, directory roles and raw SID / Object ID only members stay in place and are flagged as <em>Report only</em>.
    </p>
</div>
"@
        }

        $statusHeaders = ''
        if ($showStatusCols) {
            $statusHeaders = "                    <th>Enabled</th>`r`n                    <th>Last logon</th>`r`n"
        }

        $null = $scopeCards.AppendLine(@"
<div class="card flex-grow-1" style="margin-bottom: 12px;">
    <div class="card-title-box">
        <div class="card-title"><i class="$($meta.Icon)"></i>&nbsp;&nbsp;$(ConvertTo-HtmlEncoded $meta.Label)</div>
    </div>
    <div class="card-body">
        <p>$scopeSubtitle</p>
$scopeNotice
        <table>
            <thead>
                <tr>
                    <th>Account</th>
                    <th>Category</th>
                    <th>SID</th>
$statusHeaders                    <th>Status</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
$($rows.ToString())
            </tbody>
        </table>
    </div>
</div>
"@)
    }

    $unauthorizedCount = @($unauthorized).Count
    $authorizedCount   = @($authorizedHits).Count
    $totalCount        = @($Admins).Count
    $removedCount      = @($RemovedSids | Where-Object { $_ }).Count
    $eligibleUnauthorized = @($annotated | Where-Object {
        -not $_.Authorized -and $_.Action -eq 'Will remove'
    }).Count
    $reportOnlyUnauthorized = @($annotated | Where-Object {
        -not $_.Authorized -and $_.Action -eq 'Report only'
    }).Count

    if ($unauthorizedCount -gt 0) {
        $summaryClass = 'error'
        $summaryIcon  = 'fa-solid fa-circle-exclamation'
        $summaryTitle = "$unauthorizedCount unauthorized administrator(s) detected"
    }
    else {
        $summaryClass = 'success'
        $summaryIcon  = 'fa-solid fa-circle-check'
        $summaryTitle = 'All local administrators are authorized'
    }

    $generated = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')
    $computer  = ConvertTo-HtmlEncoded $env:COMPUTERNAME

    # Authorized list: render fixed entries (always-on built-in safe list
    # plus the LAPS-managed account) separately from operator-supplied
    # entries (read from the LAPSauthorizedLocalAdmins custom field) so
    # the operator can tell at a glance which entries they control vs.
    # which ones the script enforces. Falls back to the legacy flat list
    # when the breakdown was not supplied (older callers).
    $fixedList    = @(@($AuthorizedFixed)    | Where-Object { $_ } | Sort-Object -Unique)
    $operatorList = @(@($AuthorizedOperator) | Where-Object { $_ } | Sort-Object -Unique)
    if (-not $fixedList -and -not $operatorList) {
        $fixedList    = @(@($Authorized) | Where-Object { $_ } | Sort-Object -Unique)
        $operatorList = @()
    }

    $renderAuthEntries = {
        param([string[]] $Items, [string] $EmptyText)
        if (-not $Items -or $Items.Count -eq 0) {
            return ('<p style="margin: 0; color: #6e7781; font-style: italic;">{0}</p>' -f (ConvertTo-HtmlEncoded $EmptyText))
        }
        $tags = ($Items | ForEach-Object {
            '<span class="tag" style="margin: 2px 4px 2px 0; display: inline-block;">{0}</span>' -f (ConvertTo-HtmlEncoded $_)
        }) -join ''
        return ('<p style="margin: 0;">{0}</p>' -f $tags)
    }

    $fixedHtml = & $renderAuthEntries $fixedList 'No fixed entries.'

    # Operator entries: parse prefixes (role:/group:/user:/sid:/name:)
    # and render one labelled sub-section per kind so the operator can
    # tell at a glance whether an entry is meant to authorize a directory
    # role, a group, an individual user, a raw SID, or a free-form name.
    # Untyped (bare) entries fall into "Other".
    $kindMeta = [ordered]@{
        'role'  = @{ Label = 'Roles';  Icon = 'fa-solid fa-shield-halved'; Hint = 'Entra ID directory roles &mdash; membership is managed in Entra ID, not on the endpoint.' }
        'group' = @{ Label = 'Groups'; Icon = 'fa-solid fa-users';         Hint = 'Entra ID or Active Directory groups.' }
        'user'  = @{ Label = 'Users';  Icon = 'fa-solid fa-user';          Hint = 'Individual user principals.' }
        'sid'   = @{ Label = 'SIDs';   Icon = 'fa-solid fa-fingerprint';   Hint = 'Raw security identifiers.' }
        'name'  = @{ Label = 'Names';  Icon = 'fa-solid fa-id-badge';      Hint = 'Account names (e.g. DOMAIN\user).' }
        'other' = @{ Label = 'Other';  Icon = 'fa-solid fa-tag';           Hint = 'Untagged entries &mdash; matched against name, SID and Entra Object ID.' }
    }

    $operatorParsed = @($operatorList | ForEach-Object { ConvertFrom-AuthorizedEntry -Entry $_ })
    $operatorByKind = @{}
    foreach ($p in $operatorParsed) {
        $k = $p.Kind
        if (-not $operatorByKind.ContainsKey($k)) {
            $operatorByKind[$k] = New-Object System.Collections.Generic.List[string]
        }
        $operatorByKind[$k].Add($p.Value)
    }

    $operatorSb = New-Object System.Text.StringBuilder
    if (-not $operatorList -or $operatorList.Count -eq 0) {
        $null = $operatorSb.Append(('<p style="margin: 0; color: #6e7781; font-style: italic;">{0}</p>' -f (ConvertTo-HtmlEncoded ("No operator entries (custom field '{0}' is empty)." -f $CF_AuthorizedAdmins))))
    }
    else {
        foreach ($k in $kindMeta.Keys) {
            if (-not $operatorByKind.ContainsKey($k)) { continue }
            $values = @($operatorByKind[$k] | Where-Object { $_ } | Sort-Object -Unique)
            if ($values.Count -eq 0) { continue }

            $meta = $kindMeta[$k]
            $tags = ($values | ForEach-Object {
                '<span class="tag" style="margin: 2px 4px 2px 0; display: inline-block;">{0}</span>' -f (ConvertTo-HtmlEncoded $_)
            }) -join ''

            $null = $operatorSb.AppendLine(@"
<div style="margin-bottom: 8px;">
    <div style="font-weight: 600; font-size: 12px; margin-bottom: 4px;">
        <i class="$($meta.Icon)" style="margin-right: 4px;"></i>$(ConvertTo-HtmlEncoded $meta.Label)
        <span style="color: #6e7781; font-weight: 400;">&nbsp;&middot; $($meta.Hint)</span>
    </div>
    <p style="margin: 0;">$tags</p>
</div>
"@)
        }
    }
    $operatorHtml = $operatorSb.ToString()

    $authListHtml = @"
<div style="margin-bottom: 12px;">
    <div style="font-weight: 600; margin-bottom: 4px;">
        <i class="fa-solid fa-lock" style="margin-right: 4px;"></i>Fixed entries
        <span style="color: #6e7781; font-weight: 400; font-size: 12px;">&nbsp;&middot; privileged groups safe list + LAPS-managed account (always authorized)</span>
    </div>
    $fixedHtml
</div>
<div>
    <div style="font-weight: 600; margin-bottom: 4px;">
        <i class="fa-solid fa-pen-to-square" style="margin-right: 4px;"></i>From custom field
        <span style="color: #6e7781; font-weight: 400; font-size: 12px;">&nbsp;&middot; $(ConvertTo-HtmlEncoded $CF_AuthorizedAdmins) &middot; supports optional prefixes <code>role:</code>, <code>group:</code>, <code>user:</code>, <code>sid:</code>, <code>name:</code></span>
    </div>
    $operatorHtml
</div>
"@

    $scopeLabel = switch ($RemovalScope) {
        'Disabled'       { 'Disabled (report only)' }
        'LocalOnly'      { 'Local accounts only' }
        'LocalAndDomain' { 'Local + Active Directory' }
        'All'            { 'Local + Active Directory + Entra ID + Microsoft Account' }
        default          { $RemovalScope }
    }

    $summaryDescription = "Host: {0} &middot; Generated: {1} &middot; Removal scope: {2}" -f $computer, $generated, (ConvertTo-HtmlEncoded $scopeLabel)

    # Stat cards row. Bootstrap grid is part of the NinjaOne CSS.
    $stats = @"
<div class="row" style="margin-bottom: 12px;">
    <div class="col">
        <div class="stat-card">
            <div class="stat-value"><span>$totalCount</span></div>
            <div class="stat-desc"><span>Total members</span></div>
        </div>
    </div>
    <div class="col">
        <div class="stat-card">
            <div class="stat-value"><span style="color: #1f883d;">$authorizedCount</span></div>
            <div class="stat-desc"><span>Authorized</span></div>
        </div>
    </div>
    <div class="col">
        <div class="stat-card">
            <div class="stat-value"><span style="color: #d1242f;">$unauthorizedCount</span></div>
            <div class="stat-desc"><span>Unauthorized</span></div>
        </div>
    </div>
</div>
"@

    # Optional sub-banner that warns when there are unauthorized
    # principals the configured scope will NOT clean up. Helps the
    # operator notice that AD / Entra rogue admins are visible but
    # untouched.
    $reportOnlyBanner = ''
    if ($reportOnlyUnauthorized -gt 0 -and $RemovalScope -ne 'All') {
        $reportOnlyBanner = @"
<div class="info-card warning" style="margin-bottom: 12px;">
    <i class="info-icon fa-solid fa-triangle-exclamation"></i>
    <div class="info-text">
        <div class="info-title">$reportOnlyUnauthorized unauthorized principal(s) outside the configured removal scope</div>
        <div class="info-description">These accounts/groups are reported but will not be removed automatically. Review them and either add to the authorized list or widen RemoveUnauthorizedAdminsScope.</div>
    </div>
</div>
"@
    }

    $eligibleBanner = ''
    if ($eligibleUnauthorized -gt 0 -and $removedCount -eq 0) {
        $eligibleBanner = @"
<div class="info-card warning" style="margin-bottom: 12px;">
    <i class="info-icon fa-solid fa-triangle-exclamation"></i>
    <div class="info-text">
        <div class="info-title">$eligibleUnauthorized unauthorized principal(s) eligible for automatic removal</div>
        <div class="info-description">The next run with the current RemoveUnauthorizedAdminsScope setting will remove these from the local Administrators group.</div>
    </div>
</div>
"@
    }

    # Native (built-in) Administrator banner. Three states:
    #   1. Just disabled this run         -> success banner
    #   2. Currently enabled, will fix    -> warning banner (DisableNativeAdmin on)
    #   3. Currently enabled, won't fix   -> error banner   (DisableNativeAdmin off)
    $nativeAdminBanner = ''
    $builtinEntry = @($annotated | Where-Object { Test-IsBuiltinAdministratorSid -Sid $_.Admin.SID } | Select-Object -First 1)
    if ($builtinEntry) {
        switch ($builtinEntry.Action) {
            'Disabled' {
                $nativeAdminBanner = @"
<div class="info-card success" style="margin-bottom: 12px;">
    <i class="info-icon fa-solid fa-shield-halved"></i>
    <div class="info-text">
        <div class="info-title">Built-in Administrator account disabled</div>
        <div class="info-description">The native Administrator (RID 500) was enabled on this run and has just been disabled (DisableNativeAdmin = on).</div>
    </div>
</div>
"@
            }
            'Will disable' {
                $nativeAdminBanner = @"
<div class="info-card warning" style="margin-bottom: 12px;">
    <i class="info-icon fa-solid fa-triangle-exclamation"></i>
    <div class="info-text">
        <div class="info-title">Built-in Administrator account is enabled</div>
        <div class="info-description">An active native Administrator (RID 500) is a recurring security-audit finding. Automatic remediation (DisableNativeAdmin = on) will disable this account; if it is still enabled, the previous attempt failed &mdash; check the audit log. The account is intentionally never removed from the local Administrators group.</div>
    </div>
</div>
"@
            }
            'Should disable' {
                $nativeAdminBanner = @"
<div class="info-card error" style="margin-bottom: 12px;">
    <i class="info-icon fa-solid fa-circle-exclamation"></i>
    <div class="info-text">
        <div class="info-title">Built-in Administrator account is enabled</div>
        <div class="info-description">Automatic remediation is OFF (DisableNativeAdmin = off). Either enable the DisableNativeAdmin script variable so the next run disables the account, or disable the account manually.</div>
    </div>
</div>
"@
            }
        }
    }

    $html = @"
<div>
    <div class="info-card $summaryClass" style="margin-bottom: 12px;">
        <i class="info-icon $summaryIcon"></i>
        <div class="info-text">
            <div class="info-title">$(ConvertTo-HtmlEncoded $summaryTitle)</div>
            <div class="info-description">$summaryDescription</div>
        </div>
    </div>
$stats
$reportOnlyBanner
$eligibleBanner
$nativeAdminBanner
$($scopeCards.ToString())
    <div class="card flex-grow-1">
        <div class="card-title-box">
            <div class="card-title"><i class="fa-solid fa-list-check"></i>&nbsp;&nbsp;Authorized list</div>
        </div>
        <div class="card-body">
$authListHtml
        </div>
    </div>
</div>
"@

    # The NinjaOne WYSIWYG renderer turns source newlines between block
    # elements into visible blank lines, which made the scope cards
    # (Local / Active Directory / Entra ID) and especially the
    # Authorized list card render with a lot of empty rows. Collapse
    # any whitespace that sits purely between adjacent HTML tags - this
    # is a no-op for browsers but removes the artificial blank rows in
    # the WYSIWYG view.
    $html = [regex]::Replace($html, '>\s+<', '><').Trim()

    return [pscustomobject]@{
        Html               = $html
        UnauthorizedAdmins = @($unauthorized)
        AuthorizedAdmins   = @($authorizedHits)
        BuiltinAdminEntry  = if ($builtinEntry) { $builtinEntry[0] } else { $null }
    }
}

function Remove-UnauthorizedAdmins {
    <#
        Removes every account in the supplied list from the local
        Administrators group. Refuses to remove well-known privileged
        SIDs even if the caller passed them in, and never touches the
        managed LAPS account.

        Only principals whose Scope is contained in -EligibleScopes are
        eligible for removal. Out-of-scope unauthorized principals are
        kept in place (they remain visible in the report and the alert
        flag still fires) so the operator can decide manually.

        An empty operator-supplied authorized list is allowed: the fixed
        allow-list (built-in Administrator, Domain Admins, Enterprise
        Admins, the managed LAPS account) plus the hard safety nets
        above are sufficient when the operator wants only the LAPS
        account to retain local admin rights. The fact that cleanup ran
        against the fixed allow-list only is logged at INFO level for
        traceability.

        Returns the names that were successfully removed.
    #>
    param (
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [object[]] $Unauthorized,
        [Parameter(Mandatory = $true)] [string[]] $AuthorizedList,
        [Parameter(Mandatory = $true)] [string]   $ManagedAccountName,
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [string[]] $EligibleScopes
    )

    # The operator-supplied authorized list (i.e. the custom field
    # contents minus the fixed safe entries and the managed account)
    # may legitimately be empty when the operator wants only the
    # LAPS-managed account to keep local admin rights. Surface this at
    # INFO level so it is obvious in the audit log, but proceed with
    # the cleanup - the hard safety nets below still protect well-known
    # privileged SIDs and the managed account itself.
    $operatorEntries = @($AuthorizedList | Where-Object {
        $_ -and
        $_ -ne $ManagedAccountName -and
        $_ -notin @('Administrator','Domain Admins','Enterprise Admins')
    })
    if ($operatorEntries.Count -eq 0) {
        Write-AuditLog -Severity INFO -Message (("Authorized list (custom field '{0}') contains no operator entries - proceeding with cleanup against the fixed allow-list only " +
                                                 "(managed LAPS account '{1}', built-in Administrator, Domain Admins, Enterprise Admins, well-known privileged SIDs).") -f $CF_AuthorizedAdmins, $ManagedAccountName)
    }

    $removed     = @()
    $adminsGroup = Get-AdministratorsGroupName

    foreach ($admin in $Unauthorized) {
        # Hard safety net: never remove well-known privileged principals,
        # even if Test-AdminAuthorized somehow flagged them.
        if (Test-IsWellKnownAdminSid -Sid $admin.SID) {
            Write-AuditLog -Severity SECURITY -Message "Skipping removal of well-known privileged principal '$($admin.FullName)' (SID $($admin.SID))."
            continue
        }

        # Never remove the managed LAPS account.
        if ($admin.ShortName -ieq $ManagedAccountName) {
            Write-AuditLog -Severity SECURITY -Message "Skipping removal of managed LAPS account '$($admin.FullName)'."
            continue
        }

        # Honour the configured removal scope. Out-of-scope principals
        # (and anything we could not classify) are reported only.
        $scope = [string]$admin.Scope
        if (-not $EligibleScopes -or $EligibleScopes.Count -eq 0 -or $scope -notin $EligibleScopes) {
            Write-AuditLog -Severity SECURITY -Message "Skipping removal of '$($admin.FullName)' (SID $($admin.SID)) - scope '$scope' is not in the configured removal set."
            continue
        }

        # Hard safety net for Entra ID: even with RemovalScope=All we
        # only auto-remove principals that are positively identified as
        # a real, named user account. Directory roles, security groups
        # and "raw SID / OID only" members (typically groups or roles
        # that have never signed in on the device, so the OS could not
        # translate them to a friendly name) are kept in place. The
        # report still flags them as unauthorized so the operator can
        # decide manually.
        if ($scope -eq 'Azure AD' -and -not (Test-IsResolvedEntraUserAccount -Admin $admin)) {
            Write-AuditLog -Severity SECURITY -Message (("Skipping removal of Entra ID principal '{0}' (SID {1}, ObjectClass {2}) - " +
                                                         "only resolved Entra user accounts are auto-removed; groups, directory roles and unresolved SID/OID-only members must be handled manually.") -f $admin.FullName, $admin.SID, $admin.ObjectClass)
            continue
        }

        try {
            # Remove-LocalGroupMember's -Member parameter is typed as
            # LocalPrincipal[]. In the in-box Microsoft.PowerShell.LocalAccounts
            # module shipped with Windows PowerShell 5.1 the binder cannot
            # convert a [SecurityIdentifier] to LocalPrincipal, so passing
            # a SID directly fails with:
            #   "The value <SID> of type SecurityIdentifier cannot be
            #    converted to type LocalPrincipal."
            # Pass the resolved name (DOMAIN\Account) instead - the binder
            # accepts strings and resolves them itself. For orphaned SIDs
            # that no longer resolve (or whose name we never resolved),
            # fall back to ADSI WinNT://<SID> which works regardless of
            # name resolvability.
            $memberName = $admin.FullName
            if ([string]::IsNullOrWhiteSpace($memberName)) { $memberName = $admin.ShortName }

            $removedOk = $false
            if (-not [string]::IsNullOrWhiteSpace($memberName)) {
                try {
                    Remove-LocalGroupMember -Group $adminsGroup -Member $memberName -ErrorAction Stop
                    $removedOk = $true
                }
                catch {
                    Write-AuditLog -Severity WARN -Message ("Remove-LocalGroupMember by name failed for '{0}' (SID {1}): {2} - falling back to ADSI." -f $memberName, $admin.SID, $_.Exception.Message)
                }
            }

            if (-not $removedOk) {
                if (-not $admin.SID) {
                    $identifier = $memberName
                    if ([string]::IsNullOrWhiteSpace($identifier)) { $identifier = '<unknown>' }
                    throw "Cannot remove '$identifier': no SID and no usable name available for ADSI fallback."
                }
                # ADSI accepts WinNT://<SID> for both resolvable and
                # orphaned SIDs, sidestepping the LocalAccounts binder.
                $groupAdsi = [ADSI]("WinNT://./{0},group" -f $adminsGroup)
                $groupAdsi.Remove(("WinNT://{0}" -f $admin.SID))
            }

            Write-AuditLog -Severity SECURITY -Message "Removed '$($admin.FullName)' (SID $($admin.SID)) from local Administrators."
            Add-ChangelogEntry -Category 'RemovedAdmin' -Message ("Removed '{0}' (scope {1}) from local Administrators." -f $admin.FullName, $scope)
            $removed += $admin
        }
        catch {
            Write-AuditLog -Severity ERROR -Message "Failed to remove '$($admin.FullName)' from local Administrators: $($_.Exception.Message)"
        }
    }
    return $removed
}
#endregion ===================================================================


#region ============================ Main ====================================

Initialize-AuditLog

$exitCode = 0
try {
    $runMode            = Resolve-RunMode             -Value $Mode
    $removalScope       = Resolve-RemovalScope        -ScopeValue $RemoveUnauthorizedAdminsScope
    $eligibleScopes     = Get-EligibleRemovalScopes   -RemovalScope $removalScope
    $disableNativeAdmin = Resolve-DisableNativeAdmin  -Value $DisableNativeAdmin
    $doRemove           = ($removalScope -ne 'Disabled')
    $runRotate          = $runMode -in @('All','Rotate')
    $runReport          = $runMode -in @('All','Report')

    Write-AuditLog -Severity INFO -Message "NinjaOne LAPS script start - Mode: $runMode (Rotate=$runRotate, Report=$runReport, RemovalScope=$removalScope, DisableNativeAdmin=$disableNativeAdmin)"

    # 1) Rotate the LAPS password and capture the managed account name so
    #    the audit step never flags it as unauthorized.
    $managedAccount = $NewAdminUsername

    if ($runRotate) {
        $managedAccount = Invoke-LapsRotation -TargetUser $NewAdminUsername `
                                              -PwLength   $PasswordLength
    }
    else {
        Write-AuditLog -Severity INFO -Message "Skipping LAPS password rotation (mode=$runMode)."
    }

    # 2) Enumerate local admins and build the report.
    if (-not $runReport) {
        Write-AuditLog -Severity INFO -Message "Skipping local admin audit / report (mode=$runMode)."
        exit 0
    }

    $admins     = @(Get-LocalAdministrators)
    $authBreakdown = Get-AuthorizedAdmins -AlwaysAuthorized @($managedAccount)
    $authorized    = @($authBreakdown.All)
    $report     = New-LocalAdminsReport -Admins             $admins `
                                        -Authorized         $authorized `
                                        -AuthorizedFixed    $authBreakdown.Fixed `
                                        -AuthorizedOperator $authBreakdown.Operator `
                                        -RemovalScope       $removalScope `
                                        -EligibleScopes     $eligibleScopes `
                                        -DisableNativeAdmin $disableNativeAdmin

    # 2a) Optionally disable the built-in Administrator account (RID 500)
    #     when it is enabled. The account is never removed from the local
    #     Administrators group; disabling matches the CIS Benchmark
    #     recommendation and keeps emergency / safe-mode recovery paths
    #     intact.
    $disabledNativeSid = ''
    if ($disableNativeAdmin) {
        $builtin = Get-BuiltinAdministratorAccount
        if (-not $builtin) {
            Write-AuditLog -Severity WARN -Message "Built-in Administrator account could not be located - skipping disable step."
        }
        elseif (-not $builtin.Enabled) {
            Write-AuditLog -Severity INFO -Message "Built-in Administrator '$($builtin.Name)' (SID $($builtin.SID)) is already disabled."
        }
        else {
            Write-AuditLog -Severity SECURITY -Message "DisableNativeAdmin=on - disabling built-in Administrator '$($builtin.Name)' (SID $($builtin.SID))."
            if (Disable-BuiltinAdministrator -BuiltinAdmin $builtin) {
                $disabledNativeSid = $builtin.SID
            }
        }
    }

    # 2b) Optionally remove unauthorized admins.
    $removedSids = @()
    if ($doRemove -and @($report.UnauthorizedAdmins).Count -gt 0) {
        Write-AuditLog -Severity SECURITY -Message "RemoveUnauthorizedAdminsScope='$removalScope' - cleaning up local Administrators group (eligible scopes: $($eligibleScopes -join ', '))."
        $removed = Remove-UnauthorizedAdmins -Unauthorized       $report.UnauthorizedAdmins `
                                             -AuthorizedList     $authorized `
                                             -ManagedAccountName $managedAccount `
                                             -EligibleScopes     $eligibleScopes
        if (@($removed).Count -gt 0) {
            $removedSids = @($removed | ForEach-Object { [string]$_.SID })
        }
    }

    # 2c) Rebuild the report so the data written to NinjaOne reflects
    #     the post-cleanup / post-disable state (and shows "Removed" /
    #     "Disabled" tags for principals that were just acted on).
    if ($removedSids.Count -gt 0 -or $disabledNativeSid) {
        $admins = @(Get-LocalAdministrators)
        $report = New-LocalAdminsReport -Admins                 $admins `
                                        -Authorized             $authorized `
                                        -AuthorizedFixed        $authBreakdown.Fixed `
                                        -AuthorizedOperator     $authBreakdown.Operator `
                                        -RemovalScope           $removalScope `
                                        -EligibleScopes         $eligibleScopes `
                                        -RemovedSids            $removedSids `
                                        -DisableNativeAdmin     $disableNativeAdmin `
                                        -DisabledNativeAdminSid $disabledNativeSid
    }

    # 3) Push the WYSIWYG HTML report to NinjaOne. WYSIWYG fields require
    #    the piped variant of Ninja-Property-Set.
    Write-LapsCustomField -Name $CF_AdminsReport -Value $report.Html -Piped

    # 4) Toggle the alert checkbox depending on the audit outcome. An
    #    enabled, unmanaged built-in Administrator is now part of
    #    UnauthorizedAdmins, so a single check covers both cases.
    if (@($report.UnauthorizedAdmins).Count -gt 0) {
        Write-AuditLog -Severity SECURITY -Message "Unauthorized local administrators detected:"
        foreach ($u in $report.UnauthorizedAdmins) {
            Write-AuditLog -Severity SECURITY -Message " - $($u.FullName) (SID $($u.SID))"
        }
        Add-ChangelogEntry -Category 'UnauthorizedDetected' -Message ("{0} unauthorized local administrator(s) still present after cleanup: {1}" -f `
            @($report.UnauthorizedAdmins).Count, `
            (@($report.UnauthorizedAdmins | ForEach-Object { "'$($_.FullName)'" }) -join ', '))
        Write-LapsCustomField -Name $CF_UnauthorizedFlag -Value 1
        # Non-zero exit code so the NinjaOne activity is also visible as failed.
        $exitCode = 1
    }
    else {
        Write-AuditLog -Severity INFO -Message "All local administrators are authorized."
        Write-LapsCustomField -Name $CF_UnauthorizedFlag -Value 0
        $exitCode = 0
    }
}
catch {
    # Make every uncaught failure visible to NinjaOne by raising the
    # alert flag and exiting non-zero. The audit log captures the full
    # exception details for forensics.
    $exitCode = 2
    Write-AuditLog -Severity ERROR -Message "Unhandled exception: $($_.Exception.Message)"
    Write-AuditLog -Severity ERROR -Message "Stack trace: $($_.ScriptStackTrace)"
    Add-ChangelogEntry -Category 'Error' -Message ("Unhandled exception: {0}" -f $_.Exception.Message)
    try { Write-LapsCustomField -Name $CF_UnauthorizedFlag -Value 1 } catch { $null = $_ }
}
finally {
    # Flush the per-run changelog buffer to NinjaOne. Done in finally so
    # the run history is updated even when the main block threw.
    try { Write-LapsChangelog } catch { $null = $_ }

    if ($Script:Rng) {
        try { $Script:Rng.Dispose() } catch { $null = $_ }
    }
    Write-AuditLog -Severity INFO -Message "NinjaOne LAPS script finished with exit code $exitCode."
}

exit $exitCode
#endregion ===================================================================
