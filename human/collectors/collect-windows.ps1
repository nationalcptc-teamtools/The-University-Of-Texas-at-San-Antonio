<#
.SYNOPSIS
    Human-run local Windows inventory collector.
.DESCRIPTION
    Uses local CIM and service metadata only. It does not use remoting,
    network discovery, credentials, prompts, raw ACL descriptors, or mutation.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $Target
)

$ErrorActionPreference = 'Stop'
$records = New-Object System.Collections.Generic.List[object]
$issues = New-Object System.Collections.Generic.List[string]
$controls = [ordered]@{ network_access = $false; sudo_used = $false; service_changes = $false }

try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $records.Add([ordered]@{ kind = 'identity'; sid = $identity.User.Value; domain_sid = 'unknown'; domain_name = ([string]$computer.Domain).Substring(0, [Math]::Min(128, ([string]$computer.Domain).Length)) })
} catch {
    $issues.Add('unsupported_identity')
}

# Service names and state are local metadata. ACL descriptors remain unsupported.
try {
    Get-Service | Sort-Object -Property Name | Select-Object -First 96 | ForEach-Object {
        $state = switch ([string]$_.Status) { 'Running' { 'running' } 'Stopped' { 'stopped' } default { 'unknown' } }
        $records.Add([ordered]@{ kind = 'service'; name = ([string]$_.Name).Substring(0, [Math]::Min(128, ([string]$_.Name).Length)); state = $state })
    }
} catch {
    $issues.Add('unsupported_service_metadata')
}

$issues.Add('unsupported_service_acl')
$issues.Add('unsupported_task_acl')
$issues.Add('manual_controlled_account_review_required')
$issues.Add('unsupported_smb_ldap_policy_metadata')
[ordered]@{ schema = 'cptc.windows_ad.inventory.v1'; target = $Target.Substring(0, [Math]::Min(256, $Target.Length)); controls = $controls; records = @($records | Select-Object -First 256); issues = @($issues | Sort-Object -Unique) } | ConvertTo-Json -Compress -Depth 5
