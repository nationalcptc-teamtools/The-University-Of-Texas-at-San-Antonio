<#
Local file exposure inventory for Windows PowerShell 3.0 or later.
Run only on systems and mounted storage you may inspect. Candidate values are
shown without masking and written to a private local text report.
#>
param(
    [string[]]$Root,
    [string]$OutputPath,
    [ValidateRange(1, 4096)][int]$MaxExtractMiB = 256,
    [switch]$SelfTest
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
$script:Pattern = New-Object System.Text.RegularExpressions.Regex -ArgumentList @(
    'password|passwd|passphrase|pwd|secret|token|api[_-]?key|client[_-]?secret|connection[ _-]?string|credential|username|user_name|account_name|private[ _-]?key|://[^\s:/@]+:[^\s@]+@',
    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
)
$script:NamePattern = New-Object System.Text.RegularExpressions.Regex -ArgumentList @(
    '(?:^|[\\/])(?:\.env(?:$|\.)|id_(?:rsa|dsa|ecdsa|ed25519)$|[^\\/]*(?:pass|cred|secret|token|unattend|sysprep|web\.config|\.pem$|\.pfx$|\.kdbx$|\.bak$|\.old$|history))',
    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
)
$script:Files = 0
$script:Findings = 0
$script:Named = 0
$script:Errors = 0
$script:Partial = 0
$script:Extracted = 0
$script:ReparseSkipped = 0
$script:MaxExtractBytes = [long]$MaxExtractMiB * 1048576
$script:RunName = 'host-exposure-' + [Guid]::NewGuid().ToString('N')

function Escape-Text([string]$Text) {
    if ($null -eq $Text) { return '' }
    $Text = $Text.Replace("`r", '\r').Replace("`n", '\n').Replace("`t", '\t')
    return [System.Text.RegularExpressions.Regex]::Replace($Text, '[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '?')
}

function Emit([string]$Text) {
    $safe = Escape-Text $Text
    [Console]::Out.WriteLine($safe)
    $script:Writer.WriteLine($safe)
    $script:Writer.Flush()
}

function Status([string]$Kind, [string]$Path, [string]$Detail) {
    Emit ('STATUS ' + $Kind + ' path=' + (Escape-Text $Path) + ' ' + $Detail)
    if ($Kind -eq 'error' -or $Kind -eq 'unreadable') { $script:Errors++ }
    if ($Kind -eq 'partial' -or $Kind -eq 'unsupported' -or $Kind -eq 'timeout') { $script:Partial++ }
}

function Protect-Path([string]$Path, [bool]$Directory) {
    $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $system = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList @('S-1-5-18')
    $rights = [System.Security.AccessControl.FileSystemRights]::FullControl
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $inherit = [System.Security.AccessControl.InheritanceFlags]::None
    if ($Directory) { $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit }
    $propagate = [System.Security.AccessControl.PropagationFlags]::None
    if ($Directory) { $acl = New-Object System.Security.AccessControl.DirectorySecurity }
    else { $acl = New-Object System.Security.AccessControl.FileSecurity }
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList @($sid, $rights, $inherit, $propagate, $allow)))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList @($system, $rights, $inherit, $propagate, $allow)))
    if ($Directory) { [System.IO.Directory]::SetAccessControl($Path, $acl) }
    else { [System.IO.File]::SetAccessControl($Path, $acl) }
    if ($Directory) { $verified = [System.IO.Directory]::GetAccessControl($Path) }
    else { $verified = [System.IO.File]::GetAccessControl($Path) }
    foreach ($rule in $verified.Access) {
        $ruleSid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
        if ($rule.AccessControlType -eq $allow -and $ruleSid -ne $sid.Value -and $ruleSid -ne $system.Value) {
            throw ('Output ACL has an extra access rule: ' + $Path)
        }
    }
}

function New-PrivateFileSecurity {
    $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $system = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList @('S-1-5-18')
    $rights = [System.Security.AccessControl.FileSystemRights]::FullControl
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $inherit = [System.Security.AccessControl.InheritanceFlags]::None
    $propagate = [System.Security.AccessControl.PropagationFlags]::None
    $acl = New-Object System.Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList @($sid, $rights, $inherit, $propagate, $allow)))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList @($system, $rights, $inherit, $propagate, $allow)))
    return $acl
}

if (-not ('AuditOutputGuard.FileIdentity' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace AuditOutputGuard {
    public static class FileIdentity {
        [StructLayout(LayoutKind.Sequential)]
        private struct NativeFileTime {
            public uint Low;
            public uint High;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct ByHandleFileInformation {
            public uint Attributes;
            public NativeFileTime Creation;
            public NativeFileTime LastAccess;
            public NativeFileTime LastWrite;
            public uint VolumeSerial;
            public uint SizeHigh;
            public uint SizeLow;
            public uint LinkCount;
            public uint IndexHigh;
            public uint IndexLow;
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandle(
            SafeFileHandle handle, out ByHandleFileInformation information);

        public static string Read(SafeFileHandle handle) {
            ByHandleFileInformation info;
            if (!GetFileInformationByHandle(handle, out info))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return String.Format(CultureInfo.InvariantCulture, "{0:X8}:{1:X8}{2:X8}",
                info.VolumeSerial, info.IndexHigh, info.IndexLow);
        }
        public static int StructureSize() {
            return Marshal.SizeOf(typeof(ByHandleFileInformation));
        }
    }
}
'@ -ErrorAction Stop
}
if ([AuditOutputGuard.FileIdentity]::StructureSize() -ne 52) {
    throw 'File identity structure layout is unavailable'
}

function Find-Tool([string]$Name) {
    $cmd = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd) { return $cmd.Source }
    return $null
}

function Process-Line([string]$Line, [string]$Label, [string]$Encoding, [int]$Number) {
    if ($script:Pattern.IsMatch($Line)) {
        Emit ('CANDIDATE path=' + (Escape-Text $Label) + ' source=' + $Encoding + ' line=' + $Number + ' text=' + $Line)
        $script:Findings++
    }
}

function Process-Chunk([string]$Text, [hashtable]$State, [string]$Label, [string]$Encoding) {
    $combined = [string]$State.Tail + $Text
    $lastLF = $combined.LastIndexOf("`n")
    $lastCR = $combined.LastIndexOf("`r")
    $end = [Math]::Max($lastLF, $lastCR)
    if ($end -ge 0) {
        $ready = $combined.Substring(0, $end + 1)
        $reader = New-Object System.IO.StringReader -ArgumentList @($ready)
        try {
            while ($null -ne ($line = $reader.ReadLine())) {
                $State.Line++
                Process-Line $line $Label $Encoding $State.Line
            }
        } finally { $reader.Dispose() }
        $State.Tail = $combined.Substring($end + 1)
    } else { $State.Tail = $combined }
    # A binary file may have no newline. Keep overlap for boundary matches.
    while ($State.Tail.Length -gt 16384) {
        $State.Line++
        Process-Line $State.Tail.Substring(0, 16384) $Label ($Encoding + '-fragment') $State.Line
        $State.Tail = $State.Tail.Substring(15872)
        $State.Fragmented = $true
    }
}

function Scan-Stream([System.IO.Stream]$Stream, [string]$Label, [long]$MaxBytes) {
    $script:LastScanBytes = [long]0
    $encodings = @(
        @{ Name='utf8-or-ascii'; Decoder=([System.Text.Encoding]::UTF8.GetDecoder()); Tail=''; Line=0; Fragmented=$false },
        @{ Name='utf16le'; Decoder=([System.Text.Encoding]::Unicode.GetDecoder()); Tail=''; Line=0; Fragmented=$false },
        @{ Name='utf16be'; Decoder=([System.Text.Encoding]::BigEndianUnicode.GetDecoder()); Tail=''; Line=0; Fragmented=$false }
    )
    $bytes = New-Object byte[] 65536
    $chars = New-Object char[] 131072
    $builder = New-Object System.Text.StringBuilder
    $total = [long]0
    $complete = $true
    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    while ($true) {
        if ($clock.Elapsed.TotalSeconds -ge 300) {
            Status 'timeout' $Label 'stream exceeded 300 seconds'
            $complete = $false
            break
        }
        $readSize = $bytes.Length
        if ($MaxBytes -gt 0) {
            $remaining = $MaxBytes - $total
            if ($remaining -le 0) {
                Status 'partial' $Label ('expanded byte cap=' + $MaxBytes)
                $complete = $false
                break
            }
            if ($remaining -lt $readSize) { $readSize = [int]$remaining }
        }
        $pending = $Stream.BeginRead($bytes, 0, $readSize, $null, $null)
        $wait = $pending.AsyncWaitHandle
        if (-not $wait.WaitOne(60000)) {
            Status 'timeout' $Label 'read exceeded 60 seconds'
            $complete = $false
            $wait.Close()
            break
        }
        $count = $Stream.EndRead($pending)
        $wait.Close()
        if ($count -eq 0) { break }
        $total += $count
        foreach ($state in $encodings) {
            $n = $state.Decoder.GetChars($bytes, 0, $count, $chars, 0, $false)
            [void]$builder.Append($chars, 0, $n)
            Process-Chunk $builder.ToString() $state $Label $state.Name
            [void]$builder.Remove(0, $builder.Length)
        }
        if ($MaxBytes -gt 0 -and $total -ge $MaxBytes) {
            Status 'partial' $Label ('expanded byte cap=' + $MaxBytes)
            $complete = $false
            break
        }
    }
    $clock.Stop()
    foreach ($state in $encodings) {
        $n = $state.Decoder.GetChars((New-Object byte[] 0), 0, 0, $chars, 0, $true)
        if ($n -gt 0) {
            [void]$builder.Append($chars, 0, $n)
            Process-Chunk $builder.ToString() $state $Label $state.Name
            [void]$builder.Remove(0, $builder.Length)
        }
        if ($state.Tail.Length -gt 0) {
            $state.Line++
            Process-Line $state.Tail $Label $state.Name $state.Line
        }
    }
    $script:LastScanBytes = $total
    return $complete
}

function Scan-ZipNative([string]$Path) {
    try {
        Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
        $archive = [System.IO.Compression.ZipFile]::OpenRead($Path)
        try {
            $remaining = $script:MaxExtractBytes
            foreach ($entry in $archive.Entries) {
                if ($entry.Name.Length -eq 0) { continue }
                if ($remaining -le 0) { Status 'partial' $Path ('expanded byte cap=' + $script:MaxExtractBytes); break }
                $stream = $entry.Open()
                try { $complete = Scan-Stream $stream ($Path + '!' + $entry.FullName) $remaining }
                finally { $stream.Dispose() }
                $remaining -= $script:LastScanBytes
                if (-not $complete) { break }
            }
            $script:Extracted++
        } finally { $archive.Dispose() }
    } catch { Status 'unsupported' $Path ('ZIP decode unavailable: ' + $_.Exception.Message) }
}

function Scan-External([string]$Path, [string]$Tool, [string]$Arguments, [string]$Kind) {
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $Tool
    $info.Arguments = $Arguments
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = [System.Diagnostics.Process]::Start($info)
    try {
        $process.BeginErrorReadLine()
        $done = Scan-Stream $process.StandardOutput.BaseStream ($Path + '!' + $Kind) $script:MaxExtractBytes
        if (-not $done) { try { $process.Kill() } catch {} }
        if (-not $process.WaitForExit(60000)) {
            try { $process.Kill() } catch {}
            Status 'timeout' $Path ($Kind + ' extractor exceeded 60 seconds')
        } elseif ($process.ExitCode -ne 0) {
            Status 'partial' $Path ($Kind + ' extractor exit=' + $process.ExitCode)
        }
        $script:Extracted++
    } finally { $process.Dispose() }
}

function Scan-File([string]$Path) {
    $normalized = $Path
    try { $normalized = [System.IO.Path]::GetFullPath($Path) } catch {}
    if ([string]::Equals($normalized, $script:OutputPath, [System.StringComparison]::OrdinalIgnoreCase)) { return }
    $script:Files++
    try {
        $stream = New-Object System.IO.FileStream -ArgumentList @($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    } catch {
        if ($script:NamePattern.IsMatch($Path)) {
            Emit ('CANDIDATE path=' + (Escape-Text $Path) + ' source=filename text=interesting-name')
            $script:Named++
        }
        Status 'unreadable' $Path $_.Exception.Message
        return
    }
    try {
        try { $identity = [AuditOutputGuard.FileIdentity]::Read($stream.SafeFileHandle) }
        catch { Status 'unsupported' $Path ('file identity unavailable; skipped: ' + $_.Exception.Message); return }
        if ($identity -eq $script:ReportIdentity) { $script:Files--; return }
        if ($script:NamePattern.IsMatch($Path)) {
            Emit ('CANDIDATE path=' + (Escape-Text $Path) + ' source=filename text=interesting-name')
            $script:Named++
        }
        try { [void](Scan-Stream $stream $Path 0) }
        catch { Status 'unreadable' $Path $_.Exception.Message; return }
    } finally { $stream.Dispose() }
    $ext = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
    $sevenZip = Find-Tool '7z.exe'
    if ($null -eq $sevenZip) { $sevenZip = Find-Tool '7za.exe' }
    if ($ext -match '^\.(zip|7z|tar|gz|tgz|bz2|xz|docx|xlsx|pptx|odt|ods|odp)$') {
        if ($sevenZip) {
            try { Scan-External $Path $sevenZip ('x -so -y "' + $Path + '"') 'expanded-stream' }
            catch { Status 'partial' $Path ('archive extraction: ' + $_.Exception.Message) }
        } elseif ($ext -match '^\.(zip|docx|xlsx|pptx|odt|ods|odp)$') {
            Scan-ZipNative $Path
        } else { Status 'unsupported' $Path 'archive extractor unavailable' }
    } elseif ($ext -eq '.pdf') {
        $pdf = Find-Tool 'pdftotext.exe'
        if ($pdf) {
            try { Scan-External $Path $pdf ('-layout -enc UTF-8 "' + $Path + '" -') 'pdf-text' }
            catch { Status 'partial' $Path ('PDF extraction: ' + $_.Exception.Message) }
        } else { Status 'unsupported' $Path 'pdftotext unavailable' }
    } elseif ($ext -eq '.doc') {
        $antiword = Find-Tool 'antiword.exe'
        if ($antiword) {
            try { Scan-External $Path $antiword ('"' + $Path + '"') 'doc-text' }
            catch { Status 'partial' $Path ('DOC extraction: ' + $_.Exception.Message) }
        } else { Status 'unsupported' $Path 'antiword unavailable' }
    } elseif ($ext -match '^\.(kdbx|pfx|p12|gpg|age|enc)$') {
        Status 'unsupported' $Path 'protected format not decrypted'
    }
}

function Scan-Root([string]$Start) {
    Emit ('MOUNT path=' + (Escape-Text $Start))
    $stack = New-Object 'System.Collections.Generic.Stack[string]'
    $stack.Push($Start)
    while ($stack.Count -gt 0) {
        $directory = $stack.Pop()
        $enumerationErrors = @()
        try { $children = Get-ChildItem -LiteralPath $directory -Force -ErrorAction SilentlyContinue -ErrorVariable +enumerationErrors }
        catch { Status 'error' $directory ('enumeration: ' + $_.Exception.Message); continue }
        foreach ($problem in $enumerationErrors) { Status 'error' $directory ('enumeration: ' + $problem.Exception.Message) }
        foreach ($child in $children) {
            if (($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { $script:ReparseSkipped++; continue }
            if ($child.PSIsContainer) { $stack.Push($child.FullName) }
            else { Scan-File $child.FullName }
        }
    }
}

if ($SelfTest) {
    $script:Writer = New-Object System.IO.StringWriter
    try {
        $fixture = [System.Text.Encoding]::UTF8.GetBytes("username=fixture-user`npassword=fixture-value`n")
        $stream = New-Object System.IO.MemoryStream -ArgumentList @(,$fixture)
        try { [void](Scan-Stream $stream 'memory-fixture' 0) }
        finally { $stream.Dispose() }
        $fixture = [System.Text.Encoding]::Unicode.GetBytes("secret=fixture-utf16`n")
        $stream = New-Object System.IO.MemoryStream -ArgumentList @(,$fixture)
        try { [void](Scan-Stream $stream 'utf16-fixture' 0) }
        finally { $stream.Dispose() }
        $fixture = [byte[]](0, 1) + [System.Text.Encoding]::ASCII.GetBytes('api_key=fixture-binary') + [byte[]](0, 2)
        $stream = New-Object System.IO.MemoryStream -ArgumentList @(,$fixture)
        try { [void](Scan-Stream $stream 'binary-fixture' 0) }
        finally { $stream.Dispose() }
        $report = $script:Writer.ToString()
        if ($script:Findings -lt 4 -or $report -notmatch 'fixture-value' -or $report -notmatch 'fixture-utf16' -or $report -notmatch 'fixture-binary') { throw 'Stream self-test failed' }
        [Console]::Out.WriteLine('SELFTEST OK')
    } finally { $script:Writer.Dispose() }
    return
}

$defaultOutput = [string]::IsNullOrEmpty($OutputPath)
if ($defaultOutput) {
    $OutputPath = Join-Path $env:LOCALAPPDATA ('HostExposureAudit\scan-' + (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ') + '-' + $script:RunName + '.txt')
}
$OutputPath = [System.IO.Path]::GetFullPath($OutputPath)
$script:OutputPath = $OutputPath
$parent = [System.IO.Path]::GetDirectoryName($OutputPath)
if ([System.IO.File]::Exists($OutputPath) -or [System.IO.Directory]::Exists($OutputPath)) {
    [Console]::Error.WriteLine('Output already exists')
    exit 1
}
[void][System.IO.Directory]::CreateDirectory($parent)
if ($defaultOutput) { Protect-Path $parent $true }
$privateSecurity = New-PrivateFileSecurity
$file = New-Object System.IO.FileStream -ArgumentList @($OutputPath, [System.IO.FileMode]::CreateNew, [System.Security.AccessControl.FileSystemRights]::Write, [System.IO.FileShare]::Read, 4096, [System.IO.FileOptions]::None, $privateSecurity)
try {
    $script:ReportIdentity = [AuditOutputGuard.FileIdentity]::Read($file.SafeFileHandle)
    Protect-Path $OutputPath $false
    $encoding = New-Object System.Text.UTF8Encoding -ArgumentList @($false)
    [Console]::OutputEncoding = $encoding
    $script:Writer = New-Object System.IO.StreamWriter -ArgumentList @($file, $encoding)
    try {
        Emit 'Host Exposure Audit: candidate findings, not verified credentials'
        Emit ('UTC ' + (Get-Date).ToUniversalTime().ToString('o'))
        Emit ('HOST ' + [Environment]::MachineName + ' OS ' + [Environment]::OSVersion.VersionString + ' ID ' + [System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
        Emit ('REPORT ' + $OutputPath)
        try {
            Get-WmiObject -Class Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop | ForEach-Object {
                Emit ('LOCAL_USER name=' + $_.Name + ' sid=' + $_.SID + ' disabled=' + $_.Disabled)
            }
        } catch { Status 'error' 'local-users' $_.Exception.Message }
        $starts = New-Object 'System.Collections.Generic.List[string]'
        if ($Root -and $Root.Count -gt 0) {
            foreach ($r in $Root) { [void]$starts.Add($r) }
        } else {
            try {
                Get-PSDrive -PSProvider FileSystem | ForEach-Object { if ($_.Root) { [void]$starts.Add($_.Root) } }
                Get-WmiObject -Class Win32_Volume -ErrorAction Stop | ForEach-Object {
                    if ($_.DriveLetter) { [void]$starts.Add($_.DriveLetter + '\') }
                    elseif ($_.Name) { [void]$starts.Add($_.Name) }
                }
            } catch { Status 'error' 'mount-discovery' $_.Exception.Message }
        }
        $seen = @{}
        foreach ($start in $starts) {
            if ([string]::IsNullOrEmpty($start)) { continue }
            $key = $start.TrimEnd('\').ToLowerInvariant()
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            if ([System.IO.File]::Exists($start)) { Scan-File $start }
            elseif ([System.IO.Directory]::Exists($start)) { Scan-Root $start }
            else { Status 'error' $start 'root unavailable' }
        }
        Emit ('SUMMARY regular_files=' + $script:Files + ' content_findings=' + $script:Findings + ' interesting_names=' + $script:Named + ' extracted_files=' + $script:Extracted + ' reparse_skipped=' + $script:ReparseSkipped + ' errors=' + $script:Errors + ' partial_or_unsupported=' + $script:Partial)
    } finally { $script:Writer.Dispose() }
} finally { if ($file) { $file.Dispose() } }
