param([ValidateSet('protect', 'unprotect')][string]$Mode)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$inputBytes = $null
$outputBytes = $null
$memory = $null
try {
    Add-Type -AssemblyName System.Security
    $source = [Console]::OpenStandardInput()
    $memory = New-Object System.IO.MemoryStream
    $buffer = New-Object byte[] 8192
    while (($count = $source.Read($buffer, 0, $buffer.Length)) -gt 0) {
        if (($memory.Length + $count) -gt 4194304) { throw 'Invalid input' }
        $memory.Write($buffer, 0, $count)
    }
    $inputBytes = $memory.ToArray()
    if ($inputBytes.Length -eq 0) { throw 'Invalid input' }
    $scope = [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    if ($Mode -eq 'protect') {
        $outputBytes = [System.Security.Cryptography.ProtectedData]::Protect($inputBytes, $null, $scope)
    } elseif ($Mode -eq 'unprotect') {
        $outputBytes = [System.Security.Cryptography.ProtectedData]::Unprotect($inputBytes, $null, $scope)
    } else { throw 'Invalid operation' }
    if ($outputBytes.Length -eq 0 -or $outputBytes.Length -gt 4194304) { throw 'Invalid output' }
    $destination = [Console]::OpenStandardOutput()
    $destination.Write($outputBytes, 0, $outputBytes.Length)
    $destination.Flush()
} catch {
    [Console]::Error.WriteLine('DPAPI operation failed')
    exit 1
} finally {
    if ($null -ne $inputBytes) { [Array]::Clear($inputBytes, 0, $inputBytes.Length) }
    if ($null -ne $outputBytes) { [Array]::Clear($outputBytes, 0, $outputBytes.Length) }
    if ($null -ne $buffer) { [Array]::Clear($buffer, 0, $buffer.Length) }
    if ($null -ne $memory) { $memory.Dispose() }
}
