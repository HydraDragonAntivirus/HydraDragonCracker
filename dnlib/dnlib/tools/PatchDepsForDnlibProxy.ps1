param(
    [Parameter(Mandatory = $true)]
    [string]$DepsJsonPath,

    [string]$Version = "4.5.0.0",
    [string]$RuntimeFile = "dnlib.real.dll"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $DepsJsonPath)) {
    throw "deps.json not found: $DepsJsonPath"
}

function Add-JsonProperty($Object, [string]$Name, $Value) {
    $property = $Object.PSObject.Properties[$Name]
    if ($property) {
        $property.Value = $Value
    }
    else {
        $Object | Add-Member -MemberType NoteProperty -Name $Name -Value $Value
    }
}

$depsPath = (Resolve-Path $DepsJsonPath).Path
$deps = Get-Content -Path $depsPath -Raw | ConvertFrom-Json
$targetName = $deps.targets.PSObject.Properties.Name | Select-Object -First 1
if (-not $targetName) {
    throw "No target section found in $depsPath"
}

$target = $deps.targets.$targetName
$rootEntries = @()

foreach ($entry in $target.PSObject.Properties) {
    if ($entry.Name -eq "dnlib.real/$Version") {
        continue
    }

    $dependencies = $entry.Value.dependencies
    if ($dependencies -and $dependencies.PSObject.Properties["dnlib"]) {
        $rootEntries += $entry.Value
    }
}

if ($rootEntries.Count -eq 0) {
    foreach ($entry in $target.PSObject.Properties) {
        if ($entry.Value.dependencies) {
            $rootEntries += $entry.Value
            break
        }
    }
}

foreach ($rootEntry in $rootEntries) {
    if (-not $rootEntry.dependencies) {
        Add-JsonProperty $rootEntry "dependencies" ([pscustomobject]@{})
    }
    Add-JsonProperty $rootEntry.dependencies "dnlib.real" $Version
}

$runtime = [pscustomobject]@{}
Add-JsonProperty $runtime $RuntimeFile ([pscustomobject]@{
    assemblyVersion = $Version
    fileVersion = $Version
})

Add-JsonProperty $target "dnlib.real/$Version" ([pscustomobject]@{
    runtime = $runtime
})

Add-JsonProperty $deps.libraries "dnlib.real/$Version" ([pscustomobject]@{
    type = "reference"
    serviceable = $false
    sha512 = ""
})

$json = $deps | ConvertTo-Json -Depth 100
Set-Content -Path $depsPath -Value $json -Encoding UTF8
Write-Host "Patched $depsPath with dnlib.real/$Version"
