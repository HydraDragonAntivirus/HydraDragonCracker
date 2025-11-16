# Find the real System.Windows.Forms.dll in the GAC
$gacPath = Get-ChildItem -Path "C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Windows.Forms" -Recurse | Where-Object { $_.Name -eq 'System.Windows.Forms.dll' } | Select-Object -First 1 -ExpandProperty FullName

if (-not $gacPath) {
    Write-Error "Could not find System.Windows.Forms.dll in the GAC. Ensure .NET Framework 4.8 is installed."
    return
}

Write-Host "Found real DLL at: $gacPath"

# Load the assembly
[System.Reflection.Assembly]::LoadFrom($gacPath) | Out-Null

# HARIÇ TUTMA LİSTESİ KALDIRILDI.
# Tüm dışa aktarılan tipler iletilecektir (CS0729 hatasına neden olacaktır).
$typesToForward = [System.Windows.Forms.Application].Assembly.GetExportedTypes()

$codeLines = New-Object System.Collections.Generic.List[string]

foreach ($type in $typesToForward) {
    # Yalnızca ana (nested olmayan) tipleri ilet.
    if (-not $type.IsNested) {
        
        # Get the full type name from the runtime and make it C#-compatible
        $csTypeName = $type.FullName.Replace('+', '.')

        # Handle generic types correctly
        if ($type.IsGenericTypeDefinition) {
            $baseName = $csTypeName.Split('`')[0]
            $paramCount = $type.GetGenericArguments().Length
            $genericParams = '<' + (',' * ($paramCount - 1)) + '>'
            $formattedName = $baseName + $genericParams
        }
        else {
            $formattedName = $csTypeName
        }
        
        # Add the valid line of code to our list
        $codeLines.Add("[assembly: System.Runtime.CompilerServices.TypeForwardedTo(typeof($formattedName))]")
    }
}

# Save the code to a file on your Desktop
$desktopPath = [Environment]::GetFolderPath("Desktop")
$outputFile = Join-Path $desktopPath "TypeForwarders.cs"
Set-Content -Path $outputFile -Value $codeLines -Encoding UTF8

Write-Host "Success! The TypeForwarders.cs file has been created on your Desktop."