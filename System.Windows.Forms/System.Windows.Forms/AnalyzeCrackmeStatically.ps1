# Static Analysis of RikaCrackme v1 - NO DLL INJECTION
$ErrorActionPreference = "Continue"

Write-Host "=== RIKA CRACKME V1 - STATIC ANALYSIS ===" -ForegroundColor Cyan
Write-Host ""

$exePath = ".\RikaCrackmeV1.exe"
if (-not (Test-Path $exePath)) {
    Write-Host "ERROR: RikaCrackmeV1.exe not found!" -ForegroundColor Red
    exit 1
}

Write-Host "Loading assembly for static analysis..." -ForegroundColor Yellow
$asm = [System.Reflection.Assembly]::LoadFile((Resolve-Path $exePath).Path)

Write-Host "Assembly loaded: $($asm.FullName)" -ForegroundColor Green
Write-Host ""

# ==================================================
# 1. FIND ALL STRING LITERALS
# ==================================================
Write-Host "=== SEARCHING FOR PASSWORD/KEY STRINGS ===" -ForegroundColor Cyan
$types = $asm.GetTypes()
$foundStrings = @{}

foreach ($type in $types) {
    # Get all string fields (potential passwords)
    $fields = $type.GetFields([System.Reflection.BindingFlags]::Public -bor 
                              [System.Reflection.BindingFlags]::NonPublic -bor 
                              [System.Reflection.BindingFlags]::Static -bor 
                              [System.Reflection.BindingFlags]::Instance)
    
    foreach ($field in $fields) {
        if ($field.FieldType -eq [string]) {
            $fieldName = $field.Name.ToLower()
            if ($fieldName -match 'pass|key|serial|code|secret|correct|valid') {
                try {
                    if ($field.IsStatic -and $field.IsLiteral) {
                        $value = $field.GetValue($null)
                        if ($value) {
                            Write-Host "[POTENTIAL PASSWORD]" -ForegroundColor Red -NoNewline
                            Write-Host " $($type.Name).$($field.Name) = " -NoNewline
                            Write-Host """$value""" -ForegroundColor Yellow
                            $foundStrings[$field.Name] = $value
                        }
                    }
                } catch { }
            }
        }
    }
}

Write-Host ""

# ==================================================
# 2. FIND VALIDATION METHODS
# ==================================================
Write-Host "=== SEARCHING FOR VALIDATION METHODS ===" -ForegroundColor Cyan

foreach ($type in $types) {
    $methods = $type.GetMethods([System.Reflection.BindingFlags]::Public -bor 
                                [System.Reflection.BindingFlags]::NonPublic -bor 
                                [System.Reflection.BindingFlags]::Instance -bor 
                                [System.Reflection.BindingFlags]::Static)
    
    foreach ($method in $methods) {
        $methodName = $method.Name.ToLower()
        if ($methodName -match 'check|valid|login|auth|verify|compare') {
            Write-Host ""
            Write-Host "[VALIDATION METHOD] $($type.Name).$($method.Name)" -ForegroundColor Green
            Write-Host "  Return Type: $($method.ReturnType.Name)" -ForegroundColor Gray
            
            $params = $method.GetParameters()
            if ($params.Count -gt 0) {
                Write-Host "  Parameters:" -ForegroundColor Gray
                foreach ($param in $params) {
                    Write-Host "    - $($param.ParameterType.Name) $($param.Name)" -ForegroundColor Gray
                }
            }
            
            # Try to get method body (IL code)
            try {
                $methodBody = $method.GetMethodBody()
                if ($methodBody) {
                    $ilBytes = $methodBody.GetILAsByteArray()
                    Write-Host "  IL Size: $($ilBytes.Length) bytes" -ForegroundColor Gray
                }
            } catch { }
        }
    }
}

Write-Host ""

# ==================================================
# 3. FIND BUTTON CLICK HANDLERS
# ==================================================
Write-Host "=== SEARCHING FOR BUTTON CLICK HANDLERS ===" -ForegroundColor Cyan

foreach ($type in $types) {
    # Check if it's a Form
    $baseType = $type.BaseType
    $isForm = $false
    while ($baseType) {
        if ($baseType.Name -eq "Form") {
            $isForm = $true
            break
        }
        $baseType = $baseType.BaseType
    }
    
    if ($isForm) {
        Write-Host ""
        Write-Host "[FORM] $($type.Name)" -ForegroundColor Yellow
        
        $methods = $type.GetMethods([System.Reflection.BindingFlags]::Public -bor 
                                    [System.Reflection.BindingFlags]::NonPublic -bor 
                                    [System.Reflection.BindingFlags]::Instance)
        
        foreach ($method in $methods) {
            if ($method.Name -like "*_Click" -or $method.Name -like "*Button*") {
                Write-Host "  Event Handler: $($method.Name)" -ForegroundColor Cyan
            }
        }
        
        # Find text boxes
        $fields = $type.GetFields([System.Reflection.BindingFlags]::Public -bor 
                                  [System.Reflection.BindingFlags]::NonPublic -bor 
                                  [System.Reflection.BindingFlags]::Instance)
        
        foreach ($field in $fields) {
            if ($field.FieldType.Name -eq "TextBox") {
                Write-Host "  TextBox: $($field.Name)" -ForegroundColor Green
            }
            if ($field.FieldType.Name -eq "Button") {
                Write-Host "  Button: $($field.Name)" -ForegroundColor Magenta
            }
        }
    }
}

Write-Host ""

# ==================================================
# 4. SEARCH IN EMBEDDED RESOURCES
# ==================================================
Write-Host "=== SEARCHING EMBEDDED RESOURCES ===" -ForegroundColor Cyan
$resources = $asm.GetManifestResourceNames()
foreach ($res in $resources) {
    Write-Host "  Resource: $res" -ForegroundColor Gray
}

Write-Host ""

# ==================================================
# SUMMARY
# ==================================================
Write-Host "=== ANALYSIS COMPLETE ===" -ForegroundColor Cyan
Write-Host ""

if ($foundStrings.Count -gt 0) {
    Write-Host "FOUND $($foundStrings.Count) POTENTIAL PASSWORD(S):" -ForegroundColor Green
    foreach ($key in $foundStrings.Keys) {
        Write-Host "  $key = ""$($foundStrings[$key])""" -ForegroundColor Yellow
    }
} else {
    Write-Host "No hardcoded passwords found in static fields." -ForegroundColor Yellow
    Write-Host "Password might be:" -ForegroundColor Yellow
    Write-Host "  - Computed at runtime" -ForegroundColor Gray
    Write-Host "  - Obfuscated" -ForegroundColor Gray
    Write-Host "  - In method IL code (use dnSpy to view)" -ForegroundColor Gray
}

Write-Host ""
Write-Host "NEXT STEPS:" -ForegroundColor Cyan
Write-Host "1. Open RikaCrackmeV1.exe in dnSpy" -ForegroundColor White
Write-Host "2. Search for the validation methods listed above" -ForegroundColor White
Write-Host "3. Read the IL/C# code to find password logic" -ForegroundColor White
Write-Host ""

