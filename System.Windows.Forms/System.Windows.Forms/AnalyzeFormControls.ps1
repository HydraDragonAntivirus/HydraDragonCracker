# Analyze Form Controls in RikaCrackmeV1.exe

Write-Host "=== ANALYZING FORM CONTROLS ===" -ForegroundColor Cyan
Write-Host ""

try {
    $asmPath = ".\RikaCrackmeV1.exe"
    $asm = [System.Reflection.Assembly]::LoadFile((Resolve-Path $asmPath).Path)
    
    Write-Host "Assembly loaded: $($asm.FullName)" -ForegroundColor Green
    Write-Host ""
    
    # Find the Form class: cyR=
    $formType = $asm.GetTypes() | Where-Object { $_.Name -eq "cyR=" }
    
    if ($formType) {
        Write-Host "FORM FOUND: $($formType.FullName)" -ForegroundColor Green
        Write-Host ""
        
        Write-Host "=== FIELDS ===" -ForegroundColor Yellow
        $fields = $formType.GetFields([System.Reflection.BindingFlags]::Public -bor [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Instance)
        
        foreach ($field in $fields) {
            $fieldName = $field.Name
            $fieldType = $field.FieldType.Name
            
            Write-Host "  $fieldName : $fieldType" -ForegroundColor White
            
            # Highlight interesting controls
            if ($fieldType -like "*TextBox*" -or $fieldType -like "*Button*" -or $fieldType -like "*Label*") {
                Write-Host "    >>> CONTROL: $fieldType <<<" -ForegroundColor Green
            }
        }
        
        Write-Host ""
        Write-Host "=== METHODS ===" -ForegroundColor Yellow
        $methods = $formType.GetMethods([System.Reflection.BindingFlags]::Public -bor [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Instance) | Where-Object { $_.Name -like "*Click*" -or $_.Name -like "*Check*" -or $_.Name -like "*Valid*" -or $_.Name -like "*Login*" -or $_.Name -like "*Password*" }
        
        foreach ($method in $methods) {
            Write-Host "  $($method.Name)()" -ForegroundColor Cyan
        }
        
    } else {
        Write-Host "Form cyR= not found!" -ForegroundColor Red
    }
    
} catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""

