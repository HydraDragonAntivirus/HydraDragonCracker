# Find Button Click Event Handler

Write-Host "=== FINDING BUTTON CLICK HANDLER ===" -ForegroundColor Cyan
Write-Host ""

try {
    $asmPath = ".\RikaCrackmeV1.exe"
    $asm = [System.Reflection.Assembly]::LoadFile((Resolve-Path $asmPath).Path)
    
    # Find the Form class
    $formType = $asm.GetTypes() | Where-Object { $_.Name -eq "cyR=" }
    
    if ($formType) {
        Write-Host "Form: $($formType.FullName)" -ForegroundColor Green
        Write-Host ""
        
        # Get all methods
        $methods = $formType.GetMethods([System.Reflection.BindingFlags]::Public -bor [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::Static)
        
        Write-Host "=== ALL NON-SYSTEM METHODS ===" -ForegroundColor Yellow
        
        foreach ($method in $methods) {
            # Skip property getters/setters and system methods
            if ($method.Name -notlike "get_*" -and $method.Name -notlike "set_*" -and $method.Name -notlike "add_*" -and $method.Name -notlike "remove_*" -and $method.Name -notlike "Should*" -and $method.Name -notlike "On*" -and $method.Name -notlike "System.*" -and $method.Name -notlike "Perform*" -and $method.Name -notlike "Validate*" -and $method.Name -notlike "Notify*" -and $method.Name -notlike "Invoke*" -and $method.DeclaringType.Name -eq "cyR=") {
                
                $params = $method.GetParameters()
                $paramStr = ($params | ForEach-Object { "$($_.ParameterType.Name) $($_.Name)" }) -join ", "
                
                Write-Host "  $($method.Name)($paramStr)" -ForegroundColor Cyan
                
                # Check if looks like event handler (object sender, EventArgs e)
                if ($params.Count -eq 2 -and $params[0].ParameterType.Name -like "*Object*" -and $params[1].ParameterType.Name -like "*EventArgs*") {
                    Write-Host "    >>> LIKELY EVENT HANDLER <<<" -ForegroundColor Green
                }
            }
        }
        
        Write-Host ""
        Write-Host "=== OBFUSCATED PRIVATE METHODS ===" -ForegroundColor Yellow
        
        $privateMethods = $methods | Where-Object { $_.IsPrivate -and $_.DeclaringType.Name -eq "cyR=" -and $_.Name -match "^[A-Za-z]{3,4}=" }
        
        foreach ($method in $privateMethods) {
            $params = $method.GetParameters()
            $paramStr = ($params | ForEach-Object { "$($_.ParameterType.Name) $($_.Name)" }) -join ", "
            
            Write-Host "  $($method.Name)($paramStr)" -ForegroundColor White
            
            if ($params.Count -eq 2 -and $params[0].ParameterType.Name -like "*Object*") {
                Write-Host "    >>> POSSIBLE BUTTON CLICK HANDLER <<<" -ForegroundColor Green
            }
        }
        
    } else {
        Write-Host "Form not found!" -ForegroundColor Red
    }
    
} catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== NEXT STEP ===" -ForegroundColor Cyan
Write-Host "Open dnSpy and navigate to:" -ForegroundColor White
Write-Host "  Wbj=.cyR= class" -ForegroundColor Yellow
Write-Host "Look for the method with signature: void MethodName(object, EventArgs)" -ForegroundColor Yellow
Write-Host ""

