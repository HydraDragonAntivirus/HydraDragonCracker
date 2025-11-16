# Extract Button Click Handler Code using Reflection

Write-Host "=== EXTRACTING BUTTON CLICK HANDLER ===" -ForegroundColor Cyan
Write-Host ""

try {
    Add-Type -AssemblyName System.Reflection
    
    $asmPath = ".\RikaCrackmeV1.exe"
    $asm = [System.Reflection.Assembly]::LoadFile((Resolve-Path $asmPath).Path)
    
    # Find the Form class
    $formType = $asm.GetTypes() | Where-Object { $_.Name -eq "cyR=" }
    
    if ($formType) {
        # Get the button click handler method
        $clickMethod = $formType.GetMethod("qCn=", [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Instance)
        
        if ($clickMethod) {
            Write-Host "Method Found: $($clickMethod.Name)" -ForegroundColor Green
            Write-Host "Return Type: $($clickMethod.ReturnType.Name)" -ForegroundColor Gray
            Write-Host ""
            
            # Get method body
            $methodBody = $clickMethod.GetMethodBody()
            
            if ($methodBody) {
                Write-Host "=== METHOD INFO ===" -ForegroundColor Yellow
                Write-Host "Max Stack Size: $($methodBody.MaxStackSize)" -ForegroundColor Gray
                Write-Host "Local Variables: $($methodBody.LocalVariables.Count)" -ForegroundColor Gray
                Write-Host "IL Code Size: $($methodBody.GetILAsByteArray().Length) bytes" -ForegroundColor Gray
                Write-Host ""
                
                # Get IL bytes
                $ilBytes = $methodBody.GetILAsByteArray()
                Write-Host "=== IL BYTES (First 100) ===" -ForegroundColor Yellow
                Write-Host ($ilBytes[0..([Math]::Min(99, $ilBytes.Length-1))] | ForEach-Object { $_.ToString("X2") }) -join " "
                Write-Host ""
                
                Write-Host "=== LOCAL VARIABLES ===" -ForegroundColor Yellow
                foreach ($localVar in $methodBody.LocalVariables) {
                    Write-Host "  $($localVar.LocalIndex): $($localVar.LocalType.Name)" -ForegroundColor White
                }
                Write-Host ""
            }
            
            # Try to get string constants used in method
            Write-Host "=== REFERENCED STRINGS (scanning IL) ===" -ForegroundColor Yellow
            
            # This is a simplified approach - real IL parsing would be more complex
            Write-Host "(Note: For full decompilation, use dnSpy GUI)" -ForegroundColor Gray
            Write-Host ""
            
        } else {
            Write-Host "Method qCn= not found!" -ForegroundColor Red
        }
        
    } else {
        Write-Host "Form not found!" -ForegroundColor Red
    }
    
} catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.Exception.StackTrace -ForegroundColor Gray
}

Write-Host ""
Write-Host "=== ACTION REQUIRED ===" -ForegroundColor Cyan
Write-Host "Open dnSpy and view the decompiled C# code for:" -ForegroundColor White
Write-Host "  Class: Wbj=.cyR=" -ForegroundColor Yellow
Write-Host "  Method: qCn=(Object VlT=, EventArgs hCD=)" -ForegroundColor Yellow
Write-Host ""
Write-Host "This method contains the password/serial check logic!" -ForegroundColor Green
Write-Host ""

