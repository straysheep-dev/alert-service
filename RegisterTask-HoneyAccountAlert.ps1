# RegisterTask-HoneyAccountAlert.ps1

$honeyaccount = "<account-name>"
$taskname = "Honey Account Alert"
$action = New-ScheduledTaskAction -Execute "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-nop -ep bypass -w hidden C:\Tools\Scripts\Send-LoginAlert.ps1"
$trigger = New-ScheduledTaskTrigger -AtLogon -User "$honeyaccount"
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -Hidden
Register-ScheduledTask "$taskname" -Action $action -Trigger $trigger -Principal $principal -Settings $settings
