# RegisterTask-UnlockAlert.ps1

# Name of the task
$taskname = "Unlock Alert"

# Execute our PowerShell script to send an alert to our webhook
$action = New-ScheduledTaskAction -Execute "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-nop -ep bypass -w hidden C:\Tools\Scripts\Send-UnlockAlert.ps1"

# Create a list of triggers, and add logon trigger to start working with
$triggers = @()
$triggers += New-ScheduledTaskTrigger -AtLogOn

# Create a TaskEventTrigger using CIM, store it in a variable, and write our XML to the Subscription property of that variable
$CIMTriggerClass = Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace Root/Microsoft/Windows/TaskScheduler:MSFT_TaskEventTrigger
$trigger = New-CimInstance -CimClass $CIMTriggerClass -ClientOnly
$trigger.Subscription = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4801)]]</Select>
  </Query>
</QueryList>
"@

# Set the Enabled property to $True, add this information to our trigger list
$trigger.Enabled = $True 
$triggers += $trigger

# Run this hidden, as SYSTEM
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -Hidden

# Register the new task
Register-ScheduledTask "$taskname" -Action $action -Trigger $trigger -Principal $principal -Settings $settings
