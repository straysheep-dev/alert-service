# Alerting

*Send an alert (to Discord, Slack, or any webhook) based on a condition, from a Linux or Windows host.*

The code examples and scripts are copy & paste ready to use. Add your webhook, and change the variables or filepaths as needed.

This project is based on two of ippsec's videos documenting the same concept:

- [Creating Webhooks in Slack for PowerShell](https://www.youtube.com/watch?v=1w0btuMAvZk)
- [Send Notifications to Slack via Scheduled Task Event Filter](https://www.youtube.com/watch?v=J9owPmgmfvo)

Combined with the concepts taught in Antisyphon's Cyber Deception course:

- [Cyber Deception/Active Defense](https://www.antisyphontraining.com/live-courses-catalog/active-defense-cyber-deception-w-john-strand/)
- [Intro Lab Files](https://github.com/strandjs/IntroLabs/blob/master/IntroClassFiles/navigation.md)

This type of alerting provides huge value without the need to set up much infrastructure, as Discord and Slack are free to use, and operating systems have actionable logging avaialble we can leverage with minial configuration.

This repo details examples on how to impliment the alerting itself and expands upon the references above. IppSec's videos go into further detail on Sysmon logs, ways to use the Task Scheduler and [deploying it as a GPO](https://www.youtube.com/watch?v=J9owPmgmfvo&t=1545s). Cyber Deception will show you the fundamentals of how to proactively detect suspicious activity. With all three combined, the goal is you'll hopefully have greater visibility into your environment with minimal overhead.


## Setup in Slack or Discord

*Specific steps and menus may change over time, this is the general process in both Slack and Discord for reference.*

- Create a channel
- Set it to private (or read-only by admins)
- [Slack: Create a Slack app > Enable Incoming Webhooks > Create an Incoming Webhook](https://api.slack.com/messaging/webhooks)
- [Discord: Go to Server Settings > Integrations > View Webhooks > New Webhook](https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks)

This allows the Webhook to post / send messages to this channel.


# Windows

*Steps for Windows auditing and alerting.*


## Configure Auditing

*Configurations required to generate log entries.*


### Audit Logon Events

[Audit Logon Events](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-logon-events)

- By default logon / logoff events are logged to Security events
- We will also enable auditing for workstation unlock events to the Security event log
- GPO Path: Local Computer Policy > Windows Settings > Security Settings > Local Policies > Audit Policy > **Audit logon events** > ✅ Success

Enable workstation unlock audit policy with: 

```powershell
auditpol.exe /set /Category:"Logon/Logoff" /success:enable
```

Obtain related event logs: 

```powershell
# Logon with explicit credentials
Get-WinEvent -FilterHashtable @{ Logname='Security'; StartTime=(Get-Date).AddDays(-1); Id='4648' }

# Workstation unlock events
Get-WinEvent -FilterHashtable @{ Logname='Security'; StartTime=(Get-Date).AddDays(-1); Id='4801' }
```

Event IDs:

- [4648: Logon with explicit credentials](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4648) (most accurate for logins)
- [4801: Workstation unlock](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4801)
- [4624: Account was logged in](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624) (noisy and harder to parse compared to 4648)


### Audit Specific Files

*Steps and detailed screenshots are available in the link below. This section builds on that information.*

[Antisyphon Cyber Deception - File Auditing](https://github.com/strandjs/IntroLabs/blob/master/IntroClassFiles/Tools/IntroClass/FileAudit/FileAudit.md)

- GPO Path: Local Computer Policy > Windows Settings > Security Settings > Local Policies > Audit Policy > **Audit object access** > ✅ Success & ✅ Failure

Enable audit object access policy with: 

```cmd
auditpol.exe /set /category:"Object Access" /success:enable /failure:enable
```

Use PowerShell to apply full auditing to a file:

- Matches the same settings described above, logging any type of access (aka **FullControl**) to the file by any user
- Syntax is essentially the same as `FileSystemAccessRule`'s .NET method, only for auditing instead of accessing (*Credit to ChatGPT for pointing this out*)
- [FileSystemAuditRule](https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.filesystemauditrule.-ctor?view=net-7.0#system-security-accesscontrol-filesystemauditrule-ctor(system-security-principal-identityreference-system-security-accesscontrol-filesystemrights-system-security-accesscontrol-auditflags))
- [Set-Acl: Grant Administrators Full Control of a File](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-acl?view=powershell-7.3#example-5-grant-administrators-full-control-of-the-file)

```powershell
# Target file to audit
$path = "C:\Path\To\Secrets.txt"

# Get the ACL of the file as a variable to begin working with it
$NewAcl = Get-Acl -Path $path

# Set audit rule to log any kind of access to the file by any user
$identity = "Everyone"
$fileSystemRights = "FullControl"
$type = "Success,Failure"
$fileSystemAuditRuleArgumentList = $identity, $fileSystemRights, $type
$fileSystemAuditRule = New-Object System.Security.AccessControl.FileSystemAuditRule -ArgumentList $fileSystemAuditRuleArgumentList

# Add the audit rule to the file's ACL we're currently editing
$NewAcl.AddAuditRule($fileSystemAuditRule)

# Apply the updated ACL
Set-Acl -Path $path -AclObject $NewAcl
```

Event IDs:

- [4656: A handle to an object was requested](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4656) (use this Event ID for monitoring files)
- [4663: An attempt was made to access an object](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4663)

Additional references from Microsoft:

- [Apply a basic audit policy on a file or folder](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/apply-a-basic-audit-policy-on-a-file-or-folder)
- [Security Recommendations for Event Id 4663](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4663#security-monitoring-recommendations) (for additional considerations)
- [Monitoring Recommendations for Audit Events](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/appendix-a-security-monitoring-recommendations-for-many-audit-events)


## Create the Scheduled Task (GUI)

*This section is built upon information taken from the following video:*

[IppSec - Send Notifications to Slack via Scheduled Task Event Filter](https://www.youtube.com/watch?v=J9owPmgmfvo)

Overview:

- Use [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), or any built in event log (e.g. Security, System)
- Create a Scheduled Task to perform an action on an event (or any trigger that works for your use case)
- Send a useful message to Slack or Discord (we'll use a PowerShell script to handle this)

Each Scheduled Task uses it's own PowerShell script to send event data to the webhook:

- File Audit Alert: Send-FileAlert.ps1
- Unlock Alert: Send-UnlockAlert.ps1
- Login Alert: Send-UnlockAlert.ps1

#### General Tab: General guidance on creating the Schedule Task

- **Run the Task Scheduler as Administrator** you want the task author to be an administrative user to restrict modification
- When debugging issues with a task, get task history logs with `Enable All Tasks History`
- Tasks saved to `\` appear under the top folder, `Task Scheduler Library`. This is the default location when creating tasks.
- Oppsec note: task details are typically restricted based on Author. Restrict read-access to any sensitive scripts. This is detailed below.
- **General: Change user to `SYSTEM` for tasks that require elevated prvileges (e.g. reading and parsing event logs)**
- **General: Check "run with highest privilege" only if you need it (e.g. reading and parsing event logs)**
- General: Check `Hidden` to have the task run hidden from the UI (silently in the background)

#### Triggers Tab: Obtain the raw XML for Event Filters

- Triggers: New > "On an event" > select `Custom` > `New Event Filter...`
- New Event Filter: We'll choose any existing log to generate the XML for us to use
- Next to `By log Event logs:` you could use `Windows Logs` > then check `Security`
- Enter an Event Id number (we'll use 4801) into the bar that says `<All Event IDs>`
- Now at the top next to the `Filter` tab, choose `XML`
- This is your raw query in XML, copy it to a file to work with it, it can be adapted manually or generated for other logs by following these steps

#### Editing raw XML

[Tech Community: XML Event Filtering](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/advanced-xml-filtering-in-the-windows-event-viewer/ba-p/399761)

- Generate an XML template from the Task Scheduler GUI (described just above)
- You can instead use `Export-ScheduleTask` to print the raw XML of a task to the console for review
- Raw XML fields for event logs can be extracted from the EventViewer under the XML tab

This is an example for the XML Filter required to execute on an audited file (the file being Secrets.txt):

```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4656)]] and
      *[EventData[Data[@Name='ObjectName'] and (Data='C:\Path\To\Secrets.txt')]]
    </Select>
  </Query>
</QueryList>
```

Example XML Filter required to execute on Event ID 4801, workstation unlock:

```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4801)]]</Select>
  </Query>
</QueryList>
```

*Wildcards: There does not appear to be any way to do regex or wildcard matching with the XML. If there's a way to use wildcards to audit a specific set of files, for example anything with `Z:\Share` and `.xlsx` in the ObjectName, that could be implemented here, and a matching list or regex would be used instead of the full path to a single file in the Send-FileAlert.ps1 PowerShell script.*


#### Actions Tab: Using a Shell with Arguments

- It's best to use `powershell.exe` or `cmd.exe` as the program to execute scripts (even though script paths work)
- If you use a script path: You must embed arguments like `-nop -ep bypass -w hidden` into the script itself
- If you use a shell as the program: You can specify those arguments here in the Scheduled Task Actions
- Actions: Program/script: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- Actions: Arguments: `-nop -ep bypass -w hidden C:\Tools\Scripts\Send-FileAlert.ps1`


## Create the Scheduled Task (PowerShell)

*Avoid the Task Scheduler GUI and deploy these with PowerShell.*

- [New-ScheduledTask](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtask?view=windowsserver2022-ps)

*There are a few things to be aware of before starting when handling your scheduled tasks entirely in PowerShell.*

- There's no way to import the raw XML of a Task using PowerShell like how you can `Export-ScheduledTask`
- There's no built in way to specify certain triggers, or describe events, for the `New-ScheduledTaskTrigger` cmdlet

Let's compare the output of the Trigger properties of two separate Scheduled Tasks, one to Trigger on Workstation Unlock, and one to trigger on Event ID 4801 (which is the Event ID for a Workstation Unlock):

```powershell
PS C:\Windows\system32> Get-ScheduledTask "Event Unlock Alert" | Select -ExpandProperty Triggers


Enabled            : True
EndBoundary        :
ExecutionTimeLimit :
Id                 :
Repetition         : MSFT_TaskRepetitionPattern
StartBoundary      :
Delay              :
Subscription       : <QueryList><Query Id="0" Path="Security"><Select Path="Security">*[System[(EventID=4801)]]</Select></Query></QueryList>
ValueQueries       :
PSComputerName     :



PS C:\Windows\system32> Get-ScheduledTask "Unlock Alert" | Select -ExpandProperty Triggers


Enabled            : True
EndBoundary        :
ExecutionTimeLimit :
Id                 :
Repetition         : MSFT_TaskRepetitionPattern
StartBoundary      :
Delay              :
StateChange        : 8
UserId             :
PSComputerName     :
```

You'll see `Subscription` and `StateChange` are unique and have data.

We want to write these in PowerShell as properties of the `-Trigger` argument to `Register-ScheduledTask`.

A way to visualize this is by running this on Scheduled Tasks we've already created in the GUI (if you followed along above) and using `-ExpandProperty` on each argument required to register a Scheduled Task to see what each argument's property value is:

```powershell
Get-ScheduledTask "Unlock Alert" | Select -ExpandProperty Principal
Get-ScheduledTask "Unlock Alert" | Select -ExpandProperty Actions
Get-ScheduledTask "Unlock Alert" | Select -ExpandProperty Triggers
Get-ScheduledTask "Unlock Alert" | Select -ExpandProperty Settings
```

#### Working with XML

So we need a way of passing raw XML to the trigger using PowerShell. This post: [Stack Overflow - Register Scheduled Task (with PowerShell) to Trigger on an Event](https://stackoverflow.com/questions/57552869/register-scheduled-task-with-new-scheduledtasktrigger-to-trigger-on-event-id) shows an example of how to work with the raw XML in PowerShell.

***Credit goes to this answer for demonstrating how to pass XML as an argument to Scheduled Task triggers. That code block has been modified and used below.***

Through trial and error we'll find that the `Subscription` Trigger property works as expected, while the `StateChange` property does not. For now we'll move ahead with `Subscription`. So what does this look like? We need to use the following cmdlets from the Stack Overflow example:

#### Get-CimClass

- [Get-CimClass](https://learn.microsoft.com/en-us/powershell/module/cimcmdlets/get-cimclass?view=powershell-7.3)
- `Get-CimClass -Namespace Root/Microsoft/Windows/TaskScheduler`
- Enumerates all possible `CimClassNames` we can use to write custom filters for Scheduled Tasks
- `$CIMTriggerClass = Get-CimClass -Namespace Root/Microsoft/Windows/TaskScheduler -ClassName MSFT_TaskEventTrigger`
- Puts `MSFT_TaskEventTrigger` into a variable to work with
- Most importantly ***this will print an error if the CimClassName does not exist or is incorrect***


#### New-CimInstance

- [New-CimInstance](https://learn.microsoft.com/en-us/powershell/module/cimcmdlets/new-ciminstance?view=powershell-7.3)
- `$trigger = New-CimInstance -CimClass $CIMTriggerClass -ClientOnly`
- `New-CimInstance` ***does not return errors*** if the CimClassName does not exist, it simply creates a new CimInstance
- `-ClientOnly` creates the CIM instance in-memory locally for PowerShell operations alone
- Now that we have a writable CimInstance to use with our Scheduled Task, we can write our XML filter to the `Subscription` property


### Example: On Workstation Unlock

PowerShell block to create a Scheduled Task that triggers on Event Id 4801 (Workstation Unlock):

```powershell
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
```


### Example: On All Logins

PowerShell Block to create a Scheduled Task that triggers on login (any account):

```powershell
$taskname = "Login Alert"
$action = New-ScheduledTaskAction -Execute "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-nop -ep bypass -w hidden C:\Tools\Scripts\Send-LoginAlert.ps1"
$trigger = New-ScheduledTaskTrigger -AtLogon
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -Hidden
Register-ScheduledTask "$taskname" -Action $action -Trigger $trigger -Principal $principal
```


### Example: On Unique Login (Honey Account)

PowerShell Block to create a Scheduled Task that triggers on login (unique user, honey account):

- The only difference from the previous example is adding `-User "$honeyaccount"` to `New-ScheduledTaskTrigger`
- This task will only run if $honeyaccount logs in

```powershell
$honeyaccount = "<account-name>"
$taskname = "Honey Account Alert"
$action = New-ScheduledTaskAction -Execute "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-nop -ep bypass -w hidden C:\Tools\Scripts\Send-LoginAlert.ps1"
$trigger = New-ScheduledTaskTrigger -AtLogon -User "$honeyaccount"
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -Hidden
Register-ScheduledTask "$taskname" -Action $action -Trigger $trigger -Principal $principal
```


### Example: On Access of Audited File

PowerShell block to create a Scheduled Task that triggers on Event Id 4656, handle to an object requested (honey files):

- Change the `$filepath` variable to point to your audited file (note the double and single quotes)
- *NOTE: If there's a syntax

```powershell
# Name of the task
$taskname = "File Audit Alert"

# File to monitor
$filepath = "Data='C:\Path\To\Secrets.txt'"

# Execute our PowerShell script to send an alert to our webhook
$action = New-ScheduledTaskAction -Execute "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-nop -ep bypass -w hidden C:\Tools\Scripts\Send-FileAlert.ps1"

# Create a list of triggers, and add logon trigger to start working with
$triggers = @()
$triggers += New-ScheduledTaskTrigger -AtLogOn

# Create a TaskEventTrigger using CIM, store it in a variable, and write our XML to the Subscription property of that variable
$CIMTriggerClass = Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace Root/Microsoft/Windows/TaskScheduler:MSFT_TaskEventTrigger
$trigger = New-CimInstance -CimClass $CIMTriggerClass -ClientOnly
$trigger.Subscription = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4656)]] and
      *[EventData[Data[@Name='ObjectName'] and ($filepath)]]
    </Select>
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
```


## Create the Webhook

There are a few notes to consider for the webhook scripts:

- Running the task as BUILTIN\Users, extract environment variables via simple PowerShell scripts requires the scripts to be readable by the user
- Running as SYSTEM can restrict the scripts to administrators only
- SYSTEM allows you to extract event log information
- Running as SYSTEM and extracting log data when a particular user triggers a task to run also prevents issues where scripts are executed as the wrong user when multiple sessions are active (or at least this was encounter while testing all of this).

Utlimately you want the task information and scripts to be owned by the administrators group and restrict regular users from accessing or reading them.

*NOTE: This method is not as resistant to log tampering as embedding the variables directly into the Task XML data like in IppSec's video. However, **even if logs are cleared you'll still receive the empty alert letting you know someting happened**. Details are below this section.*

### Webhook Script Permissions

*IMPORTANT!*

Change the script's permissions to prevent read/write/execute from non administrative users:
```powershell
icacls.exe C:\Tools\Scripts\Send-FileAlert.ps1 /reset
takeown.exe /F C:\Tools\Scripts\Send-FileAlert.ps1 /A
icacls.exe C:\Tools\Scripts\Send-FileAlert.ps1 /inheritance:r
icacls.exe C:\Tools\Scripts\Send-FileAlert.ps1 /grant SYSTEM:"(F)"
icacls.exe C:\Tools\Scripts\Send-FileAlert.ps1 /grant BUILTIN\Administrators:"(F)"
```

This sets the ownership of the file to the Administrators group, and removes object inheritance, meaning folder permissions are not inherited (this effectively removes all access to the file until you grant specific access). Finally the SYSTEM account and the Administrators group are the only principals given access to the file. No other user or account will be able to modify, delete, or read this file. 


### PowerShell Webhook: Environment Variables

This PowerShell script can be used with any scheduled task to record a username, timestamp, hostname, (really anything about the environment you want to put into a PowerShell variable) to your alerts channel. This is a base script used to show what you can do with PowerShell and webhooks.

```powershell
# The full URL to your webhook
$webhook = '<your-webhook-url>'

# The timestamp of the event
$timestamp = Get-Date -Format "yyyy.MM.dd HH:mm:ss"

# The body of the webhook POST content populated with environment variables
$body = ConvertTo-Json @{ content="=======[ Account Login Alert ]========`nTimestamp: $timestamp`nHostname: $env:COMPUTERNAME`nUser: $env:USERDOMAIN\$env:USERNAME"}

# The POST request to your webhook
Invoke-RestMethod "$webhook" -Method Post -Body "$body" -ContentType 'application/json'
```


### PowerShell Webhook: File Alerts (Event Logs)

- Uses `Get-WinEvent` to pull the most recent log matching our criteria (in this example a honey file)
- Extract the most important fields as variables to send to the webhook

A quick explaination of what's happening so you can build your own queries:

- Here `$_.properties[6].value` is known to be the `ObjectName` which means the filename being audited.
- If you wanted to obtain these property values for any event log, you can list all of them by using `[0..25]`, `25` being an arbitrary number (most event logs don't have more than 25 fields, so by doing this you'll list them all)
- Use this example query to see how this works: `Get-WinEvent -FilterHashtable @{ Logname='Security'; StartTime=(Get-Date).AddDays(-1); Id='4656' } | ForEach-Object { Out-String -InputObject $_.properties[0..25].value } | select -First 1 | fl`
- Count and choose which fields you want to print or match with something like `$_.properties[1,6,15].value` (The first field is always `0`)

The full script once all the pieces are together:

```powershell
# Send-FileAlert.ps1

# The full URL to your webhook
$webhook=''

# Set the full path (backslashes escaped) of the file to be audited
$filepath = 'C:\\Path\\To\\Secrets.txt'

# Set a short start date to reduce log parsing time
$StartDate = (Get-Date).AddMinutes(-1)

# Get the event properties as variables
Get-WinEvent -FilterHashtable @{ Logname='Security'; StartTime=$StartDate; Id='4656' } | Where-Object { (Out-String -InputObject $_.properties[6].value) -imatch "$filepath" } | Select -First 1 | ForEach-Object {
    $timecreated = Out-String -InputObject $_.TimeCreated;
    $username = Out-String -InputObject $_.properties[1].value;
    $domain = Out-String -InputObject $_.properties[2].value;
    $file = Out-String -InputObject $_.properties[6].value;
    $pid = Out-String -InputIObject $_.properties[14].value;
    $process = Out-String -InputObject $_.properties[15].value;
}

# The body of the webhook POST content
$body = ConvertTo-Json @{ content="=======[ Honey File Alert ]========`nTimestamp: $timestamp`nHostname: $env:COMPUTERNAME`nDomain: $domain`nUser: $username`nFile: $file`nProcess: $process`nPID: $pid" }

# The POST request to your webhook
Invoke-RestMethod "$webhook" -Method Post -Body "$body" -ContentType 'application/json'
```


### PowerShell Webhook: Login Alerts (Event Logs)

- Parses Security events for ID 4648
- Filters out the `winlogon.exe` process (this helps retrieve only user sessions)
- Extracts all properties as variables
- Built upon [Seatbelt's ExplicitLogonEventsCommand.cs](https://github.com/GhostPack/Seatbelt/blob/master/Seatbelt/Commands/Windows/EventLogs/ExplicitLogonEvents/ExplicitLogonEventsCommand.cs)

```powershell
# Send-LoginAlert.ps1

# The full URL to your webhook
$webhook=''

# Set a short start date to reduce log parsing time
$StartDate = (Get-Date).AddMinutes(-1)

# Filter out the winlogon.exe process (this helps retrieve only user sessions)
$pattern = 'winlogon.exe'

# Get the event properties as variables
Get-WinEvent -FilterHashtable @{ Logname='Security'; StartTime=$StartDate; Id='4648' } | Where-Object { (Out-String -InputObject $_.properties[11].value) -inotmatch "$pattern" } | Select -First 1 | ForEach-Object {
    # Variable names were kept the same as they are in Seatbelt's ExplicitLogonEventsCommand.cs
    # Variable properties can be extracted from the Windows Event ID 4648 $_.Message object:
    $creationTime = $_.TimeCreated
    $subjectUserSid = $_.properties[0].value
    $subjectUserName = $_.properties[1].value
    $subjectDomainName = $_.properties[2].value
    $subjectLogonId = $_.properties[3].value
    $logonGuid = $_.properties[4].value
    $targetUserName = $_.properties[5].value
    $targetDomainName = $_.properties[6].value
    $targetLogonGuid = $_.properties[7].value
    $targetServerName = $_.properties[8].value
    $targetServerInfo = $_.properties[9].value
    $processId = $_.properties[10].value
    $processName = $_.properties[11].value
    $ipAddress = $_.properties[12].value
    $ipPort = $_.properties[13].value
}

# The body of the webhook POST content
$body = ConvertTo-Json @{ content="=======[ Account Login Alert ]========`nTimestamp: $creationTime`nHostname: $targetServerName`nUser: $targetDomainName\$targetUserName`nIp: $ipAddress"}

# The POST request to your webhook
Invoke-RestMethod "$webhook" -Method Post -Body "$body" -ContentType 'application/json'
```


### PowerShell Webhook: Workstation Unlock Alerts (Event Logs)

- Parses Security Events for ID 4801
- Extracts all properties as variables

```powershell
# Send-UnlockAlert.ps1

# The full URL to your webhook
$webhook=''

# Set a short start date to reduce log parsing time
$StartDate = (Get-Date).AddMinutes(-1)

# Get the event properties as variables
Get-WinEvent -FilterHashtable @{ Logname='Security'; StartTime=$StartDate; Id='4801' } | Select -First 1 | ForEach-Object {
    $creationTime = $_.TimeCreated
    $subjectUserSid = $_.properties[0].value
    $subjectUserName = $_.properties[1].value
    $subjectDomainName = $_.properties[2].value
    $subjectLogonId = $_.properties[3].value
    $subjectSessionId = $_.properties[4].value
}

# The body of the webhook POST content
$body = ConvertTo-Json @{ content="=======[ Device Unlock Alert ]========`nTimestamp: $creationTime`nHostname: $env:COMPUTERNAME`nUser: $subjectDomainName\$subjectUserName`nSessionId: $SubjectSessionId"}

# The POST request to your webhook
Invoke-RestMethod "$webhook" -Method Post -Body "$body" -ContentType 'application/json'
```

## Try to Break the Webhook

***IMPORTANT! This is a destructive exercise, perform this in a sandbox environment!***

The one downside to handling the webhook data separately from the Scheduled Task (compared to IppSec's video where event information is embedded into the Task XML) is that logs need accessed ***after*** the task executes, to obtain the alert data. This creates a situation where an attacker with awareness of your monitoring is able to modify the logs before the data can be sent. 

However, ***the empty alert itself is still sent*** with a header informing you of what task was executed. 

Each PowerShell script in this repo sends data with a header to delineate it from the previous alert, and to detail what it's alerting on (e.g. "Login Alert"). Even if the log is cleared, the Task still triggers and the script is still executed. Here's the result of a file audit alert where the logs were cleared:

```
=======[ Honey File Alert ]========
Timestamp: 
Hostname: HOSTNAME
Domain: 
User: 
File: 
Process: 
PID: 12345
```

You should validate this yourself ***in a sandbox***. The following script was used to test clearing the logs:

```powershell
# Access the honey file
$filepath = "C:\Path\To\Secrets.xlsx"
Get-Content -Path $filepath

# Run this in a loop for 5 seconds, clearing events immediately doesn't erase the newest log
$EndTime = (Get-Date).AddSeconds(5)

# Clear the audit log (Security)
while ((Get-Date) -lt $EndTime) {
	Clear-EventLog -LogName 'Security'
}
```

***What if the attacker removes the PowerShell alerting script AND clears the logs at the same time?***

Unfortunately once an adversary successfully has SYSTEM and hasn't been kicked out by AV / EDR, there's nothing limiting what they can do. The monitoring and alerting techniques described in this repo should be a starting point. Ideally you'll have alerts configured that will catch behavior leading to system compromise as it happens. Combine this with things like [Attack Surface Reduction rules](https://github.com/straysheep-dev/windows-configs/tree/main#asr-attack-surface-reduction) for defense in depth!

# Linux

*Steps for Linux (and Unix) auditing and alerting.*

The scripts as of now were built to run on Ubuntu Linux (tested on 20.04 and 22.04).

They use a webhook to POST information via `curl` to an alert channel.

- `/var/log/auth.log` is used for all login and sudo alerts
- `/var/log/audit/audit.log` is used for specific monitoring and would be based on your auditd rule file(s)

`alert.sh` functions as the log monitoring and POST mechanism, tailing any file you require (it's easy to add functions for different logs based on your requirements) and sending lines that match your rule(s) to your webhook.

`alert-service.sh` configures this as a systemd service to restart automatically or if it ever stops.

While only root can read the script containing the webhook URL, an unfortunate side effect of using a webhook via `curl` is that anyone on the system can pull the URL from the process list with `ps aux` if timed correctly, or by using a process monitoring tool like [`pspy`](https://github.com/DominicBreuker/pspy). This will need addressed in a future revision. For now, having the capability of receiving a text message if your server is logged into outweighs the risk of having a private webhook stolen.
