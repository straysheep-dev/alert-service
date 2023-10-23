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
