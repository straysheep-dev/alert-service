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
