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
