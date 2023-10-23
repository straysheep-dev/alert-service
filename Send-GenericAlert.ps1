# The full URL to your webhook
$webhook = '<your-webhook-url>'

# The timestamp of the event
$timestamp = Get-Date -Format "yyyy.MM.dd HH:mm:ss"

# The body of the webhook POST content populated with environment variables
$body = ConvertTo-Json @{ content="=======[ Account Login Alert ]========`nTimestamp: $timestamp`nHostname: $env:COMPUTERNAME`nUser: $env:USERDOMAIN\$env:USERNAME"}

# The POST request to your webhook
Invoke-RestMethod "$webhook" -Method Post -Body "$body" -ContentType 'application/json'
