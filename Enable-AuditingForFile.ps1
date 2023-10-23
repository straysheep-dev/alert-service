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
