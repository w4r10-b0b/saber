<#
.SYNOPSIS
    File Integrity Monitoring Script in PowerShell.

.DESCRIPTION
    Monitors critical files for changes, stores their hashes, and sends notifications when changes are detected.

.PARAMETER Init
    Initialize and store file hashes.

.PARAMETER ServiceNowInstance
    ServiceNow instance name.

.PARAMETER ServiceNowUser
    ServiceNow username.

.PARAMETER ServiceNowPassword
    ServiceNow password.

.PARAMETER Rapid7ApiKey
    Rapid7 InsightConnect API key.

.PARAMETER Rapid7WorkflowId
    Rapid7 InsightConnect workflow ID.

.PARAMETER JiraUrl
    Jira base URL.

.PARAMETER JiraUser
    Jira username/email.

.PARAMETER JiraApiToken
    Jira API token.

.PARAMETER JiraProjectKey
    Jira project key.

.PARAMETER SlackWebhookUrl
    Slack incoming webhook URL.

.PARAMETER TeamsWebhookUrl
    Microsoft Teams incoming webhook URL.

#>

param(
    [switch]$Init,
    [string]$ServiceNowInstance,
    [string]$ServiceNowUser,
    [string]$ServiceNowPassword,
    [string]$Rapid7ApiKey,
    [string]$Rapid7WorkflowId,
    [string]$JiraUrl,
    [string]$JiraUser,
    [string]$JiraApiToken,
    [string]$JiraProjectKey,
    [string]$SlackWebhookUrl,
    [string]$TeamsWebhookUrl
)

# Import SQLite module (Install-Module System.Data.SQLite -Scope CurrentUser)
Import-Module System.Data.SQLite

# Directories to search
$DirectoriesToSearch = @(
    'C:\Windows\System32',
    'C:\Program Files',
    'C:\Program Files (x86)',
    # Add more directories as needed
)

# File extensions to monitor
$FileExtensions = @(
    '.ini', '.conf', '.crt', '.pem', '.key', '.service', '.cfg', '.cnf',
    '.csr', '.der', '.pfx', '.exe', '.dll', '.sys'
)

# Sensitive files (do not store diffs)
$SensitiveFiles = @(
    'C:\Windows\System32\config\SAM',
    'C:\Windows\System32\config\SYSTEM',
    'C:\Windows\System32\config\SECURITY',
    # Add more sensitive files as needed
)

# Sensitive file patterns (file names or extensions)
$SensitivePatterns = @(
    '.key', '.pem', '.der', '.pfx', 'SAM', 'SYSTEM', 'SECURITY'
)

$DBName = 'file_integrity.db'

function Initialize-Database {
    param(
        [SQLiteConnection]$Connection
    )
    $createHashesTable = @"
CREATE TABLE IF NOT EXISTS file_hashes (
    file_path TEXT PRIMARY KEY,
    sha256 TEXT NOT NULL,
    last_modified TEXT NOT NULL
);
"@
    $createContentsTable = @"
CREATE TABLE IF NOT EXISTS file_contents (
    file_path TEXT PRIMARY KEY,
    content TEXT NOT NULL,
    last_modified TEXT NOT NULL
);
"@
    $Command = $Connection.CreateCommand()
    $Command.CommandText = $createHashesTable
    $Command.ExecuteNonQuery() | Out-Null

    $Command.CommandText = $createContentsTable
    $Command.ExecuteNonQuery() | Out-Null
}

function Calculate-SHA256 {
    param(
        [string]$FilePath
    )
    try {
        if (Test-Path $FilePath) {
            $HashAlgorithm = [System.Security.Cryptography.SHA256]::Create()
            $Stream = [System.IO.File]::OpenRead($FilePath)
            $HashBytes = $HashAlgorithm.ComputeHash($Stream)
            $Stream.Close()
            $HashString = [BitConverter]::ToString($HashBytes) -replace '-', ''
            return $HashString.ToLower()
        } else {
            return $null
        }
    } catch {
        return $null
    }
}

function Get-FilesToMonitor {
    $FilesToMonitor = @()
    foreach ($Directory in $DirectoriesToSearch) {
        if (Test-Path $Directory) {
            Get-ChildItem -Path $Directory -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
                $FilePath = $_.FullName
                $Extension = $_.Extension
                if ($FileExtensions -contains $Extension -or (Is-SensitiveFile -FilePath $FilePath)) {
                    $FilesToMonitor += $FilePath
                }
            }
        }
    }
    return $FilesToMonitor
}

function Is-SensitiveFile {
    param(
        [string]$FilePath
    )
    $FileName = [System.IO.Path]::GetFileName($FilePath)
    if ($SensitiveFiles -contains $FilePath) {
        return $true
    }
    foreach ($Pattern in $SensitivePatterns) {
        if ($FileName -like "*$Pattern*") {
            return $true
        }
    }
    return $false
}

function Store-InitialHashes {
    param(
        [SQLiteConnection]$Connection,
        [array]$FilesToMonitor
    )
    foreach ($FilePath in $FilesToMonitor) {
        $Sha256 = Calculate-SHA256 -FilePath $FilePath
        if ($Sha256) {
            $LastModified = (Get-Item $FilePath).LastWriteTime.ToString('o')
            $Command = $Connection.CreateCommand()
            $Command.CommandText = "INSERT OR REPLACE INTO file_hashes (file_path, sha256, last_modified) VALUES (@FilePath, @Sha256, @LastModified);"
            $Command.Parameters.AddWithValue("@FilePath", $FilePath) | Out-Null
            $Command.Parameters.AddWithValue("@Sha256", $Sha256) | Out-Null
            $Command.Parameters.AddWithValue("@LastModified", $LastModified) | Out-Null
            $Command.ExecuteNonQuery() | Out-Null

            # Store file content if not sensitive
            if (-not (Is-SensitiveFile -FilePath $FilePath)) {
                try {
                    $Content = Get-Content -Path $FilePath -ErrorAction Stop | Out-String
                    $Command.CommandText = "INSERT OR REPLACE INTO file_contents (file_path, content, last_modified) VALUES (@FilePath, @Content, @LastModified);"
                    $Command.Parameters.Clear()
                    $Command.Parameters.AddWithValue("@FilePath", $FilePath) | Out-Null
                    $Command.Parameters.AddWithValue("@Content", $Content) | Out-Null
                    $Command.Parameters.AddWithValue("@LastModified", $LastModified) | Out-Null
                    $Command.ExecuteNonQuery() | Out-Null
                } catch {
                    Write-Host "Could not read file content for $FilePath: $_"
                }
            }
            Write-Host "Stored hash for $FilePath"
        } else {
            Write-Host "Could not access file: $FilePath"
        }
    }
}

function Generate-Diff {
    param(
        [string]$OldContent,
        [string]$NewContent
    )
    $OldLines = $OldContent -split "`n"
    $NewLines = $NewContent -split "`n"
    $Diff = [System.Management.Automation.PSObject].Assembly.GetType("Microsoft.PowerShell.Commands.UnifiedDiff")::GetUnifiedDiff($OldLines, $NewLines, 3)
    return $Diff
}

function Check-ForChanges {
    param(
        [SQLiteConnection]$Connection,
        [array]$FilesToMonitor
    )
    $ChangesDetected = $false
    $ChangedFiles = @()
    foreach ($FilePath in $FilesToMonitor) {
        $CurrentSha256 = Calculate-SHA256 -FilePath $FilePath
        if ($CurrentSha256) {
            $Command = $Connection.CreateCommand()
            $Command.CommandText = "SELECT sha256 FROM file_hashes WHERE file_path = @FilePath;"
            $Command.Parameters.AddWithValue("@FilePath", $FilePath) | Out-Null
            $Reader = $Command.ExecuteReader()
            if ($Reader.Read()) {
                $StoredSha256 = $Reader["sha256"]
                if ($CurrentSha256 -ne $StoredSha256) {
                    Write-Host "Change detected in $FilePath"
                    $ChangesDetected = $true
                    $ChangedFiles += $FilePath
                    $LastModified = (Get-Item $FilePath).LastWriteTime.ToString('o')
                    $Command = $Connection.CreateCommand()
                    $Command.CommandText = "UPDATE file_hashes SET sha256 = @Sha256, last_modified = @LastModified WHERE file_path = @FilePath;"
                    $Command.Parameters.AddWithValue("@FilePath", $FilePath) | Out-Null
                    $Command.Parameters.AddWithValue("@Sha256", $CurrentSha256) | Out-Null
                    $Command.Parameters.AddWithValue("@LastModified", $LastModified) | Out-Null
                    $Command.ExecuteNonQuery() | Out-Null

                    # Generate and store diff if not sensitive
                    if (-not (Is-SensitiveFile -FilePath $FilePath)) {
                        try {
                            $NewContent = Get-Content -Path $FilePath -ErrorAction Stop | Out-String
                            $Command.CommandText = "SELECT content FROM file_contents WHERE file_path = @FilePath;"
                            $Command.Parameters.Clear()
                            $Command.Parameters.AddWithValue("@FilePath", $FilePath) | Out-Null
                            $OldContent = ''
                            $Reader = $Command.ExecuteReader()
                            if ($Reader.Read()) {
                                $OldContent = $Reader["content"]
                            }
                            $Diff = Generate-Diff -OldContent $OldContent -NewContent $NewContent

                            # Update stored content
                            $Command.CommandText = "UPDATE file_contents SET content = @Content, last_modified = @LastModified WHERE file_path = @FilePath;"
                            $Command.Parameters.Clear()
                            $Command.Parameters.AddWithValue("@FilePath", $FilePath) | Out-Null
                            $Command.Parameters.AddWithValue("@Content", $NewContent) | Out-Null
                            $Command.Parameters.AddWithValue("@LastModified", $LastModified) | Out-Null
                            $Command.ExecuteNonQuery() | Out-Null

                            # Store the diff
                            $DiffFileName = "diffs\$([System.IO.Path]::GetFileName($FilePath)).diff"
                            $DiffDirectory = [System.IO.Path]::GetDirectoryName($DiffFileName)
                            if (-not (Test-Path $DiffDirectory)) {
                                New-Item -ItemType Directory -Path $DiffDirectory | Out-Null
                            }
                            $Diff | Out-File -FilePath $DiffFileName -Encoding utf8
                        } catch {
                            Write-Host "Could not generate diff for $FilePath: $_"
                        }
                    } else {
                        Write-Host "Sensitive file changed: $FilePath. Diff not stored."
                    }
                }
            } else {
                Write-Host "New file detected: $FilePath. Storing current hash."
                $LastModified = (Get-Item $FilePath).LastWriteTime.ToString('o')
                $Command = $Connection.CreateCommand()
                $Command.CommandText = "INSERT INTO file_hashes (file_path, sha256, last_modified) VALUES (@FilePath, @Sha256, @LastModified);"
                $Command.Parameters.AddWithValue("@FilePath", $FilePath) | Out-Null
                $Command.Parameters.AddWithValue("@Sha256", $CurrentSha256) | Out-Null
                $Command.Parameters.AddWithValue("@LastModified", $LastModified) | Out-Null
                $Command.ExecuteNonQuery() | Out-Null

                # Store file content if not sensitive
                if (-not (Is-SensitiveFile -FilePath $FilePath)) {
                    try {
                        $Content = Get-Content -Path $FilePath -ErrorAction Stop | Out-String
                        $Command.CommandText = "INSERT INTO file_contents (file_path, content, last_modified) VALUES (@FilePath, @Content, @LastModified);"
                        $Command.Parameters.Clear()
                        $Command.Parameters.AddWithValue("@FilePath", $FilePath) | Out-Null
                        $Command.Parameters.AddWithValue("@Content", $Content) | Out-Null
                        $Command.Parameters.AddWithValue("@LastModified", $LastModified) | Out-Null
                        $Command.ExecuteNonQuery() | Out-Null
                    } catch {
                        Write-Host "Could not read file content for $FilePath: $_"
                    }
                }
                $ChangesDetected = $true
                $ChangedFiles += $FilePath
            }
        } else {
            Write-Host "Could not access file: $FilePath"
        }
    }
    if ($ChangesDetected) {
        Send-Notifications -ChangedFiles $ChangedFiles
    } else {
        Write-Host "No changes detected."
    }
}

function Send-Notifications {
    param(
        [array]$ChangedFiles
    )
    $Message = "File integrity changes detected:`n" + ($ChangedFiles -join "`n")
    if ($ServiceNowInstance -and $ServiceNowUser -and $ServiceNowPassword) {
        Send-ServiceNowAlert -Message $Message
    }
    if ($Rapid7ApiKey) {
        Send-Rapid7Alert -Message $Message
    }
    if ($JiraUrl -and $JiraUser -and $JiraApiToken) {
        Send-JiraIssue -Message $Message
    }
    if ($SlackWebhookUrl) {
        Send-SlackMessage -Message $Message
    }
    if ($TeamsWebhookUrl) {
        Send-TeamsMessage -Message $Message
    }
}

function Send-ServiceNowAlert {
    param(
        [string]$Message
    )
    $Url = "https://$ServiceNowInstance.service-now.com/api/now/table/incident"
    $Headers = @{
        "Content-Type" = "application/json"
        "Accept" = "application/json"
    }
    $Body = @{
        "short_description" = "File Integrity Alert"
        "description" = $Message
        "urgency" = "2"
        "impact" = "2"
    } | ConvertTo-Json
    try {
        $Response = Invoke-RestMethod -Uri $Url -Method Post -Headers $Headers -Body $Body -Credential (New-Object System.Management.Automation.PSCredential($ServiceNowUser, (ConvertTo-SecureString $ServiceNowPassword -AsPlainText -Force)))
        Write-Host "ServiceNow incident created successfully."
    } catch {
        Write-Host "Error sending to ServiceNow: $_"
    }
}

function Send-Rapid7Alert {
    param(
        [string]$Message
    )
    $Url = "https://us.api.insight.rapid7.com/connect/v1/workflows/trigger"
    $Headers = @{
        "X-API-Key" = $Rapid7ApiKey
        "Content-Type" = "application/json"
    }
    $Body = @{
        "workflow" = $Rapid7WorkflowId
        "message" = $Message
    } | ConvertTo-Json
    try {
        $Response = Invoke-RestMethod -Uri $Url -Method Post -Headers $Headers -Body $Body
        Write-Host "Rapid7 InsightConnect alert sent successfully."
    } catch {
        Write-Host "Error sending to Rapid7 InsightConnect: $_"
    }
}

function Send-JiraIssue {
    param(
        [string]$Message
    )
    $Url = "$JiraUrl/rest/api/2/issue"
    $Headers = @{
        "Content-Type" = "application/json"
    }
    $AuthInfo = "$JiraUser:$JiraApiToken"
    $AuthHeader = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($AuthInfo))
    $Headers["Authorization"] = $AuthHeader
    $Body = @{
        "fields" = @{
            "project" = @{
                "key" = $JiraProjectKey
            }
            "summary" = "File Integrity Alert"
            "description" = $Message
            "issuetype" = @{
                "name" = "Task"
            }
        }
    } | ConvertTo-Json -Depth 4
    try {
        $Response = Invoke-RestMethod -Uri $Url -Method Post -Headers $Headers -Body $Body
        Write-Host "Jira issue created successfully."
    } catch {
        Write-Host "Error sending to Jira: $_"
    }
}

function Send-SlackMessage {
    param(
        [string]$Message
    )
    $Body = @{
        "text" = $Message
    } | ConvertTo-Json
    try {
        $Response = Invoke-RestMethod -Uri $SlackWebhookUrl -Method Post -Body $Body -ContentType 'application/json'
        Write-Host "Slack message sent successfully."
    } catch {
        Write-Host "Error sending to Slack: $_"
    }
}

function Send-TeamsMessage {
    param(
        [string]$Message
    )
    $Body = @{
        "@type" = "MessageCard"
        "@context" = "https://schema.org/extensions"
        "summary" = "File Integrity Alert"
        "themeColor" = "0076D7"
        "title" = "File Integrity Alert"
        "text" = $Message
    } | ConvertTo-Json
    try {
        $Response = Invoke-RestMethod -Uri $TeamsWebhookUrl -Method Post -Body $Body -ContentType 'application/json'
        Write-Host "Teams message sent successfully."
    } catch {
        Write-Host "Error sending to Teams: $_"
    }
}

function Main {
    $ConnectionString = "Data Source=$DBName;Version=3;"
    $Connection = New-Object System.Data.SQLite.SQLiteConnection($ConnectionString)
    $Connection.Open()
    Initialize-Database -Connection $Connection
    $FilesToMonitor = Get-FilesToMonitor
    if ($Init) {
        Write-Host "Initializing and storing file hashes..."
        Store-InitialHashes -Connection $Connection -FilesToMonitor $FilesToMonitor
    } else {
        Write-Host "Checking for changes..."
        Check-ForChanges -Connection $Connection -FilesToMonitor $FilesToMonitor
    }
    $Connection.Close()
}

# Create diffs directory if it doesn't exist
if (-not (Test-Path 'diffs')) {
    New-Item -ItemType Directory -Path 'diffs' | Out-Null
}

Main
