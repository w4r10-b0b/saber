Usage Instructions

1. Prerequisites

	•	PowerShell Version: Ensure you have PowerShell 5.1 or higher.
	•	SQLite Module: Install the System.Data.SQLite module.
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module -Name System.Data.SQLite -Scope CurrentUser

	•	Permissions: Run the script with administrative privileges to access system files.

2. Script Setup

	•	Save the Script:
Save the script code to a file named FileIntegrityChecker.ps1.
	•	Unblock the Script:
Unblock-File -Path .\FileIntegrityChecker.ps1

	•	Set Execution Policy:
If necessary, change the execution policy to allow running scripts.
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

3. Initializing the Database

Run the script with the -Init parameter to store the initial hashes and contents of the files.
.\FileIntegrityChecker.ps1 -Init

4. Running the Script

Provide the necessary API keys and configurations as parameters or set them as environment variables.
.\FileIntegrityChecker.ps1 `
    -ServiceNowInstance "your_instance" `
    -ServiceNowUser "your_username" `
    -ServiceNowPassword "your_password" `
    -Rapid7ApiKey "your_rapid7_api_key" `
    -Rapid7WorkflowId "your_workflow_id" `
    -JiraUrl "https://your_jira_instance.atlassian.net" `
    -JiraUser "your_jira_email" `
    -JiraApiToken "your_jira_api_token" `
    -JiraProjectKey "YOURPROJECTKEY" `
    -SlackWebhookUrl "https://hooks.slack.com/services/your/webhook/url" `
    -TeamsWebhookUrl "https://outlook.office.com/webhook/your/webhook/url"

Note:
	•	Only include parameters for the platforms you wish to notify.
	•	You can use environment variables to store sensitive information and modify the script to read from them.

5. Automating with Task Scheduler

To automate the integrity checking, you can set up a scheduled task.
	1.	Open Task Scheduler:
Start-Process taskschd.msc

2.	Create a New Task:
	•	Name: File Integrity Checker
	•	Run with highest privileges
	•	Configure for your operating system
	3.	Set a Trigger:
	•	Schedule the task to run at your desired interval (e.g., daily at 2 AM).
	4.	Set an Action:
	•	Action: Start a program
	•	Program/script: powershell.exe
	•	Add arguments:
-ExecutionPolicy Bypass -File "C:\Path\To\FileIntegrityChecker.ps1" -ServiceNowInstance "your_instance" [other parameters]

	5.	Secure the Task:
	•	Ensure the task runs under an account with necessary permissions.
	•	Do not store sensitive passwords in plain text if possible.

Explanation of the Script

	•	Functions:
	•	Initialize-Database: Creates the necessary SQLite tables if they don’t exist.
	•	Calculate-SHA256: Calculates the SHA-256 hash of a file.
	•	Get-FilesToMonitor: Recursively finds files to monitor based on specified directories and extensions.
	•	Is-SensitiveFile: Determines if a file is sensitive based on its name or path.
	•	Store-InitialHashes: Stores the initial hashes and contents of the files.
	•	Check-ForChanges: Checks for changes in the file hashes and generates diffs.
	•	Generate-Diff: Generates a unified diff between old and new content.
	•	Send-Notifications: Sends notifications to configured platforms.
	•	Notification functions: Send-ServiceNowAlert, Send-Rapid7Alert, Send-JiraIssue, Send-SlackMessage, Send-TeamsMessage.
	•	Database Usage:
	•	Uses a SQLite database file_integrity.db to store file hashes and contents.
	•	Requires the System.Data.SQLite module.
	•	Diffs Directory:
	•	Stores diffs in the diffs directory.
	•	Sensitive Files Handling:
	•	Does not store contents or diffs for sensitive files.
	•	Notifications:
	•	Sends alerts to specified platforms when changes are detected.
	•	Credentials and API keys are passed as parameters.

Security Considerations

Handling Sensitive Files
	•	The script monitors sensitive files for changes but does not store their contents or diffs to prevent exposure of confidential data.
	•	Customize the SensitiveFiles and SensitivePatterns arrays as needed.

Permissions
	•	Run the script with administrative privileges to ensure it can access all necessary files.
	•	Secure the file_integrity.db database and diffs directory.
# Secure the database file
$dbPath = Join-Path (Get-Location) $DBName
icacls $dbPath /inheritance:r /grant:r "Administrators:F" /c

# Secure the diffs directory
icacls "diffs" /inheritance:r /grant:r "Administrators:F" /c

Credentials Management
	•	Avoid hardcoding sensitive credentials in scripts.
	•	Use secure methods to store and retrieve credentials, such as Windows Credential Manager or encrypted files.

Data Privacy
	•	Be cautious when storing file contents and diffs, as they may contain sensitive information.
	•	Ensure compliance with your organization’s data handling policies.

Customization
Directories to Monitor
Modify the $DirectoriesToSearch array to add or remove directories.
$DirectoriesToSearch = @(
    'C:\Windows\System32',
    'C:\Program Files',
    # Add more directories as needed
)

File Extensions to Monitor
Update the $FileExtensions array to include additional file extensions.

Sensitive Files and Patterns
Add sensitive files and patterns to prevent storing their contents or diffs.

$SensitiveFiles = @(
    'C:\Windows\System32\config\SAM',
    # Add more sensitive files
)

$SensitivePatterns = @(
    '.key', '.pem', 'SAM', 'SYSTEM', 'SECURITY',
    # Add more patterns
)

Additional Considerations

Exception Handling
	•	The script includes basic error handling. Enhance it as needed for your environment.

Logging
	•	Implement logging to a file if required, using Start-Transcript and Stop-Transcript.

Performance
	•	Monitor resource usage, especially when scanning large directories.

Disclaimer
	•	Use Responsibly: This script is a basic tool for monitoring file integrity. For critical systems, consider using established solutions.
	•	Testing: Thoroughly test the script in a controlled environment before deploying it to production systems.
