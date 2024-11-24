File Integrity Monitoring Script

Overview

This Python script monitors critical files on a Linux server for any unauthorized changes that might indicate malicious activity or system compromise. It calculates the SHA-256 checksums of specified files, stores them in a SQLite database, and compares them on subsequent runs to detect changes. If changes are detected, the script:
	•	Stores the differences (diffs) between the old and new file versions unless the files are sensitive (e.g., private keys, password files).
	•	Sends notifications to configured platforms such as ServiceNow, Rapid7 InsightConnect, Jira, Microsoft Teams, and Slack.
	•	Provides options to specify API keys or managed identity names via command-line arguments or environment variables.

Features

	•	File Monitoring:
	•	Monitors configuration files, certificate files, private keys, startup scripts, and service definitions.
	•	Recursively searches specified directories for files with certain extensions.
	•	Monitors authorized_keys files for the root user and all other users.
	•	Checks for changes in Nagios, Apache, and common web server configurations.
	•	Monitors the contents of the /root folder and changes to startup and services.
	•	Change Detection:
	•	Calculates SHA-256 checksums and detects any changes in monitored files.
	•	Stores differences between file versions unless the files are sensitive.
	•	Sensitive files (e.g., private keys, /etc/shadow) are monitored for changes, but their contents are not stored or displayed.
	•	Notifications:
	•	Sends alerts to various platforms when changes are detected.
	•	Supports ServiceNow, Rapid7 InsightConnect, Jira, Microsoft Teams, and Slack.
	•	Allows specifying API keys and configurations via command-line arguments or environment variables.
	•	Security Considerations:
	•	Handles sensitive files carefully to prevent exposure of confidential data.
	•	Provides options to secure the script, database, and log files.
	•	Encourages the use of environment variables for sensitive credentials.

 Usage Instructions

1. Prerequisites

	•	Python Version: Ensure you have Python 3.x installed.
	•	Dependencies: Install required Python packages.

  pip install requests

  
2. Script Setup

	•	Make the Script Executable:
chmod +x file_integrity_checker.py

	•	Secure the Script:
sudo chown root:root file_integrity_checker.py
sudo chmod 700 file_integrity_checker.py

3. Initializing the Database
Run the script with the --init flag to store the initial hashes and contents of the files.

sudo ./file_integrity_checker.py --init

Note: Running with sudo is necessary to access all files, especially those owned by root.

4. Running the Script

Provide the necessary API keys and configurations as command-line arguments or set them as environment variables.

sudo ./file_integrity_checker.py \
--servicenow-instance your_instance \
--servicenow-user your_username \
--servicenow-password your_password \
--rapid7-api-key your_rapid7_api_key \
--rapid7-workflow-id your_workflow_id \
--jira-url https://your_jira_instance.atlassian.net \
--jira-user your_jira_email \
--jira-api-token your_jira_api_token \
--jira-project-key YOURPROJECTKEY \
--slack-webhook-url https://hooks.slack.com/services/your/webhook/url \
--teams-webhook-url https://outlook.office.com/webhook/your/webhook/url

ote:
	•	Only include arguments for the platforms you wish to notify.
	•	You can use environment variables to store sensitive information.

5. Automating with Cron
Set up a cron job to run the script at regular intervals.
sudo crontab -e

Add the following line to run the script every day at 2 AM:
sudo touch /var/log/file_integrity.log
sudo chown root:root /var/log/file_integrity.log
sudo chmod 600 /var/log/file_integrity.log

Configuration Options

Directories to Monitor
Modify the DIRECTORIES_TO_SEARCH list in the script to add or remove directories.
DIRECTORIES_TO_SEARCH = [
    '/etc',
    '/var',
    '/root',
    # Add more directories as needed
]

File Extensions to Monitor
Update the FILE_EXTENSIONS tuple to include additional file extensions.
FILE_EXTENSIONS = (
    '.ini', '.conf', '.cfg', '.cnf', '.crt', '.csr', '.der', '.pem', '.pfx', '.key',
    # Add more extensions as needed)

Sensitive Files and Patterns
Add sensitive files and patterns to prevent storing their contents or diffs.  
SENSITIVE_FILES = [
    '/etc/shadow',
    '/etc/passwd',
    # Add more sensitive files
]

SENSITIVE_PATTERNS = (
    '.key', '.pem', 'shadow', 'passwd',
    # Add more patterns
)

Security Considerations

Handling Sensitive Files
	•	Sensitive Files: The script monitors sensitive files for changes but does not store their contents or diffs to prevent exposure of confidential data.
	•	Identification: Sensitive files are identified based on exact paths and filename patterns.
	•	Customization: Update the SENSITIVE_FILES and SENSITIVE_PATTERNS in the script to suit your environment.

File Permissions
	•	Script and Database:
 sudo chown root:root file_integrity.db
sudo chmod 600 file_integrity.db
sudo chown root:root file_integrity_checker.py
sudo chmod 700 file_integrity_checker.py

•	Diffs Directory:
sudo chown root:root diffs
sudo chmod 700 diffs

Credentials Management
	•	Environment Variables: Use environment variables to store sensitive credentials instead of command-line arguments.
export SERVICENOW_PASSWORD='your_password'

	•	Modify Script to Use Environment Variables:
 args.servicenow_password = args.servicenow_password or os.getenv('SERVICENOW_PASSWORD')
 	•	Secure Storage: Ensure that any method used to store credentials complies with your organization’s security policies.

Data Privacy
	•	Non-Sensitive Files: The script stores contents and diffs for non-sensitive files. Ensure that this complies with your data handling policies.
	•	Notifications: Be cautious when including file paths or other potentially sensitive information in notifications.

Testing
	•	Controlled Environment: Test the script in a non-production environment to ensure it works as expected.
	•	Monitor Resource Usage: Storing file contents and generating diffs can consume storage and processing time.

 Notification Integrations

ServiceNow
	•	Arguments:
	•	--servicenow-instance: Your ServiceNow instance name (e.g., dev12345).
	•	--servicenow-user: ServiceNow username.
	•	--servicenow-password: ServiceNow password.

Rapid7 InsightConnect
	•	Arguments:
	•	--rapid7-api-key: Your Rapid7 InsightConnect API key.
	•	--rapid7-workflow-id: The workflow ID to trigger.

Jira
	•	Arguments:
	•	--jira-url: Base URL of your Jira instance.
	•	--jira-user: Your Jira username or email.
	•	--jira-api-token: Your Jira API token.
	•	--jira-project-key: The project key where the issue will be created.

Slack
	•	Argument:
	•	--slack-webhook-url: Slack incoming webhook URL.

Microsoft Teams
	•	Argument:
	•	--teams-webhook-url: Microsoft Teams incoming webhook URL.

 Additional Considerations

Exception Handling
	•	The script includes basic exception handling when reading files and sending notifications.
	•	Enhance exception handling as needed to handle specific exceptions and retries.

Modularization and Logging
	•	For better maintainability, consider modularizing the code.
	•	Replace print statements with proper logging using Python’s logging module.

Performance
	•	Resource Usage: Monitor CPU and memory usage, especially when scanning large directories or storing many diffs.
	•	Database Maintenance: Regularly backup and maintain the SQLite database.

Compliance and Policies
	•	Ensure that using this script and storing file contents complies with your organization’s security policies and regulations.

 Disclaimer
	•	Use Responsibly: This script is a basic tool for monitoring file integrity. For critical systems, consider using established solutions like AIDE or Tripwire.
	•	No Warranty: The script is provided “as is” without warranty of any kind. Use it at your own risk.
	•	Testing: Thoroughly test the script in a controlled environment before deploying it to production systems.

Support and Further Assistance

If you have any questions or need additional customization, feel free to ask or consult with a cybersecurity professional to ensure the script meets your specific requirements.
