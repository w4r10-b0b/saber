#!/usr/bin/env python3

import hashlib
import os
import sqlite3
import sys
from datetime import datetime
import pwd
import argparse
import requests
import json
import difflib

# Directories to search
DIRECTORIES_TO_SEARCH = [
    '/etc',
    '/var',
    '/root',
    '/etc/init.d',
    '/etc/systemd/system',
    '/lib/systemd/system',
    '/usr/lib/systemd/system',
    '/etc/nagios',
    '/usr/local/nagios/etc',
    '/etc/httpd',
    '/etc/apache2',
    '/etc/nginx',
    # Add more directories as needed
]

# File extensions to monitor
FILE_EXTENSIONS = (
    '.ini', '.conf', '.crt', '.pem', '.key', '.service', '.cfg', '.cnf',
    '.csr', '.der', '.pfx'
)

# Sensitive files (do not store diffs)
SENSITIVE_FILES = [
    '/etc/shadow',
    '/etc/passwd',
    '/etc/gshadow',
    '/etc/security/opasswd',
    '/etc/ssh/ssh_host_rsa_key',
    '/etc/ssh/ssh_host_dsa_key',
    '/etc/ssh/ssh_host_ecdsa_key',
    '/etc/ssh/ssh_host_ed25519_key',
    # Add more sensitive files as needed
]

# Sensitive file patterns (file names or extensions)
SENSITIVE_PATTERNS = (
    '.key', '.pem', '.der', '.pfx', 'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519',
    'shadow', 'passwd', 'gshadow'
)

DB_NAME = 'file_integrity.db'

def calculate_sha256(file_path):
    """Calculate the SHA-256 checksum of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            # Read and update hash in chunks of 4K
            for byte_block in iter(lambda: f.read(4096), b''):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (FileNotFoundError, PermissionError):
        return None

def initialize_database(conn):
    """Create the database tables if they don't exist."""
    conn.execute('''
        CREATE TABLE IF NOT EXISTS file_hashes (
            file_path TEXT PRIMARY KEY,
            sha256 TEXT NOT NULL,
            last_modified TEXT NOT NULL
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS file_contents (
            file_path TEXT PRIMARY KEY,
            content TEXT NOT NULL,
            last_modified TEXT NOT NULL
        )
    ''')
    conn.commit()

def get_files_to_monitor():
    """Recursively find files with specified extensions in given directories and authorized_keys files."""
    files_to_monitor = []
    # Search for files with specified extensions
    for directory in DIRECTORIES_TO_SEARCH:
        if os.path.exists(directory):
            for root, dirs, files in os.walk(directory):
                for file in files:
                    full_path = os.path.join(root, file)
                    if file.endswith(FILE_EXTENSIONS):
                        files_to_monitor.append(full_path)
                    elif is_sensitive_file(full_path):
                        files_to_monitor.append(full_path)
    # Add authorized_keys files
    # For root user
    root_authorized_keys = '/root/.ssh/authorized_keys'
    if os.path.exists(root_authorized_keys):
        files_to_monitor.append(root_authorized_keys)
    # For other users
    for user in pwd.getpwall():
        user_home = user.pw_dir
        authorized_keys_path = os.path.join(user_home, '.ssh', 'authorized_keys')
        if os.path.exists(authorized_keys_path):
            files_to_monitor.append(authorized_keys_path)
    return files_to_monitor

def is_sensitive_file(file_path):
    """Determine if a file is sensitive based on its name or path."""
    filename = os.path.basename(file_path)
    if file_path in SENSITIVE_FILES:
        return True
    for pattern in SENSITIVE_PATTERNS:
        if pattern in filename:
            return True
    return False

def store_initial_hashes(conn, files_to_monitor):
    """Store the initial hashes and content of the files."""
    for file_path in files_to_monitor:
        sha256 = calculate_sha256(file_path)
        if sha256:
            last_modified = datetime.fromtimestamp(os.path.getmtime(file_path))
            conn.execute('''
                INSERT OR REPLACE INTO file_hashes (file_path, sha256, last_modified)
                VALUES (?, ?, ?)
            ''', (file_path, sha256, last_modified))
            # Store file content if not sensitive
            if not is_sensitive_file(file_path):
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                    conn.execute('''
                        INSERT OR REPLACE INTO file_contents (file_path, content, last_modified)
                        VALUES (?, ?, ?)
                    ''', (file_path, content, last_modified))
                except Exception as e:
                    print(f"Could not read file content for {file_path}: {e}")
            print(f"Stored hash for {file_path}")
        else:
            print(f"Could not access file: {file_path}")
    conn.commit()

def send_notifications(changed_files, args):
    """Send notifications to configured platforms."""
    message = f"File integrity changes detected:\n" + "\n".join(changed_files)
    if args.servicenow_instance and args.servicenow_user and args.servicenow_password:
        send_servicenow_alert(message, args)
    if args.rapid7_api_key:
        send_rapid7_alert(message, args)
    if args.jira_url and args.jira_user and args.jira_api_token:
        send_jira_issue(message, args)
    if args.slack_webhook_url:
        send_slack_message(message, args)
    if args.teams_webhook_url:
        send_teams_message(message, args)

def send_servicenow_alert(message, args):
    """Create an incident in ServiceNow."""
    url = f"https://{args.servicenow_instance}.service-now.com/api/now/table/incident"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    data = {
        "short_description": "File Integrity Alert",
        "description": message,
        "urgency": "2",
        "impact": "2"
    }
    try:
        response = requests.post(url, auth=(args.servicenow_user, args.servicenow_password), headers=headers, json=data)
        if response.status_code == 201:
            print("ServiceNow incident created successfully.")
        else:
            print(f"Failed to create ServiceNow incident: {response.text}")
    except Exception as e:
        print(f"Error sending to ServiceNow: {e}")

def send_rapid7_alert(message, args):
    """Send an alert to Rapid7 InsightConnect."""
    url = "https://us.api.insight.rapid7.com/connect/v1/workflows/trigger"
    headers = {
        "X-API-Key": args.rapid7_api_key,
        "Content-Type": "application/json"
    }
    data = {
        "workflow": args.rapid7_workflow_id,
        "message": message
    }
    try:
        response = requests.post(url, headers=headers, json=data)
        if response.status_code == 202:
            print("Rapid7 InsightConnect alert sent successfully.")
        else:
            print(f"Failed to send Rapid7 alert: {response.text}")
    except Exception as e:
        print(f"Error sending to Rapid7 InsightConnect: {e}")

def send_jira_issue(message, args):
    """Create an issue in Jira."""
    url = f"{args.jira_url}/rest/api/2/issue"
    auth = (args.jira_user, args.jira_api_token)
    headers = {
        "Content-Type": "application/json"
    }
    data = {
        "fields": {
            "project": {
                "key": args.jira_project_key
            },
            "summary": "File Integrity Alert",
            "description": message,
            "issuetype": {
                "name": "Task"
            }
        }
    }
    try:
        response = requests.post(url, headers=headers, auth=auth, json=data)
        if response.status_code == 201:
            print("Jira issue created successfully.")
        else:
            print(f"Failed to create Jira issue: {response.text}")
    except Exception as e:
        print(f"Error sending to Jira: {e}")

def send_slack_message(message, args):
    """Send a message to Slack."""
    data = {
        "text": message
    }
    try:
        response = requests.post(args.slack_webhook_url, json=data)
        if response.status_code == 200:
            print("Slack message sent successfully.")
        else:
            print(f"Failed to send Slack message: {response.text}")
    except Exception as e:
        print(f"Error sending to Slack: {e}")

def send_teams_message(message, args):
    """Send a message to Microsoft Teams."""
    data = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": "File Integrity Alert",
        "themeColor": "0076D7",
        "title": "File Integrity Alert",
        "text": message
    }
    try:
        response = requests.post(args.teams_webhook_url, json=data)
        if response.status_code == 200:
            print("Teams message sent successfully.")
        else:
            print(f"Failed to send Teams message: {response.text}")
    except Exception as e:
        print(f"Error sending to Teams: {e}")

def generate_diff(old_content, new_content):
    """Generate a unified diff between old and new content."""
    old_lines = old_content.splitlines(keepends=True)
    new_lines = new_content.splitlines(keepends=True)
    diff = difflib.unified_diff(old_lines, new_lines, fromfile='before', tofile='after')
    return ''.join(diff)

def check_for_changes(conn, files_to_monitor, args):
    """Check for changes in the file hashes and store diffs."""
    changes_detected = False
    changed_files = []
    for file_path in files_to_monitor:
        current_sha256 = calculate_sha256(file_path)
        if current_sha256:
            cursor = conn.execute('SELECT sha256 FROM file_hashes WHERE file_path = ?', (file_path,))
            row = cursor.fetchone()
            if row:
                stored_sha256 = row[0]
                if current_sha256 != stored_sha256:
                    print(f"Change detected in {file_path}")
                    changes_detected = True
                    changed_files.append(file_path)
                    last_modified = datetime.fromtimestamp(os.path.getmtime(file_path))
                    conn.execute('''
                        UPDATE file_hashes
                        SET sha256 = ?, last_modified = ?
                        WHERE file_path = ?
                    ''', (current_sha256, last_modified, file_path))
                    # Generate and store diff if not sensitive
                    if not is_sensitive_file(file_path):
                        try:
                            with open(file_path, 'r') as f:
                                new_content = f.read()
                            cursor = conn.execute('SELECT content FROM file_contents WHERE file_path = ?', (file_path,))
                            diff_row = cursor.fetchone()
                            old_content = diff_row[0] if diff_row else ''
                            diff = generate_diff(old_content, new_content)
                            conn.execute('''
                                UPDATE file_contents
                                SET content = ?, last_modified = ?
                                WHERE file_path = ?
                            ''', (new_content, last_modified, file_path))
                            # Optionally, store the diff in a file or send it with notifications
                            diff_filename = f'diffs/{os.path.basename(file_path)}.diff'
                            os.makedirs(os.path.dirname(diff_filename), exist_ok=True)
                            with open(diff_filename, 'w') as diff_file:
                                diff_file.write(diff)
                        except Exception as e:
                            print(f"Could not generate diff for {file_path}: {e}")
                    else:
                        print(f"Sensitive file changed: {file_path}. Diff not stored.")
            else:
                print(f"New file detected: {file_path}. Storing current hash.")
                last_modified = datetime.fromtimestamp(os.path.getmtime(file_path))
                conn.execute('''
                    INSERT INTO file_hashes (file_path, sha256, last_modified)
                    VALUES (?, ?, ?)
                ''', (file_path, current_sha256, last_modified))
                # Store file content if not sensitive
                if not is_sensitive_file(file_path):
                    try:
                        with open(file_path, 'r') as f:
                            content = f.read()
                        conn.execute('''
                            INSERT INTO file_contents (file_path, content, last_modified)
                            VALUES (?, ?, ?)
                        ''', (file_path, content, last_modified))
                    except Exception as e:
                        print(f"Could not read file content for {file_path}: {e}")
                changes_detected = True
                changed_files.append(file_path)
        else:
            print(f"Could not access file: {file_path}")
    conn.commit()
    if changes_detected:
        send_notifications(changed_files, args)
    else:
        print("No changes detected.")

def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description='File Integrity Monitoring Script')
    parser.add_argument('--init', action='store_true', help='Initialize and store file hashes')
    # ServiceNow arguments
    parser.add_argument('--servicenow-instance', help='ServiceNow instance name')
    parser.add_argument('--servicenow-user', help='ServiceNow username')
    parser.add_argument('--servicenow-password', help='ServiceNow password')
    # Rapid7 InsightConnect arguments
    parser.add_argument('--rapid7-api-key', help='Rapid7 InsightConnect API key')
    parser.add_argument('--rapid7-workflow-id', help='Rapid7 InsightConnect workflow ID')
    # Jira arguments
    parser.add_argument('--jira-url', help='Jira base URL')
    parser.add_argument('--jira-user', help='Jira username/email')
    parser.add_argument('--jira-api-token', help='Jira API token')
    parser.add_argument('--jira-project-key', help='Jira project key')
    # Slack arguments
    parser.add_argument('--slack-webhook-url', help='Slack incoming webhook URL')
    # Teams arguments
    parser.add_argument('--teams-webhook-url', help='Microsoft Teams incoming webhook URL')
    args = parser.parse_args()
    return args

def main():
    args = parse_arguments()
    conn = sqlite3.connect(DB_NAME)
    initialize_database(conn)
    files_to_monitor = get_files_to_monitor()
    if args.init:
        print("Initializing and storing file hashes...")
        store_initial_hashes(conn, files_to_monitor)
    else:
        print("Checking for changes...")
        check_for_changes(conn, files_to_monitor, args)
    conn.close()

if __name__ == '__main__':
    # Create diffs directory if it doesn't exist
    os.makedirs('diffs', exist_ok=True)
    main()
