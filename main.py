#!/usr/bin/env python3

"""
This file holds the main function that does all the things.

Inputs:
- GitHub API endpoint (assumes github.com if not specified or run within GHES/GHAE)
- PAT of appropriate scope (assumes the workflow token if not specified)
- Report scope ("enterprise", "organization", "repository")
- Enterprise slug OR organization name OR repository name
- Features to run (comma separated list of "secretscanning", "codescanning", "dependabot")

Outputs:
- CSV file of secret scanning alerts
- CSV file of code scanning alerts
- CSV file of Dependabot alerts 
"""

# Import modules
from src import code_scanning, dependabot, enterprise, secret_scanning
import os
import requests
import csv

# Possible strings indicating feature is not enabled
secret_scanning_disabled_strings = ["secret scanning is not enabled", "secret scanning is disabled"]
dependabot_disabled_strings = ["dependabot alerts are not enabled", "dependabot alerts are disabled"]

# Define the available features
FEATURES = ["secretscanning", "codescanning", "dependabot"]

# Read in config values
api_endpoint = os.getenv("GITHUB_API_URL", "https://api.github.com")
url = os.getenv("GITHUB_SERVER_URL", "https://github.com")
github_pat = os.getenv("GITHUB_PAT", os.getenv("GITHUB_TOKEN"))
report_scope = os.getenv("GITHUB_REPORT_SCOPE", "repository")
scope_name = os.getenv("SCOPE_NAME", os.getenv("GITHUB_REPOSITORY"))
requested_features = os.getenv("FEATURES")
if (requested_features is None) or (requested_features == "all"):
    features = FEATURES
else:
    features = requested_features.split(",")
    for f in features:
        if f not in FEATURES:
            print(f"Invalid feature: {f}. Proceeding without. Valid features are: {FEATURES}")
            features.remove(f)


def get_repo_admins(repo_name, api_endpoint, github_pat):
    """Fetches admin details for a given repository."""
    headers = {
        "Authorization": f"token {github_pat}",
        "Accept": "application/vnd.github.v3+json"
    }
    url = f"{api_endpoint}/repos/{repo_name}/collaborators?affiliation=admin"
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    admins = [collaborator['login'] for collaborator in response.json() if collaborator['permissions']['admin']]
    return admins


def write_csv_with_admins(filename, data, admin_details):
    """Writes data to a CSV file and includes admin details."""
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        headers = list(data[0].keys()) + ['Admins']
        writer.writerow(headers)
        for row in data:
            repo_name = row.get('repository', scope_name)  # Adjust as needed
            admins = admin_details.get(repo_name, [])
            writer.writerow(list(row.values()) + [', '.join(admins)])


# Do the things!
if __name__ == "__main__":
    print("Starting GitHub security report...")
    admin_details = {}
    # Fetch admin details if needed
    if report_scope == "repository":
        admin_details[scope_name] = get_repo_admins(scope_name, api_endpoint, github_pat)
    elif report_scope in ["organization", "enterprise"]:
        # Example: For an organization, iterate through its repositories to get admin details
        repos = [scope_name]  # Replace with actual repo list fetching logic
        for repo in repos:
            admin_details[repo] = get_repo_admins(repo, api_endpoint, github_pat)
    
    # enterprise scope
    if report_scope == "enterprise":
        # secret scanning
        if "secretscanning" in features:
            try:
                secrets_list = secret_scanning.get_enterprise_ss_alerts(api_endpoint, github_pat, scope_name)
                write_csv_with_admins("enterprise_secret_scanning.csv", secrets_list, admin_details)
            except Exception as e:
                if any(x in str(e).lower() for x in secret_scanning_disabled_strings):
                    print("Skipping Secret Scanning as it is not enabled.")
                    print(e)
                else:
                    raise
        # code scanning
        if "codescanning" in features:
            version = enterprise.get_enterprise_version(api_endpoint)
            # For GHES version 3.5 and 3.6 we need to loop through each repo
            # and use the repo level api to get the code scanning alerts.
            # For 3.7 and above we use the enterprise level api to get the code scanning alerts
            if version.startswith("3.5") or version.startswith("3.6"):
                repo_list = enterprise.get_repo_report(url, github_pat)
                cs_list = code_scanning.list_enterprise_server_cs_alerts(api_endpoint, github_pat, repo_list)
                write_csv_with_admins("enterprise_code_scanning.csv", cs_list, admin_details)
            else:
                cs_list = code_scanning.list_enterprise_cloud_cs_alerts(api_endpoint, github_pat, scope_name)
                write_csv_with_admins("enterprise_code_scanning.csv", cs_list, admin_details)
        # dependabot alerts
        if "dependabot" in features:
            try:
                dependabot_list = dependabot.list_enterprise_dependabot_alerts(api_endpoint, github_pat, scope_name)
                write_csv_with_admins("enterprise_dependabot.csv", dependabot_list, admin_details)
            except Exception as e:
                if any(x in str(e).lower() for x in dependabot_disabled_strings):
                    print("Skipping Dependabot as it is not enabled.")
                    print(e)
                else:
                    raise
    # organization scope
    elif report_scope == "organization":
        # code scanning
        if "codescanning" in features:
            cs_list = code_scanning.list_org_cs_alerts(api_endpoint, github_pat, scope_name)
            write_csv_with_admins("organization_code_scanning.csv", cs_list, admin_details)
        # dependabot alerts
        if "dependabot" in features:
            try:
                dependabot_list = dependabot.list_org_dependabot_alerts(api_endpoint, github_pat, scope_name)
                write_csv_with_admins("organization_dependabot.csv", dependabot_list, admin_details)
            except Exception as e:
                if any(x in str(e).lower() for x in dependabot_disabled_strings):
                    print("Skipping Dependabot as it is not enabled.")
                    print(e)
                else:
                    raise
        # secret scanning
        if "secretscanning" in features:
            try:
                secrets_list = secret_scanning.get_org_ss_alerts(api_endpoint, github_pat, scope_name)
                write_csv_with_admins("organization_secret_scanning.csv", secrets_list, admin_details)
            except Exception as e:
                if any(x in str(e).lower() for x in secret_scanning_disabled_strings):
                    print("Skipping Secret Scanning as it is not enabled.")
                    print(e)
                else:
                    raise
    # repository scope
    elif report_scope == "repository":
        # code scanning
        if "codescanning" in features:
            cs_list = code_scanning.list_repo_cs_alerts(api_endpoint, github_pat, scope_name)
            write_csv_with_admins("repository_code_scanning.csv", cs_list, admin_details)
        # dependabot alerts
        if "dependabot" in features:
            try:
                dependabot_list = dependabot.list_repo_dependabot_alerts(api_endpoint, github_pat, scope_name)
                write_csv_with_admins("repository_dependabot.csv", dependabot_list, admin_details)
            except Exception as e:
                if any(x in str(e).lower() for x in dependabot_disabled_strings):
                    print("Skipping Dependabot as it is not enabled.")
                    print(e)
                else:
                    raise
        # secret scanning
        if "secretscanning" in features:
            try:
                secrets_list = secret_scanning.get_repo_ss_alerts(api_endpoint, github_pat, scope_name)
                write_csv_with_admins("repository_secret_scanning.csv", secrets_list, admin_details)
            except Exception as e:
                if any(x in str(e).lower() for x in secret_scanning_disabled_strings):
                    print("Skipping Secret Scanning as it is not enabled.")
                    print(e)
                else:
                    raise
    else:
        exit("Invalid report scope")
