"""
This file contains a collection of helper functions for automating tasks.

Functions:
- generate_prisma_token(access_key, secret_key): Returns a PRISMA token.
- prisma_rql_query(token, query, time_range, limit): Returns query response

Usage:
Simply import this file and call the function. For example:

    from helpers import generate_prisma_token
    prisma_token = generate_prisma_token()

Note:
Before using these functions, be sure to configure the .env appropriately.
"""

import os
import json
import logging
from typing import Tuple
import requests
from dotenv import load_dotenv


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()
logger.setLevel(logging.INFO)

load_dotenv()

CSPM_ENDPOINT = os.getenv("CSPM_API")


def prisma_login(access_key: str, secret_key: str) -> Tuple[dict, int]:
    """
    Generate the token for Prisma API access.

    https://pan.dev/prisma-cloud/api/cspm/app-login/

    Parameters:
        access_key (str): Prisma generated access key
        secret_key (str): Prisma generated secret key

    Returns:
        Tuple[dict, int]:
            Prisma token and tenant info
            Response status code

    """
    endpoint = f"https://{CSPM_ENDPOINT}/login"

    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
    }

    body = {"username": access_key, "password": secret_key}

    logger.info("Generating Prisma token using endpoint: %s", endpoint)

    response = requests.post(endpoint, headers=headers, json=body, timeout=360)

    if response.status_code == 200:
        data = json.loads(response.text)

        return data, 200
    else:
        return None, response.status_code


def prisma_rql_query(token: str, query: str, time_range="", limit="") -> list:
    """
    Queries GCP using Prisma as the middleman.

    https://pan.dev/prisma-cloud/api/cspm/search-config/

    Parameters:
    token (str): Prisma token for API access.
    query (str): RQL query.
    time_range(str): optional, limit items returned based on time range.
    limit (int): optional, limit items returned in the RQL query.

    Returns:
    list: Query response.

    """
    endpoint = f"https://{CSPM_ENDPOINT}/search/config"

    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
        "x-redlock-auth": token,
    }

    payload = {
        "query": query,
    }

    if time_range:
        payload.update({"timeRange": time_range})

    if limit:
        payload.update({"limit": int(limit)})

    logger.info("Sending the following query to Prisma,\n\t%s", payload)

    response = requests.post(endpoint, json=payload, headers=headers, timeout=360)

    data = json.loads(response.text)

    return data["data"]["items"]


def prisma_get_alert_rules(token: str) -> Tuple[list[dict], int]:
    """
    Returns all alert rules you have permission to see based on your role.
    The data returned does not include an open alerts count.

    https://pan.dev/prisma-cloud/api/cspm/get-alert-rules-v-2/

    Parameters:
    token (str): Prisma token for API access.

    Returns:
    Tuple[list[dict], int]: List of alert rules and response status code.

    """
    endpoint = f"https://{CSPM_ENDPOINT}/v2/alert/rule"

    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
        "x-redlock-auth": token,
    }

    response = requests.get(endpoint, headers=headers, timeout=360)

    if response.status_code == 200:
        data = json.loads(response.text)

        return data, 200
    else:
        return None, response.status_code


def prisma_get_email_templates(token: str, tenant_id: str) -> Tuple[list[dict], int]:
    """
    Returns a list of notification templates.

    The caller must have one of the following Prisma Cloud roles:

    System Admin
    Account Group Admin
    Account and Cloud Provisioning Admin
    Account Group Read Only

    https://pan.dev/prisma-cloud/api/cspm/get-all-templates-v-1/

    Parameters:
        token (str): Prisma token for API access.
        tenant_id (str): Prisma ID.
            Your Prisma ID is available either from the response object
            of your API request to log in or from the licensing information
            in the Prisma Cloud console.

    Returns:
        Tuple[list[dict], int]:
            List of notification templates
            Response status code

    """
    endpoint = f"https://{CSPM_ENDPOINT}/api/v1/tenant/{tenant_id}/template"

    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
        "x-redlock-auth": token,
    }

    response = requests.get(endpoint, headers=headers, timeout=360)

    if response.status_code == 200:
        data = json.loads(response.text)

        return data, 200
    else:
        return None, response.status_code


def prisma_create_alert_rule(
    token: str,
    alert_rule_name="",
    description="",
    alert_rule_notification_config=[],
    delay_notification_ms=0,
    enabled=True,
    notify_on_dismissed=False,
    notify_on_open=True,
    notify_on_resolved=False,
    notify_on_snoozed=False,
    policies=[],
    policy_labels=[],
    scan_all=False,
    account_groups=[],
    excluded_accounts=[],
    regions=[],
    tags=[],
    target_resource_list={},
    alert_rule_policy_filer={},
    compute_access_group_ids=[],
    allow_auto_remediate=False,
) -> Tuple[list[dict], int]:
    """
    Creates an alert rule in Prisma.

    https://pan.dev/prisma-cloud/api/cspm/get-alert-rules-v-2/

    Args:
        token (str): Prisma token
        alert_rule_name (str, optional): Name of the alert rule.
            Defaults to "".
        description (str, optional): Description of the alert rule.
            Defaults to "".
        alert_rule_notification_config (list, optional): List of data for notifications to third-party tools.
            Defaults to [].
        delay_notification_ms (int, optional): Delay notifications by the specified milliseconds.
            Defaults to 0.
        enabled (bool, optional): Rule/Scan is enabled. Defaults to True.
        notify_on_dismissed (bool, optional): include dismissed alerts in notification.
            Defaults to False.
        notify_on_open (bool, optional): include open alerts in notification.
            Defaults to True.
        notify_on_resolved (bool, optional): include resolved alerts in notification.
            Defaults to False.
        notify_on_snoozed (bool, optional): include snoozed alerts in notification.
            Defaults to False.
        policies (list, optional): List of specific policies to scan.
            Defaults to [].
        policy_labels (list, optional): Policy labels.
            Defaults to [].
        scan_all (bool, optional): Scan all policies.
            Defaults to False.
        account_groups (list, optional): List of Account group(s).
            Defaults to [].
        excluded_accounts (list, optional): List of excluded accounts.
            Defaults to [].
        regions (list, optional): List of regions for which alerts will be triggered for account groups.
            Alerts not associated with specific regions will be triggered regardless of listed regions.
            If no regions are specified, then the alerts will be triggered for all regions.
            Defaults to [].
        tags (list, optional): List of TargetTag models (resource tags) for which alerts should be triggered.
            Defaults to [].
        target_resource_list (dict, optional): Model for holding the lists resource list ids by resource list type.
            Defaults to {}.
        alert_rule_policy_filer (dict, optional): Model for Alert Rule Policy Filter.
            Defaults to {}.
        compute_access_group_ids (list, optional): _description_.
            Defaults to [].
        allow_auto_remediate (bool, optional): Allow Auto-Remediation.
            Defaults to False.

    Returns:
        Tuple[list[dict], int]: List of alert rules and response status code.
    """
    endpoint = f"https://{CSPM_ENDPOINT}/alert/rule"

    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
        "x-redlock-auth": token,
    }

    payload = {
        "alertRuleNotificationConfig": alert_rule_notification_config,
        "description": description,
        "name": alert_rule_name,
        "delayNotificationMs": delay_notification_ms,
        "enabled": enabled,
        "notifyOnDismissed": notify_on_dismissed,
        "notifyOnOpen": notify_on_open,
        "notifyOnResolved": notify_on_resolved,
        "notifyOnSnoozed": notify_on_snoozed,
        "policies": policies,
        "policyLabels": policy_labels,
        "scanAll": scan_all,
        "target": {
            "accountGroups": account_groups,
            "excludedAccounts": excluded_accounts,
            "regions": regions,
            "tags": tags,
            "targetResourceList": target_resource_list,
            "alertRulePolicyFilter": alert_rule_policy_filer,
            "includedResourceLists": {
                "computeAccessGroupIds": compute_access_group_ids
            },
        },
        "allowAutoRemediate": allow_auto_remediate,
    }

    logger.info("Sending request to %s with payload, \r\n%s", endpoint, payload)

    response = requests.post(endpoint, json=payload, headers=headers, timeout=360)

    logger.info(
        "API returned %s",
        response.status_code,
    )

    if response.status_code == 200:
        data = json.loads(response.text)

        return data, 200
    else:
        return None, response.status_code


def prisma_get_policies(
    token: str, detailed_compliance_mappings=None
) -> Tuple[list[dict], int]:
    """
    Returns all available policies, both system default and custom.
    You can apply filters to narrow the returned policy list to a subset of policies or potentially to a specific policy.
    For improved performance, response does not include open alert counts.

    https://pan.dev/prisma-cloud/api/cspm/get-policies-v-2/

    Args:
        token (str): Prisma token.
        detailed_compliance_mappings (bool, optional): Return detailed information about compliance mappings with policies.
            Defaults to None.

    Returns:
        Tuple[list[dict], int]: list of policies and response status code.
    """
    endpoint = f"https://{CSPM_ENDPOINT}/v2/policy"

    if detailed_compliance_mappings:
        endpoint = f"https://{CSPM_ENDPOINT}/v2/policy?detailedComplianceMappings={detailed_compliance_mappings}"

    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
        "x-redlock-auth": token,
    }

    logger.info(
        "Sending request to %s",
        endpoint,
    )

    response = requests.get(endpoint, headers=headers, timeout=360)

    logger.info("API returned %s", response.status_code)

    if response.status_code == 200:
        data = json.loads(response.text)

        return data, 200
    else:
        return None, response.status_code


def prisma_get_account_groups(
    token: str, exclude_cloud_account_details=None
) -> Tuple[list[dict], int]:
    """
    Returns an array of accessible account groups.

    https://pan.dev/prisma-cloud/api/cspm/get-account-groups/

    Args:
        token (str): Prisma token.
        exclude_cloud_account_details (bool, optional): Return detailed information about compliance mappings with policies.
            Defaults to None.

    Returns:
        Tuple[list[dict], int]: list of account groups and response status code.
    """
    endpoint = f"https://{CSPM_ENDPOINT}/cloud/group"

    if exclude_cloud_account_details:
        endpoint = f"https://{CSPM_ENDPOINT}/cloud/group?excludeCloudAccountDetails={exclude_cloud_account_details}"

    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
        "x-redlock-auth": token,
    }

    logger.info(
        "Sending request to %s",
        endpoint,
    )

    response = requests.get(endpoint, headers=headers, timeout=360)

    logger.info("API returned %s", response.status_code)

    if response.status_code == 200:
        data = json.loads(response.text)

        return data, 200
    else:
        return None, response.status_code


def prisma_delete_alert_rule(token: str, alert_rule_id: str) -> Tuple[None, int]:
    """
    Deletes the alert rule that has the specified ID.

    https://pan.dev/prisma-cloud/api/cspm/delete-alert-rule/

    Args:
        token (str): Prisma token
        alert_rule_id (str): Alert rule ID (also known as the "policyScanConfigId")

    Returns:
        Tuple[list, int]: None, response status code.
    """
    endpoint = f"https://{CSPM_ENDPOINT}/alert/rule/{alert_rule_id}"

    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
        "x-redlock-auth": token,
    }

    logger.info(
        "Sending request to %s",
        endpoint,
    )

    response = requests.delete(endpoint, headers=headers, timeout=360)

    logger.info("API returned %s - %s", response.status_code, response.text)

    if response.status_code == 204:
        return None, 204
    else:
        return None, response.status_code
