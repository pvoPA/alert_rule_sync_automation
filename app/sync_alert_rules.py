"""
Prisma Alert Rule Automation Syncing Script

This file performs the syncing of alert rules, which includes:
    - RQL query through Prisma
    - Parse the RQL for a unique tag
    - Get existing alert rules in Prisma
    - Parse the alert rules prepended with
        the automation prefix indicating automated alert rules only.
    - Alert sync automation
        - If an alert rule does exist for a unique tag,
            nothing will happen.
        - If an alert rule does not exist for a unique tag,
            one will be created.
        - If an alert rule does exist but the unique tag no longer exists,
            the alert rule will be removed
    - Logging progress updates to the console.

Usage:
    python sync_alert_rules.py

Options:

Requirements:
    - Python 3.10 or higher
    - .env configured with the following variables,
        - PRISMA_ACCESS_KEY
        - PRISMA_SECRET_KEY

Example:
    python sync_alert_rules.py

Note:
    This script is meant to be deployed in a docker container or azure function.

"""

import os
import json
import ast
from helpers import prisma_login
from helpers import prisma_rql_query
from helpers import prisma_get_alert_rules
from helpers import prisma_create_alert_rule
from helpers import prisma_get_policies
from helpers import prisma_get_account_groups
from helpers import prisma_delete_alert_rule
from helpers import prisma_get_email_templates
from helpers import logger


def main(data="", context=""):
    """
    Run the alert rule sync automation.

    Parameters:
        data: required for Azure function deployment
        context: required for Azure function deployment

    Returns:
        None
    """
    ###########################################################################
    # local variables
    prisma_access_key = os.getenv("ACCESS_KEY")
    prisma_secret_key = os.getenv("SECRET_KEY")
    rql_query = os.getenv("RQL_QUERY")
    rql_time_range = json.loads(os.getenv("RQL_TIME_RANGE"))
    unique_attribute = os.getenv("UNIQUE_ATTRIBUTE")
    automation_prefix = os.getenv("AUTOMATION_PREFIX")
    policy_type_filters = json.loads(os.getenv("POLICY_TYPE_FILTER"))
    policy_sub_type_filters = json.loads(os.getenv("POLICY_SUB_TYPE_FILTER"))
    policy_severity_filters = json.loads(os.getenv("POLICY_SEVERITY_FILTER"))
    policy_cloud_filters = json.loads(os.getenv("POLICY_CLOUDTYPE_FILTER"))
    account_group_filters = json.loads(os.getenv("ACCOUNT_GROUP_FILTER"))
    email_compressed = ast.literal_eval(os.getenv("EMAIL_COMPRESSED"))
    email_include_remediation = ast.literal_eval(os.getenv("EMAIL_INCLUDE_REMEDIATION"))
    include_detailed_report = ast.literal_eval(
        os.getenv("EMAIL_INCLUDE_DETAILED_REPORT")
    )
    email_frequency_config = os.getenv("EMAIL_FREQUENCY")
    email_timezone = os.getenv("EMAIL_TIMEZONE")
    email_frequency = (
        f"DTSTART;TZID={email_timezone}:20230601T000000\n{email_frequency_config}"
    )

    email_template_name = os.getenv("EMAIL_TEMPLATE_NAME")
    auto_remediate_alerts = ast.literal_eval(os.getenv("AUTO_REMEDIATE"))

    # lower case the filters for proper comparison
    policy_type_filter = [policy_type.lower() for policy_type in policy_type_filters]

    policy_sub_type_filter = [
        [policy_sub_type.lower() for policy_sub_type in filter]
        for filter in policy_sub_type_filters
    ]

    policy_severity_filter = [
        policy_severity.lower() for policy_severity in policy_severity_filters
    ]

    account_group_filter = [
        account_group.lower() for account_group in account_group_filters
    ]

    policy_cloud_filter = [cloud_type.lower() for cloud_type in policy_cloud_filters]

    try:
        rql_limit = int(os.getenv("RQL_LIMIT"))
    except ValueError:
        rql_limit = None

    prisma_response, status_code = prisma_login(prisma_access_key, prisma_secret_key)

    if status_code == 200:
        prisma_token = prisma_response["token"]
        prisma_tenant_id = prisma_response["customerNames"][0]["prismaId"]

    else:
        logger.error(
            "Expected API Status Code: %d,\n\tGot %s instead.", 200, status_code
        )
    ###########################################################################
    # RQL query through Prisma.

    prisma_query_response = prisma_rql_query(
        prisma_token, rql_query, time_range=rql_time_range, limit=rql_limit
    )

    ##########################################################################
    # Parse the RQL for a unique tag

    logger.info("Parsing RQL query response for %s in the tags", unique_attribute)

    tag_list = list()

    if prisma_query_response:
        for item in prisma_query_response:
            if "tags" in item["data"]:
                if unique_attribute in item["data"]["tags"]:
                    tag_list.append(item["data"]["tags"][unique_attribute])

    else:
        logger.info("The query,\n\t%s\ndid not return anything.", rql_query)

    unique_tags = list(set(tag_list))

    logger.info(
        "Found %i unique tags that match %s", len(unique_tags), unique_attribute
    )

    ###########################################################################
    #   Get existing alert rules in Prisma

    alert_rules, status_code = prisma_get_alert_rules(prisma_token)

    ###########################################################################
    #   Parse the alert rules prepended with
    #       the automation prefix indicating automated alert rules only.

    if status_code == 200:
        logger.info("Parsing alert rules prefixed with %s", automation_prefix)

        auto_generated_alert_rule_tags = dict()

        for alert_rule in alert_rules:
            if str(alert_rule["name"]).startswith(automation_prefix):
                keys = [k for k in alert_rule["target"]["tags"]]
                tags = {key["key"]: key["values"] for key in keys}
                if unique_attribute in tags:
                    auto_generated_alert_rule_tags.update(
                        {tags[unique_attribute][0]: alert_rule}
                    )
    elif status_code == 401:
        logger.error("Prisma token timed out, generating a new one and continuing.")

        prisma_token = prisma_login(prisma_access_key, prisma_secret_key)

    else:
        logger.error(
            "Expected API Status Code: %d,\n\tGot %s instead.", 200, status_code
        )

    ###########################################################################
    #   Grab all policies
    #       Parse policy IDs for
    #           Type = "config"
    #           SubType = ["run"] or ["run","build"]
    #           Severity in ["low","medium","high","critical"]
    #           Cloud Type in ["Azure"]

    policy_response, status_code = prisma_get_policies(
        prisma_token, detailed_compliance_mappings=False
    )

    if status_code == 200:
        policy_ids = list()

        for policy in policy_response:
            # if any of the filters are empty, this assumes no filtering
            if policy_type_filter:
                matching_type = False
            else:
                matching_type = True
            if policy_sub_type_filter:
                matching_sub_type = False
            else:
                matching_sub_type = True
            if policy_severity_filter:
                matching_severity = False
            else:
                matching_severity = True
            if policy_cloud_filter:
                matching_cloud_type = False
            else:
                matching_cloud_type = True

            # check the policy for the filter
            if str(policy["policyType"]).lower() in policy_type_filter:
                matching_type = True

            policy_sub_types = [
                policy_sub_type.lower() for policy_sub_type in policy["policySubTypes"]
            ]

            if policy_sub_types in policy_sub_type_filter:
                matching_sub_type = True

            if str(policy["severity"]).lower() in policy_severity_filter:
                matching_severity = True

            if str(policy["cloudType"]).lower() in policy_cloud_filter:
                matching_cloud_type = True

            if (
                matching_type
                and matching_sub_type
                and matching_severity
                and matching_cloud_type
            ):
                policy_ids.append(policy["policyId"])
    elif status_code == 401:
        logger.error("Prisma token timed out, generating a new one and continuing.")

        prisma_token = prisma_login(prisma_access_key, prisma_secret_key)

    else:
        logger.error(
            "Expected API Status Code: %d,\n\tGot %s instead.", 200, status_code
        )

    ###########################################################################
    #   Grab the account group ID matching Azure Tenant Group

    account_group_response, status_code = prisma_get_account_groups(
        prisma_token, exclude_cloud_account_details=True
    )

    if status_code == 200:
        account_group_ids = list()

        for account_group in account_group_response:
            if account_group_filter:
                if str(account_group["name"]).lower() in account_group_filter:
                    account_group_ids.append(account_group["id"])

                    account_group_filter.remove(str(account_group["name"]).lower())
    elif status_code == 401:
        logger.error("Prisma token timed out, generating a new one and continuing.")

        prisma_token = prisma_login(prisma_access_key, prisma_secret_key)
    else:
        logger.error(
            "Expected API Status Code: %d,\n\tGot %s instead.", 200, status_code
        )

    ###########################################################################
    #   Grab the template ID matching email template name

    email_template_id = ""
    email_template_found = False

    email_template_response, status_code = prisma_get_email_templates(
        prisma_token, prisma_tenant_id
    )

    if status_code == 200:
        for email_template in email_template_response:
            if str(email_template["name"]).lower() == str(email_template_name).lower():
                email_template_id = email_template["id"]
                email_template_found = True
                break

        if not email_template_found:
            logger.error(
                "Unable to locate template ID for %s,"
                " creating alert rules with no email template.",
                email_template_name,
            )
    elif status_code == 401:
        logger.error("Prisma token timed out, generating a new one and continuing.")

        prisma_token = prisma_login(prisma_access_key, prisma_secret_key)
    else:
        logger.error(
            "Expected API Status Code: %d,\n\tGot %s instead.", 200, status_code
        )

    ###########################################################################
    # Alert sync automation

    if not unique_tags:
        logger.info(
            "No values for %s found to create Alert Rules for.", unique_attribute
        )

    for unique_tag in unique_tags:
        if unique_tag in auto_generated_alert_rule_tags:
            ###################################################################
            #   If an alert rule does exist for a unique tag,
            #       remove it from the list to get the diff
            auto_generated_alert_rule_tags.pop(unique_tag)
        else:
            ###################################################################
            #   If an alert rule does not exist for a unique tag,
            #       one will be created.
            alert_rule_name = f"{automation_prefix}-{unique_tag}"
            description = f"Alert rule for {unique_attribute}"
            tags = [{"key": unique_attribute, "values": [unique_tag]}]
            alert_rule_notification_config = [
                {
                    "enabled": True,
                    # "recipients": [f"{unique_tag}"],
                    "recipients": ["testemail@email.com"],
                    "type": "email",
                    "detailedReport": include_detailed_report,
                    "withCompression": email_compressed,
                    "includeRemediation": email_include_remediation,
                }
            ]

            target_resource_list = {"reason": "", "enabled": False, "ids": []}

            if email_template_id:
                alert_rule_notification_config[0].update(
                    {"templateId": email_template_id}
                )

            if email_frequency:
                # "rruleSchedule": "DTSTART;TZID=America/Los_Angeles:20230601T000000\nBYHOUR=0;BYMINUTE=0;BYSECOND=0;FREQ=MONTHLY;INTERVAL=1;BYMONTHDAY=1",
                alert_rule_notification_config[0].update(
                    {"rruleSchedule": email_frequency}
                )
            else:
                alert_rule_notification_config[0].update({"frequency": "as_it_happens"})

            delay_notification_ms = 300000
            notify_on_open = True
            allow_auto_remediate = auto_remediate_alerts

            # Create the Alert Rule
            create_alert_rule_response, status_code = prisma_create_alert_rule(
                prisma_token,
                alert_rule_notification_config=alert_rule_notification_config,
                delay_notification_ms=delay_notification_ms,
                target_resource_list=target_resource_list,
                notify_on_open=notify_on_open,
                alert_rule_name=alert_rule_name,
                description=description,
                policies=policy_ids,
                account_groups=account_group_ids,
                tags=tags,
                allow_auto_remediate=allow_auto_remediate,
            )

            if status_code == 200:
                logger.info("Successfully created the Alert Rule %s", alert_rule_name)

                logger.info(create_alert_rule_response)
            elif status_code == 401:
                logger.error(
                    "Prisma token timed out, generating a new one and continuing."
                )

                prisma_token = prisma_login(prisma_access_key, prisma_secret_key)
            else:
                logger.error(
                    "Expected API Status Code: %d,\n\tGot %s instead.", 200, status_code
                )

        # for testing
        break

    if not auto_generated_alert_rule_tags:
        logger.info(
            "No existing Alert Rules prefixed with %s to delete.", automation_prefix
        )

    for auto_generated_alert_rule in auto_generated_alert_rule_tags.items():
        #######################################################################
        #   If an alert rule does exist but the unique tag no longer exists,
        #       the alert rule will be removed

        delete_alert_rule_response, status_code = prisma_delete_alert_rule(
            prisma_token, auto_generated_alert_rule[1]["policyScanConfigId"]
        )

        if status_code == 204:
            logger.info(
                "Successfully deleted Alert Rule %s",
                auto_generated_alert_rule[1]["name"],
            )
        elif status_code == 401:
            logger.error("Prisma token timed out, generating a new one and continuing.")

            prisma_token = prisma_login(prisma_access_key, prisma_secret_key)
        else:
            logger.error(
                "Expected API Status Code: %d,\n\tGot %s instead.", 204, status_code
            )


if __name__ == "__main__":
    main()
