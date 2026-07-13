#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import copy
import datetime
import json
import os
import subprocess
import sys

from config.local_settings_and_secrets import (
    CLI_COMMAND_TIMEOUT_SECONDS,
    KTALK_AGGREGATE_MESSAGE_REPEAT_COUNT,
)


############################### VARS ###############################

CLI_PATH_DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "alios.py")
STATE_FILE_DEFAULT = "/tmp/alerts.json"
DATETIME_FORMAT = "%Y.%m.%d %H:%M:%S"
DEFAULT_DELETE_DELAY_MINUTES = 30
DELETE_DELAY_RULES = [
    {
        "name": "night_period",
        "weekdays": None,
        "start_time": "21:00",
        "end_time": "09:00",
        "delay_minutes": 180,
    },
    {
        "name": "weekend",
        "weekdays": [5, 6],
        "start_time": None,
        "end_time": None,
        "delay_minutes": 180,
    },
]
VERBOSE = False

BASE_STEPS = [
    "resolveInsightId",
    "loadInsightData",
]

SEVERITY_STEPS = {
    "0": [],
    "1": [
        "resolveKTalkUsers",
        "createLowSeverityJiraIncident",
        "sendLowSeverityRootMessage",
        "inviteKTalkUsers",
        "mentionKTalkUsers",
        "sendLowSeverityAggregateMessage",
    ],
    "2": [
        "resolveKTalkUsers",
        "createLowSeverityJiraIncident",
        "sendLowSeverityRootMessage",
        "inviteKTalkUsers",
        "mentionKTalkUsers",
        "sendLowSeverityAggregateMessage",
    ],
    "3": [
        "resolveKTalkUsers",
        "createLowSeverityJiraIncident",
        "sendLowSeverityRootMessage",
        "inviteKTalkUsers",
        "mentionKTalkUsers",
        "sendLowSeverityAggregateMessage",
    ],
    "4": [
        "resolveKTalkUsers",
        "createLowSeverityJiraIncident",
        "sendLowSeverityRootMessage",
        "inviteKTalkUsers",
        "mentionKTalkUsers",
        "sendLowSeverityAggregateMessage",
    ],
    "5": [
        "resolveKTalkUsers",
        "createCriticalJiraIncident",
        "sendCriticalRootMessage",
        "inviteKTalkUsers",
        "mentionKTalkUsers",
        "sendCriticalAggregateMessage",
    ],
}

STEP_TEMPLATES = {
    "resolveInsightId": {
        "stepName": "resolveInsightId",
        "moduleName": "InsightID",
        "stepState": 0,
        "errorMessage": "",
        "retryNumber": 0,
        "insightId": "",
    },
    "loadInsightData": {
        "stepName": "loadInsightData",
        "moduleName": "InsightData",
        "stepState": 0,
        "errorMessage": "",
        "retryNumber": 0,
        "isActiv": 0,
        "fullName": "",
        "functionObjectKey": "",
        "jiraIncidentTypeKey": "",
        "recipientADUserList": [],
    },
    "resolveKTalkUsers": {
        "stepName": "resolveKTalkUsers",
        "moduleName": "KTalkUsers",
        "stepState": 0,
        "errorMessage": "",
        "retryNumber": 0,
        "recipientList": [],
        "notFoundADUserList": [],
        "withoutMentionIdList": [],
    },
    "createLowSeverityJiraIncident": {
        "stepName": "createLowSeverityJiraIncident",
        "moduleName": "JiraINC",
        "stepState": 0,
        "errorMessage": "",
        "retryNumber": 0,
        "jiraKey": "",
        "jiraUrl": "",
    },
    "createCriticalJiraIncident": {
        "stepName": "createCriticalJiraIncident",
        "moduleName": "JiraINC",
        "stepState": 0,
        "errorMessage": "",
        "retryNumber": 0,
        "jiraKey": "",
        "jiraUrl": "",
    },
    "sendLowSeverityRootMessage": {
        "stepName": "sendLowSeverityRootMessage",
        "moduleName": "KTalkMessage",
        "stepState": 0,
        "errorMessage": "",
        "retryNumber": 0,
        "messageAttributes": "",
        "messageID": "",
        "messageDeliveryTime": "",
        "sended": 0,
    },
    "sendCriticalRootMessage": {
        "stepName": "sendCriticalRootMessage",
        "moduleName": "KTalkMessage",
        "stepState": 0,
        "errorMessage": "",
        "retryNumber": 0,
        "messageAttributes": "",
        "messageID": "",
        "messageDeliveryTime": "",
        "sended": 0,
    },
    "inviteKTalkUsers": {
        "stepName": "inviteKTalkUsers",
        "moduleName": "KTalkMessage",
        "stepState": 0,
        "errorMessage": "",
        "retryNumber": 0,
        "sended": 0,
    },
    "mentionKTalkUsers": {
        "stepName": "mentionKTalkUsers",
        "moduleName": "KTalkMessage",
        "stepState": 0,
        "errorMessage": "",
        "retryNumber": 0,
        "sended": 0,
    },
    "sendLowSeverityAggregateMessage": {
        "stepName": "sendLowSeverityAggregateMessage",
        "moduleName": "KTalkMessage",
        "stepState": 1,
        "errorMessage": "",
        "retryNumber": 0,
        "targetEventBalance": 1,
        "deliveredEventBalance": 1,
        "repeatNumber": 0,
        "repeatLimit": KTALK_AGGREGATE_MESSAGE_REPEAT_COUNT,
        "successfulDeliveryNumber": 0,
        "messageAttributes": "",
        "lastMessageID": "",
        "lastMessageDeliveryTime": "",
        "nextDeliveryTime": "",
        "sended": 0,
    },
    "sendCriticalAggregateMessage": {
        "stepName": "sendCriticalAggregateMessage",
        "moduleName": "KTalkMessage",
        "stepState": 1,
        "errorMessage": "",
        "retryNumber": 0,
        "targetEventBalance": 1,
        "deliveredEventBalance": 1,
        "repeatNumber": 0,
        "repeatLimit": KTALK_AGGREGATE_MESSAGE_REPEAT_COUNT,
        "successfulDeliveryNumber": 0,
        "messageAttributes": "",
        "lastMessageID": "",
        "lastMessageDeliveryTime": "",
        "nextDeliveryTime": "",
        "sended": 0,
    },
}


############################### ARGS ###############################


def GetArgs():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cli-path", dest="cli_path", default=CLI_PATH_DEFAULT)
    parser.add_argument("--state-file", dest="state_file", default=STATE_FILE_DEFAULT)
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args()


############################### LOGS ###############################


def WriteLog(message, level):
    if not VERBOSE:
        return
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("{} [{}] watcher: {}".format(now, level, message))


############################### CLI ###############################


def RunCliCommand(command):
    try:
        return subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=CLI_COMMAND_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        WriteLog(
            "CLI command timed out after {} seconds: {}".format(
                CLI_COMMAND_TIMEOUT_SECONDS,
                error,
            ),
            "ERROR",
        )
        return subprocess.CompletedProcess(command, 1, "", str(error))
    except OSError as error:
        WriteLog("Failed to run CLI command: {}".format(error), "ERROR")
        raise


def CheckCliPath(cli_path):
    if os.path.exists(cli_path):
        return True
    WriteLog("CLI file was not found: {}".format(cli_path), "ERROR")
    return False


def BuildCliCommand(args, mode, root_key=None, extra_arguments=None):
    command = [
        sys.executable,
        args.cli_path,
        mode,
        "--state-file",
        args.state_file,
    ]
    if root_key is not None:
        command.extend(["--rootkey", root_key])
    if extra_arguments:
        command.extend(extra_arguments)
    return command


def ParseJsonOutput(result, context):
    try:
        return json.loads(result.stdout)
    except ValueError as error:
        WriteLog("{} stdout is not valid JSON: {}".format(context, error), "ERROR")
        WriteLog("{} stdout: {}".format(context, result.stdout.strip()), "ERROR")
        return None


def LogFailedCliResult(context, result):
    WriteLog("{} failed with code {}".format(context, result.returncode), "ERROR")
    WriteLog("{} stderr: {}".format(context, result.stderr.strip()), "ERROR")
    WriteLog("{} stdout: {}".format(context, result.stdout.strip()), "ERROR")


def LoadAlertPackages(args):
    result = RunCliCommand(BuildCliCommand(args, "select", extra_arguments=["--path", "$"]))
    if result.returncode != 0:
        LogFailedCliResult("CLI select", result)
        return None
    package_list = ParseJsonOutput(result, "CLI select")
    if not isinstance(package_list, list):
        WriteLog("CLI select root result is not a list", "ERROR")
        return None
    return package_list


def BuildExpectedSnapshot(package):
    return {
        "$.severity": package.get("severity"),
        "$.eventBalance": package.get("eventBalance"),
        "$.criticalEvent": package.get("criticalEvent"),
        "$.zeroRecaveryBalance": package.get("zeroRecaveryBalance"),
        "$.stepOrder": package.get("stepOrder"),
        "$.steps": package.get("steps"),
    }


def PatchPackage(args, original_package, updated_package):
    root_key = original_package["rootKey"]
    payload = {
        "expect": BuildExpectedSnapshot(original_package),
        "set": {
            "$.stepOrder": updated_package["stepOrder"],
            "$.steps": updated_package["steps"],
        },
    }
    result = RunCliCommand(
        BuildCliCommand(
            args,
            "patch",
            root_key=root_key,
            extra_arguments=["--patch-json", json.dumps(payload, ensure_ascii=False)],
        )
    )
    if result.returncode != 0:
        LogFailedCliResult("CLI patch for root key {}".format(root_key), result)
        return None
    response = ParseJsonOutput(result, "CLI patch for root key {}".format(root_key))
    if not isinstance(response, dict):
        return None
    return response


def DeletePackage(args, package):
    root_key = package["rootKey"]
    expected = BuildExpectedSnapshot(package)
    result = RunCliCommand(
        BuildCliCommand(
            args,
            "del",
            root_key=root_key,
            extra_arguments=["--expect-json", json.dumps(expected, ensure_ascii=False)],
        )
    )
    if result.returncode != 0:
        LogFailedCliResult("CLI del for root key {}".format(root_key), result)
        return None
    response = ParseJsonOutput(result, "CLI del for root key {}".format(root_key))
    if not isinstance(response, dict):
        return None
    return response


############################### BUSINESS VALIDATION ###############################


def RequireType(dictionary, key, expected_type, root_key, step_name):
    if key not in dictionary or not isinstance(dictionary.get(key), expected_type):
        raise ValueError(
            "Invalid {} for step {} root key {}".format(key, step_name, root_key)
        )


def ValidateStepSpecificFields(step_data, root_key):
    step_name = step_data.get("stepName")
    if step_name == "resolveInsightId":
        RequireType(step_data, "insightId", str, root_key, step_name)
    elif step_name == "loadInsightData":
        if int(step_data.get("isActiv", 0)) not in (0, 1):
            raise ValueError("Invalid isActiv for step {} root key {}".format(step_name, root_key))
        for field in ("fullName", "functionObjectKey", "jiraIncidentTypeKey"):
            RequireType(step_data, field, str, root_key, step_name)
        RequireType(step_data, "recipientADUserList", list, root_key, step_name)
    elif step_name == "resolveKTalkUsers":
        for field in ("recipientList", "notFoundADUserList", "withoutMentionIdList"):
            RequireType(step_data, field, list, root_key, step_name)
    elif step_name in ("sendLowSeverityRootMessage", "sendCriticalRootMessage"):
        for field in ("messageAttributes", "messageID", "messageDeliveryTime"):
            RequireType(step_data, field, str, root_key, step_name)
        if int(step_data.get("sended", 0)) not in (0, 1):
            raise ValueError("Invalid sended for step {} root key {}".format(step_name, root_key))
    elif step_name in ("inviteKTalkUsers", "mentionKTalkUsers"):
        if int(step_data.get("sended", 0)) not in (0, 1):
            raise ValueError("Invalid sended for step {} root key {}".format(step_name, root_key))
    elif step_name in ("sendLowSeverityAggregateMessage", "sendCriticalAggregateMessage"):
        for field in (
            "targetEventBalance",
            "deliveredEventBalance",
            "repeatNumber",
            "repeatLimit",
            "successfulDeliveryNumber",
        ):
            if not isinstance(step_data.get(field), int) or step_data.get(field) < 0:
                raise ValueError("Invalid {} for step {} root key {}".format(field, step_name, root_key))
        for field in (
            "messageAttributes",
            "lastMessageID",
            "lastMessageDeliveryTime",
            "nextDeliveryTime",
        ):
            RequireType(step_data, field, str, root_key, step_name)
        if int(step_data.get("sended", 0)) not in (0, 1):
            raise ValueError("Invalid sended for step {} root key {}".format(step_name, root_key))
    elif step_name in ("createLowSeverityJiraIncident", "createCriticalJiraIncident"):
        for field in ("jiraKey", "jiraUrl"):
            RequireType(step_data, field, str, root_key, step_name)


def ValidatePackageForWatcher(package):
    if not isinstance(package, dict):
        raise ValueError("Package is not a dictionary")
    root_key = package.get("rootKey")
    if not isinstance(root_key, str) or not root_key.strip():
        raise ValueError("Package misses rootKey")
    step_order = package.get("stepOrder")
    steps = package.get("steps")
    if not isinstance(step_order, list):
        raise ValueError("stepOrder is not a list for root key {}".format(root_key))
    if not isinstance(steps, dict):
        raise ValueError("steps is not a dictionary for root key {}".format(root_key))
    if len(step_order) != len(set(step_order)):
        raise ValueError("stepOrder contains duplicates for root key {}".format(root_key))
    for step_name in step_order:
        if step_name not in steps:
            raise ValueError("stepOrder references missing step {} for root key {}".format(step_name, root_key))
    for step_key, step_data in steps.items():
        if not isinstance(step_data, dict):
            raise ValueError("Step {} is not a dictionary for root key {}".format(step_key, root_key))
        if step_data.get("stepName") != step_key:
            raise ValueError("Step key does not match stepName for root key {}".format(root_key))
        if not isinstance(step_data.get("moduleName"), str) or not step_data.get("moduleName"):
            raise ValueError("Invalid moduleName for step {} root key {}".format(step_key, root_key))
        if int(step_data.get("stepState", 0)) not in (0, 1, 2):
            raise ValueError("Invalid stepState for step {} root key {}".format(step_key, root_key))
        if int(step_data.get("retryNumber", 0)) < 0:
            raise ValueError("Invalid retryNumber for step {} root key {}".format(step_key, root_key))
        ValidateStepSpecificFields(step_data, root_key)


############################### STEP CONTROL ###############################


def MakeStepByName(step_name, package):
    if step_name not in STEP_TEMPLATES:
        raise ValueError("Step template key was not found: {}".format(step_name))
    step_data = copy.deepcopy(STEP_TEMPLATES[step_name])
    if step_name in ("sendLowSeverityAggregateMessage", "sendCriticalAggregateMessage"):
        event_balance = int(package.get("eventBalance", 1))
        step_data["targetEventBalance"] = event_balance
        step_data["deliveredEventBalance"] = 1
        step_data["repeatNumber"] = 0
        step_data["successfulDeliveryNumber"] = 0
        step_data["repeatLimit"] = KTALK_AGGREGATE_MESSAGE_REPEAT_COUNT
        step_data["stepState"] = 1 if event_balance == 1 else 0
    return step_data


def GetStepStage(package):
    load_insight_data = package.get("steps", {}).get("loadInsightData")
    if not isinstance(load_insight_data, dict):
        return "insight_check"
    if int(load_insight_data.get("stepState", 0)) != 1:
        return "insight_check"
    if int(load_insight_data.get("isActiv", 0)) == 1:
        return "active_service"
    return "inactive_service"


def GetRequiredStepKeys(package):
    required = list(BASE_STEPS)
    if GetStepStage(package) == "active_service":
        severity_key = str(package.get("severity"))
        if severity_key not in SEVERITY_STEPS:
            raise ValueError("Unknown severity: {}".format(severity_key))
        for step_name in SEVERITY_STEPS[severity_key]:
            if step_name not in required:
                required.append(step_name)
    return required


def IsLowSeverityRoute(package):
    low_steps = {
        "createLowSeverityJiraIncident",
        "sendLowSeverityRootMessage",
        "sendLowSeverityAggregateMessage",
    }
    return any(
        step_name in package.get("stepOrder", []) or step_name in package.get("steps", {})
        for step_name in low_steps
    )


def AddStepsToPackage(package, required_step_keys, reset_existing=False):
    added = []
    if reset_existing:
        package["stepOrder"] = list(required_step_keys)
        for step_name in required_step_keys:
            package["steps"][step_name] = MakeStepByName(step_name, package)
            added.append(step_name)
        return added
    for step_name in required_step_keys:
        if step_name not in package["steps"]:
            package["steps"][step_name] = MakeStepByName(step_name, package)
            added.append(step_name)
        if step_name not in package["stepOrder"]:
            package["stepOrder"].append(step_name)
    return added


def ApplyRequiredSteps(package):
    required = GetRequiredStepKeys(package)
    critical_route = list(BASE_STEPS) + list(SEVERITY_STEPS["5"])
    severity_escalated = (
        str(package.get("severity")) == "5"
        and package.get("stepOrder") != critical_route
        and IsLowSeverityRoute(package)
    )
    before_order = copy.deepcopy(package["stepOrder"])
    if severity_escalated:
        required = critical_route
        added = AddStepsToPackage(package, required, reset_existing=True)
    else:
        added = AddStepsToPackage(package, required, reset_existing=False)
    route_changed = before_order != package["stepOrder"]
    return {
        "added": added,
        "required": required,
        "stage": GetStepStage(package),
        "routeChanged": route_changed,
        "severityEscalatedToCritical": severity_escalated,
    }


def ResetAggregateStepForBalanceIfNeeded(package):
    severity = str(package.get("severity"))
    if severity == "5" and "sendCriticalAggregateMessage" in package.get("stepOrder", []):
        aggregate_step_name = "sendCriticalAggregateMessage"
    else:
        aggregate_step_name = "sendLowSeverityAggregateMessage"
    aggregate_step = package.get("steps", {}).get(aggregate_step_name)
    if not isinstance(aggregate_step, dict):
        return False
    event_balance = int(package.get("eventBalance", 0))
    if int(aggregate_step.get("targetEventBalance", -1)) == event_balance:
        return False
    aggregate_step.update(
        {
            "stepState": 0,
            "errorMessage": "",
            "retryNumber": 0,
            "targetEventBalance": event_balance,
            "repeatNumber": 0,
            "repeatLimit": KTALK_AGGREGATE_MESSAGE_REPEAT_COUNT,
            "successfulDeliveryNumber": 0,
            "messageAttributes": "",
            "lastMessageID": "",
            "lastMessageDeliveryTime": "",
            "nextDeliveryTime": "",
            "sended": 0,
        }
    )
    return True


############################### DELETE CONTROL ###############################


def CheckTimeRange(check_time, start_value, end_value):
    if start_value is None and end_value is None:
        return True
    start_time = datetime.datetime.strptime(start_value, "%H:%M").time() if start_value else None
    end_time = datetime.datetime.strptime(end_value, "%H:%M").time() if end_value else None
    if start_time is not None and end_time is None:
        return check_time >= start_time
    if start_time is None and end_time is not None:
        return check_time < end_time
    if start_time <= end_time:
        return start_time <= check_time < end_time
    return check_time >= start_time or check_time < end_time


def GetDeleteDelayMinutes(zero_balance_datetime):
    delays = []
    for rule in DELETE_DELAY_RULES:
        weekdays = rule.get("weekdays")
        if weekdays is not None and zero_balance_datetime.weekday() not in weekdays:
            continue
        if CheckTimeRange(
            zero_balance_datetime.time(),
            rule.get("start_time"),
            rule.get("end_time"),
        ):
            delays.append(rule.get("delay_minutes", DEFAULT_DELETE_DELAY_MINUTES))
    return max(delays) if delays else DEFAULT_DELETE_DELAY_MINUTES


def FindActiveCriticalEventId(package):
    critical_events = package.get("criticalEvent")
    if not isinstance(critical_events, dict):
        return "<invalid>"
    for event_id, event_data in critical_events.items():
        if not isinstance(event_data, dict):
            return str(event_id)
        if str(event_data.get("endTime", "")).strip() == "":
            return str(event_id)
    return None


def GetDeleteReadiness(package, now=None):
    steps = package["steps"]
    for step_name in package["stepOrder"]:
        step_data = steps.get(step_name)
        if not isinstance(step_data, dict):
            return False, "step {} has invalid structure".format(step_name)
        step_state = int(step_data.get("stepState", 0))
        if step_state != 1:
            return False, "step {} has stepState {}".format(step_name, step_state)
    if int(package.get("eventBalance", 0)) != 0:
        return False, "eventBalance is not zero"
    active_critical_event_id = FindActiveCriticalEventId(package)
    if active_critical_event_id is not None:
        return False, "criticalEvent contains active event {}".format(active_critical_event_id)
    zero_balance_value = package.get("zeroRecaveryBalance")
    if not isinstance(zero_balance_value, str) or not zero_balance_value.strip():
        return False, "zeroRecaveryBalance is empty"
    try:
        zero_balance_datetime = datetime.datetime.strptime(zero_balance_value, DATETIME_FORMAT)
    except ValueError:
        return False, "zeroRecaveryBalance has invalid format"
    check_time = now or datetime.datetime.now()
    delay_minutes = GetDeleteDelayMinutes(zero_balance_datetime)
    age_minutes = int((check_time - zero_balance_datetime).total_seconds() / 60)
    if age_minutes < delay_minutes:
        return False, "package age {}m is less than delete delay {}m".format(age_minutes, delay_minutes)
    return True, ""


############################### PROCESSING ###############################


def ProcessPackage(args, original_package, counters):
    root_key = original_package.get("rootKey", "<unknown>") if isinstance(original_package, dict) else "<unknown>"
    counters["processed"] += 1
    WriteLog("Processing root key: {}".format(root_key), "INFO")
    try:
        ValidatePackageForWatcher(original_package)
        updated_package = copy.deepcopy(original_package)
        route_result = ApplyRequiredSteps(updated_package)
        aggregate_reset = ResetAggregateStepForBalanceIfNeeded(updated_package)
        changed = (
            updated_package["stepOrder"] != original_package["stepOrder"]
            or updated_package["steps"] != original_package["steps"]
        )
        WriteLog(
            "Root key {} stage={}, severity={}, added={}, routeChanged={}, criticalEscalation={}, aggregateReset={}".format(
                root_key,
                route_result["stage"],
                updated_package.get("severity"),
                ", ".join(route_result["added"]),
                route_result["routeChanged"],
                route_result["severityEscalatedToCritical"],
                aggregate_reset,
            ),
            "INFO",
        )
        if changed:
            response = PatchPackage(args, original_package, updated_package)
            if response is None:
                counters["errors"] += 1
                return
            if response.get("conflict") is True:
                counters["conflicts"] += 1
                WriteLog("Patch conflict for root key {}: {}".format(root_key, response.get("reason", "")), "WARNING")
                return
            if response.get("updated") is not True:
                counters["errors"] += 1
                WriteLog("CLI did not update root key {}".format(root_key), "ERROR")
                return
            counters["steps_added"] += len(route_result["added"])
            counters["packages_updated"] += 1

        ready, reason = GetDeleteReadiness(updated_package)
        if not ready:
            counters["skipped"] += 1
            WriteLog("Root key {} was not deleted: {}".format(root_key, reason), "INFO")
            return

        response = DeletePackage(args, updated_package)
        if response is None:
            counters["errors"] += 1
            return
        if response.get("conflict") is True:
            counters["conflicts"] += 1
            WriteLog("Delete conflict for root key {}: {}".format(root_key, response.get("reason", "")), "WARNING")
            return
        if response.get("deleted") is True:
            counters["deleted"] += 1
            WriteLog("Deleted root key {}".format(root_key), "INFO")
        else:
            counters["skipped"] += 1
            WriteLog("Root key {} was not deleted: {}".format(root_key, response.get("reason", "")), "INFO")
    except Exception as error:
        counters["errors"] += 1
        WriteLog("Failed to process root key {}: {}".format(root_key, error), "ERROR")


def ProcessAlertPackages(args, package_list):
    counters = {
        "processed": 0,
        "steps_added": 0,
        "packages_updated": 0,
        "deleted": 0,
        "skipped": 0,
        "conflicts": 0,
        "errors": 0,
    }
    for package in package_list:
        ProcessPackage(args, package, counters)
    return counters


def Main():
    global VERBOSE
    args = GetArgs()
    VERBOSE = args.verbose
    if not CheckCliPath(args.cli_path):
        return 1
    package_list = LoadAlertPackages(args)
    if package_list is None:
        return 1
    counters = ProcessAlertPackages(args, package_list)
    WriteLog("Processed packages: {}".format(counters["processed"]), "INFO")
    WriteLog("Packages updated: {}".format(counters["packages_updated"]), "INFO")
    WriteLog("Steps added: {}".format(counters["steps_added"]), "INFO")
    WriteLog("Deleted packages: {}".format(counters["deleted"]), "INFO")
    WriteLog("Conflicts: {}".format(counters["conflicts"]), "INFO")
    WriteLog("Errors: {}".format(counters["errors"]), "INFO")
    return 1 if counters["errors"] > 0 else 0


if __name__ == "__main__":
    sys.exit(Main())
