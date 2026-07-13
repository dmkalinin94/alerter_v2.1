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

CLI_PATH_DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "alios.py")
STATE_FILE_DEFAULT = "/tmp/alerts.json"
DATETIME_FORMAT = "%Y.%m.%d %H:%M:%S"
DAY_DELETE_DELAY_MINUTES = 30
NIGHT_DELETE_DELAY_MINUTES = 180
VERBOSE = False

BASE_STEPS = ["resolveInsightId", "loadInsightData"]
LOW_STEPS = [
    "resolveKTalkUsers",
    "createLowSeverityJiraIncident",
    "sendLowSeverityRootMessage",
    "inviteKTalkUsers",
    "mentionKTalkUsers",
    "sendLowSeverityAggregateMessage",
]
CRITICAL_STEPS = [
    "resolveKTalkUsers",
    "createCriticalJiraIncident",
    "sendCriticalRootMessage",
    "inviteKTalkUsers",
    "mentionKTalkUsers",
    "sendCriticalAggregateMessage",
]

STEP_TEMPLATES = {
    "resolveInsightId": {
        "stepName": "resolveInsightId", "moduleName": "InsightID", "stepState": 0,
        "errorMessage": "", "retryNumber": 0, "insightId": "",
    },
    "loadInsightData": {
        "stepName": "loadInsightData", "moduleName": "InsightData", "stepState": 0,
        "errorMessage": "", "retryNumber": 0, "isActiv": 0, "fullName": "",
        "functionObjectKey": "", "jiraIncidentTypeKey": "", "recipientADUserList": [],
    },
    "resolveKTalkUsers": {
        "stepName": "resolveKTalkUsers", "moduleName": "KTalkUsers", "stepState": 0,
        "errorMessage": "", "retryNumber": 0, "recipientList": [],
        "notFoundADUserList": [], "withoutMentionIdList": [],
    },
    "createLowSeverityJiraIncident": {
        "stepName": "createLowSeverityJiraIncident", "moduleName": "JiraINC", "stepState": 0,
        "errorMessage": "", "retryNumber": 0, "jiraKey": "", "jiraUrl": "",
    },
    "createCriticalJiraIncident": {
        "stepName": "createCriticalJiraIncident", "moduleName": "JiraINC", "stepState": 0,
        "errorMessage": "", "retryNumber": 0, "jiraKey": "", "jiraUrl": "",
    },
    "sendLowSeverityRootMessage": {
        "stepName": "sendLowSeverityRootMessage", "moduleName": "KTalkMessage", "stepState": 0,
        "errorMessage": "", "retryNumber": 0, "messageAttributes": "", "messageID": "",
        "messageDeliveryTime": "", "sended": 0,
    },
    "sendCriticalRootMessage": {
        "stepName": "sendCriticalRootMessage", "moduleName": "KTalkMessage", "stepState": 0,
        "errorMessage": "", "retryNumber": 0, "messageAttributes": "", "messageID": "",
        "messageDeliveryTime": "", "sended": 0,
    },
    "inviteKTalkUsers": {
        "stepName": "inviteKTalkUsers", "moduleName": "KTalkMessage", "stepState": 0,
        "errorMessage": "", "retryNumber": 0, "sended": 0,
    },
    "mentionKTalkUsers": {
        "stepName": "mentionKTalkUsers", "moduleName": "KTalkMessage", "stepState": 0,
        "errorMessage": "", "retryNumber": 0, "sended": 0,
    },
    "sendLowSeverityAggregateMessage": {
        "stepName": "sendLowSeverityAggregateMessage", "moduleName": "KTalkMessage", "stepState": 1,
        "errorMessage": "", "retryNumber": 0, "targetEventBalance": 1,
        "deliveredEventBalance": 1, "repeatNumber": 0,
        "repeatLimit": KTALK_AGGREGATE_MESSAGE_REPEAT_COUNT, "successfulDeliveryNumber": 0,
        "messageAttributes": "", "lastMessageID": "", "lastMessageDeliveryTime": "",
        "nextDeliveryTime": "", "sended": 0,
    },
    "sendCriticalAggregateMessage": {
        "stepName": "sendCriticalAggregateMessage", "moduleName": "KTalkMessage", "stepState": 1,
        "errorMessage": "", "retryNumber": 0, "targetEventBalance": 1,
        "deliveredEventBalance": 1, "repeatNumber": 0,
        "repeatLimit": KTALK_AGGREGATE_MESSAGE_REPEAT_COUNT, "successfulDeliveryNumber": 0,
        "messageAttributes": "", "lastMessageID": "", "lastMessageDeliveryTime": "",
        "nextDeliveryTime": "", "sended": 0,
    },
}


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cli-path", default=CLI_PATH_DEFAULT)
    parser.add_argument("--state-file", default=STATE_FILE_DEFAULT)
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args()


def log(message, level="INFO"):
    if level == "INFO" and not VERBOSE:
        return
    print("{} [{}] watcher: {}".format(
        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), level, message
    ))


def run_cli(args, mode, root_key=None, extra=None):
    command = [sys.executable, args.cli_path, mode, "--state-file", args.state_file]
    if root_key:
        command.extend(["--rootkey", root_key])
    if extra:
        command.extend(extra)
    try:
        return subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=CLI_COMMAND_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        log("CLI failed: {}".format(error), "ERROR")
        return None


def load_packages(args):
    result = run_cli(args, "select")
    if result is None or result.returncode != 0:
        log("Cannot read JSON: {}".format(result.stderr.strip() if result else "CLI error"), "ERROR")
        return None
    try:
        data = json.loads(result.stdout)
    except ValueError as error:
        log("CLI returned invalid JSON: {}".format(error), "ERROR")
        return None
    return data if isinstance(data, list) else None


def update_value(args, root_key, path, value):
    result = run_cli(
        args, "update", root_key,
        ["--path", path, "--json-data", json.dumps(value, ensure_ascii=False)],
    )
    if result is None or result.returncode != 0:
        log("Update {} {} failed: {}".format(root_key, path, result.stderr.strip() if result else "CLI error"), "ERROR")
        return False
    return True


def make_step(name, balance):
    step = copy.deepcopy(STEP_TEMPLATES[name])
    if name in ("sendLowSeverityAggregateMessage", "sendCriticalAggregateMessage"):
        step["targetEventBalance"] = balance
        step["stepState"] = 1 if balance == 1 else 0
    return step


def active_service(steps):
    step = steps.get("loadInsightData")
    return isinstance(step, dict) and int(step.get("stepState", 0)) == 1 and int(step.get("isActiv", 0)) == 1


def low_route_exists(order, steps):
    return any(name in order or name in steps for name in (
        "createLowSeverityJiraIncident",
        "sendLowSeverityRootMessage",
        "sendLowSeverityAggregateMessage",
    ))


def build_steps(package):
    order = list(package.get("stepOrder", []))
    steps = copy.deepcopy(package.get("steps", {}))
    if not isinstance(order, list) or not isinstance(steps, dict):
        raise ValueError("steps or stepOrder has invalid type")

    severity = str(package.get("severity", "0"))
    balance = int(package.get("eventBalance", 0))
    required = list(BASE_STEPS)
    if active_service(steps):
        if severity == "5":
            required.extend(CRITICAL_STEPS)
        elif severity in ("1", "2", "3", "4"):
            required.extend(LOW_STEPS)

    if severity == "5" and low_route_exists(order, steps):
        order = required
        steps = {name: make_step(name, balance) for name in required}
    else:
        for name in required:
            if name not in steps:
                steps[name] = make_step(name, balance)
            if name not in order:
                order.append(name)

    aggregate = "sendCriticalAggregateMessage" if severity == "5" else "sendLowSeverityAggregateMessage"
    aggregate_step = steps.get(aggregate)
    if isinstance(aggregate_step, dict) and int(aggregate_step.get("targetEventBalance", -1)) != balance:
        aggregate_step.update({
            "stepState": 0,
            "errorMessage": "",
            "retryNumber": 0,
            "targetEventBalance": balance,
            "repeatNumber": 0,
            "repeatLimit": KTALK_AGGREGATE_MESSAGE_REPEAT_COUNT,
            "successfulDeliveryNumber": 0,
            "messageAttributes": "",
            "lastMessageID": "",
            "lastMessageDeliveryTime": "",
            "nextDeliveryTime": "",
            "sended": 0,
        })
    return order, steps


def delete_delay(value):
    if value.weekday() in (5, 6):
        return NIGHT_DELETE_DELAY_MINUTES
    if value.time() >= datetime.time(21, 0) or value.time() < datetime.time(9, 0):
        return NIGHT_DELETE_DELAY_MINUTES
    return DAY_DELETE_DELAY_MINUTES


def ready_to_delete(package):
    order = package.get("stepOrder", [])
    steps = package.get("steps", {})
    if not isinstance(order, list) or not isinstance(steps, dict):
        return False
    for name in order:
        step = steps.get(name)
        if not isinstance(step, dict) or int(step.get("stepState", 0)) != 1:
            return False
    if int(package.get("eventBalance", 0)) != 0:
        return False
    critical = package.get("criticalEvent", {})
    if not isinstance(critical, dict):
        return False
    if any(not isinstance(item, dict) or not str(item.get("endTime", "")).strip() for item in critical.values()):
        return False
    zero_time = package.get("zeroRecaveryBalance", "")
    try:
        zero_time = datetime.datetime.strptime(zero_time, DATETIME_FORMAT)
    except (TypeError, ValueError):
        return False
    age = (datetime.datetime.now() - zero_time).total_seconds() / 60
    return age >= delete_delay(zero_time)


def process_package(args, package):
    if not isinstance(package, dict) or not package.get("rootKey"):
        log("Skipped package without rootKey", "ERROR")
        return False
    root_key = package["rootKey"]
    try:
        order, steps = build_steps(package)
        if steps != package.get("steps"):
            if not update_value(args, root_key, "$.steps", steps):
                return False
            package["steps"] = steps
        if order != package.get("stepOrder"):
            if not update_value(args, root_key, "$.stepOrder", order):
                return False
            package["stepOrder"] = order
        if ready_to_delete(package):
            result = run_cli(args, "del", root_key)
            if result is None or result.returncode != 0:
                log("Delete {} failed: {}".format(root_key, result.stderr.strip() if result else "CLI error"), "ERROR")
                return False
        return True
    except (TypeError, ValueError) as error:
        log("{}: {}".format(root_key, error), "ERROR")
        return False


def main():
    global VERBOSE
    args = get_args()
    VERBOSE = args.verbose
    if not os.path.exists(args.cli_path):
        log("CLI file was not found: {}".format(args.cli_path), "ERROR")
        return 1
    packages = load_packages(args)
    if packages is None:
        return 1
    errors = sum(1 for package in packages if not process_package(args, package))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
