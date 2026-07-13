#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import copy
import datetime
import fcntl
import importlib
import importlib.util
import json
import os
import re
import signal
import sys
import tempfile
import time
import traceback
import warnings
from contextlib import contextmanager

warnings.filterwarnings("ignore", category=DeprecationWarning)
if importlib.util.find_spec("urllib3") is not None:
    urllib3 = importlib.import_module("urllib3")
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from config import local_settings_and_secrets as settings
except ImportError:
    class settings:
        pass

try:
    from config.secret_masking import MaskSensitiveText
except ImportError:
    def MaskSensitiveText(value):
        return str(value)[:2000]

STATE_FILE = getattr(settings, "STATE_FILE", "/tmp/alerts.json")
STATE_LOCK_TIMEOUT = float(getattr(settings, "STATE_LOCK_TIMEOUT_SECONDS", 30))
STATE_LOCK_RETRY = float(getattr(settings, "STATE_LOCK_RETRY_INTERVAL_SECONDS", 0.01))
RUN_LOCK_FILE = getattr(settings, "WATCHER_PROCESS_LOCK_FILE", "/tmp/alerter_watcher.lock")
RUN_LOCK_TIMEOUT = float(getattr(settings, "WATCHER_PROCESS_LOCK_TIMEOUT_SECONDS", 10))
RUN_LOCK_RETRY = float(getattr(settings, "WATCHER_PROCESS_LOCK_RETRY_INTERVAL_SECONDS", 0.2))
MAX_RUNTIME = int(getattr(settings, "WATCHER_MAX_RUNTIME_SECONDS", 30))
MAX_STEPS = int(getattr(settings, "WATCHER_MAX_STEPS_PER_RUN", 100))
LOG_FILE = getattr(settings, "WATCHER_LOG_FILE", "/tmp/watcher.log")
LOG_MAX = int(getattr(settings, "LOG_MAX_SIZE_BYTES", 104857600))
LOG_KEEP = int(getattr(settings, "LOG_KEEP_SIZE_BYTES", 83886080))
AGGREGATE_REPEAT = int(getattr(settings, "KTALK_AGGREGATE_MESSAGE_REPEAT_COUNT", 3))
DAY_DELETE_DELAY = int(getattr(settings, "DAY_DELETE_DELAY_MINUTES", 30))
NIGHT_DELETE_DELAY = int(getattr(settings, "NIGHT_DELETE_DELAY_MINUTES", 180))
TIME_FORMAT = "%Y.%m.%d %H:%M:%S"
GROUP_PATTERN = r"SG/([^,/]+)"
VERBOSE = False

BASE_STEPS = ["resolveInsightId", "loadInsightData"]
LOW_STEPS = ["resolveKTalkUsers", "createLowSeverityJiraIncident", "sendLowSeverityRootMessage", "inviteKTalkUsers", "mentionKTalkUsers", "sendLowSeverityAggregateMessage"]
CRITICAL_STEPS = ["resolveKTalkUsers", "createCriticalJiraIncident", "sendCriticalRootMessage", "inviteKTalkUsers", "mentionKTalkUsers", "sendCriticalAggregateMessage"]
MANDATORY_STEPS = set(BASE_STEPS + LOW_STEPS[:-1] + CRITICAL_STEPS[:-1])

STEP_TEMPLATES = {
    "resolveInsightId": {"stepName": "resolveInsightId", "moduleName": "InsightID", "stepState": 0, "errorMessage": "", "retryNumber": 0, "insightId": ""},
    "loadInsightData": {"stepName": "loadInsightData", "moduleName": "InsightData", "stepState": 0, "errorMessage": "", "retryNumber": 0, "isActiv": 0, "fullName": "", "functionObjectKey": "", "jiraIncidentTypeKey": "", "recipientADUserList": []},
    "resolveKTalkUsers": {"stepName": "resolveKTalkUsers", "moduleName": "KTalkUsers", "stepState": 0, "errorMessage": "", "retryNumber": 0, "recipientList": [], "notFoundADUserList": [], "withoutMentionIdList": []},
    "createLowSeverityJiraIncident": {"stepName": "createLowSeverityJiraIncident", "moduleName": "JiraINC", "stepState": 0, "errorMessage": "", "retryNumber": 0, "jiraKey": "", "jiraUrl": ""},
    "createCriticalJiraIncident": {"stepName": "createCriticalJiraIncident", "moduleName": "JiraINC", "stepState": 0, "errorMessage": "", "retryNumber": 0, "jiraKey": "", "jiraUrl": ""},
    "sendLowSeverityRootMessage": {"stepName": "sendLowSeverityRootMessage", "moduleName": "KTalkMessage", "stepState": 0, "errorMessage": "", "retryNumber": 0, "messageAttributes": "", "messageID": "", "messageDeliveryTime": "", "sended": 0},
    "sendCriticalRootMessage": {"stepName": "sendCriticalRootMessage", "moduleName": "KTalkMessage", "stepState": 0, "errorMessage": "", "retryNumber": 0, "messageAttributes": "", "messageID": "", "messageDeliveryTime": "", "sended": 0},
    "inviteKTalkUsers": {"stepName": "inviteKTalkUsers", "moduleName": "KTalkMessage", "stepState": 0, "errorMessage": "", "retryNumber": 0, "sended": 0},
    "mentionKTalkUsers": {"stepName": "mentionKTalkUsers", "moduleName": "KTalkMessage", "stepState": 0, "errorMessage": "", "retryNumber": 0, "sended": 0},
    "sendLowSeverityAggregateMessage": {"stepName": "sendLowSeverityAggregateMessage", "moduleName": "KTalkMessage", "stepState": 1, "errorMessage": "", "retryNumber": 0, "targetEventBalance": 1, "deliveredEventBalance": 1, "repeatNumber": 0, "repeatLimit": AGGREGATE_REPEAT, "successfulDeliveryNumber": 0, "messageAttributes": "", "lastMessageID": "", "lastMessageDeliveryTime": "", "nextDeliveryTime": "", "sended": 0},
    "sendCriticalAggregateMessage": {"stepName": "sendCriticalAggregateMessage", "moduleName": "KTalkMessage", "stepState": 1, "errorMessage": "", "retryNumber": 0, "targetEventBalance": 1, "deliveredEventBalance": 1, "repeatNumber": 0, "repeatLimit": AGGREGATE_REPEAT, "successfulDeliveryNumber": 0, "messageAttributes": "", "lastMessageID": "", "lastMessageDeliveryTime": "", "nextDeliveryTime": "", "sended": 0},
}


def args_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("add", "run", "watch", "select", "update", "del"))
    parser.add_argument("--state-file")
    parser.add_argument("--lock-file")
    parser.add_argument("--lock-timeout", type=float, default=STATE_LOCK_TIMEOUT)
    parser.add_argument("--rootkey")
    parser.add_argument("--path", default="$")
    parser.add_argument("--data")
    parser.add_argument("--json-data")
    parser.add_argument("--event")
    parser.add_argument("--groups")
    parser.add_argument("--triggerTime", dest="trigger_time")
    parser.add_argument("--eventRecoveryTime", dest="recovery_time")
    parser.add_argument("--trigName", dest="trig_name")
    parser.add_argument("--message")
    parser.add_argument("--severity")
    parser.add_argument("--eventid")
    parser.add_argument("--tags", default="")
    parser.add_argument("--max-steps", type=int, default=MAX_STEPS)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    if args.state_file is None:
        args.state_file = "alerts.json" if args.mode == "run" else STATE_FILE
    return args


def log(message, level="INFO", component="watcher"):
    line = "{} [{}] {}: {}".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), level, component, MaskSensitiveText(message))
    try:
        if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) >= LOG_MAX:
            with open(LOG_FILE, "rb") as source:
                source.seek(-min(LOG_KEEP, os.path.getsize(LOG_FILE)), os.SEEK_END)
                data = source.read()
            data = data[data.find(b"\n") + 1:] if b"\n" in data else data
            with open(LOG_FILE, "wb") as target:
                target.write(data)
        with open(LOG_FILE, "a", encoding="utf-8") as target:
            target.write(line + "\n")
    except Exception:
        pass
    if VERBOSE:
        print(line, file=sys.stderr)


def acquire_lock(path, timeout, retry):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    lock = open(path, "a+", encoding="utf-8")
    deadline = time.monotonic() + timeout
    while True:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return lock
        except BlockingIOError:
            if time.monotonic() >= deadline:
                lock.close()
                raise TimeoutError("Timed out waiting for lock {}".format(path))
            time.sleep(retry)


def release_lock(lock):
    if lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_UN)
        finally:
            lock.close()


def load_state(path):
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return []
    try:
        with open(path, "r", encoding="utf-8") as source:
            state = json.load(source)
        if not isinstance(state, list):
            raise ValueError("JSON root is not a list")
        return state
    except (OSError, ValueError) as error:
        backup = path + ".back"
        if os.path.exists(backup):
            os.remove(backup)
        if os.path.exists(path):
            os.replace(path, backup)
        log("Invalid state moved to {}: {}".format(backup, error), "ERROR")
        return []


def save_state(path, state):
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=directory, delete=False) as target:
            temp_path = target.name
            json.dump(state, target, ensure_ascii=False, separators=(",", ":"))
            target.write("\n")
            target.flush()
            os.fsync(target.fileno())
        os.replace(temp_path, path)
        temp_path = None
    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)


@contextmanager
def locked_state(args):
    lock = acquire_lock(args.lock_file or args.state_file + ".lock", args.lock_timeout, STATE_LOCK_RETRY)
    try:
        yield load_state(args.state_file)
    finally:
        release_lock(lock)


def find_package(state, root_key):
    for package in state:
        if isinstance(package, dict) and package.get("rootKey") == root_key:
            return package
    return None


def find_package_index(state, root_key):
    for index, package in enumerate(state):
        if isinstance(package, dict) and package.get("rootKey") == root_key:
            return index
    return None


def path_parts(path):
    if path == "$":
        return []
    if not path.startswith("$."):
        raise ValueError("Path must start with $ or $.")
    parts = path[2:].split(".")
    if any(not part for part in parts):
        raise ValueError("Path contains an empty key")
    return parts


def get_path(root, path):
    value = root
    for part in path_parts(path):
        if not isinstance(value, dict) or part not in value:
            raise ValueError("Path key was not found: {}".format(part))
        value = value[part]
    return value


def set_path(root, path, value):
    parts = path_parts(path)
    if not parts:
        raise ValueError("Update path must point inside package")
    parent = root
    for part in parts[:-1]:
        if not isinstance(parent, dict) or part not in parent:
            raise ValueError("Path key was not found: {}".format(part))
        parent = parent[part]
    if not isinstance(parent, dict):
        raise ValueError("Path parent is not a dictionary")
    parent[parts[-1]] = value


def require(value, name):
    if value is None or value == "":
        raise ValueError("Required argument is missing: {}".format(name))


def integer(value, name):
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ValueError("Invalid integer {}: {}".format(name, value))


def cli_value(args):
    if args.json_data is not None:
        return json.loads(args.json_data)
    if args.data is not None:
        return args.data
    raise ValueError("Required argument is missing: --data or --json-data")


def root_keys(groups):
    result = []
    for value in re.findall(GROUP_PATTERN, groups or ""):
        value = value.strip()
        if value and value not in result:
            result.append(value)
    return result


def new_package(args, root_key):
    return {"rootKey": root_key, "event": "1", "groups": args.groups, "triggerTime": args.trigger_time, "trigName": args.trig_name, "tags": args.tags or "", "message": args.message, "severity": str(args.severity), "eventBalance": 1, "criticalEvent": {}, "zeroRecaveryBalance": "", "stepOrder": [], "steps": {}}


def apply_event(state, args, root_key):
    event = integer(args.event, "event")
    severity = integer(args.severity, "severity")
    package = find_package(state, root_key)
    if event == 1 and package is None:
        package = new_package(args, root_key)
        if severity == 5:
            package["criticalEvent"][str(args.eventid)] = {"startTime": args.trigger_time, "endTime": ""}
        state.append(package)
        return "created"
    if package is None:
        return "not_found"
    balance = max(0, integer(package.get("eventBalance", 0), "eventBalance"))
    if event == 1:
        if severity == 5:
            critical = package.setdefault("criticalEvent", {})
            if str(args.eventid) in critical:
                return "unchanged"
            critical[str(args.eventid)] = {"startTime": args.trigger_time, "endTime": ""}
        package["eventBalance"] = balance + 1
        package["event"] = "1"
        package["zeroRecaveryBalance"] = ""
        if severity > integer(package.get("severity", 0), "severity"):
            package["severity"] = str(severity)
        return "updated"
    if severity == 5:
        event_data = package.setdefault("criticalEvent", {}).get(str(args.eventid))
        if not isinstance(event_data, dict) or str(event_data.get("endTime", "")).strip():
            return "unchanged"
        event_data["endTime"] = args.recovery_time or args.trigger_time
    elif balance == 0:
        return "unchanged"
    package["eventBalance"] = max(0, balance - 1)
    package["event"] = "0" if package["eventBalance"] == 0 else "1"
    if package["eventBalance"] == 0:
        package["zeroRecaveryBalance"] = args.recovery_time or args.trigger_time
    return "updated"


def make_step(name, balance):
    step = copy.deepcopy(STEP_TEMPLATES[name])
    if name in ("sendLowSeverityAggregateMessage", "sendCriticalAggregateMessage"):
        step["targetEventBalance"] = balance
        step["stepState"] = 1 if balance == 1 else 0
    return step


def service_active(steps):
    step = steps.get("loadInsightData")
    return isinstance(step, dict) and integer(step.get("stepState", 0), "stepState") == 1 and integer(step.get("isActiv", 0), "isActiv") == 1


def reconcile_package(package):
    order = list(package.get("stepOrder")) if isinstance(package.get("stepOrder"), list) else []
    steps = copy.deepcopy(package.get("steps")) if isinstance(package.get("steps"), dict) else {}
    old_order, old_steps = package.get("stepOrder"), package.get("steps")
    balance = max(0, integer(package.get("eventBalance", 0), "eventBalance"))
    severity = str(package.get("severity", "0"))
    required = list(BASE_STEPS)
    if service_active(steps):
        required += CRITICAL_STEPS if severity == "5" else LOW_STEPS if severity in ("1", "2", "3", "4") else []
    low_route = any(name in order or name in steps for name in ("createLowSeverityJiraIncident", "sendLowSeverityRootMessage", "sendLowSeverityAggregateMessage"))
    if severity == "5" and low_route:
        steps = {name: copy.deepcopy(steps.get(name)) if isinstance(steps.get(name), dict) else make_step(name, balance) for name in BASE_STEPS}
        order = list(BASE_STEPS)
        for name in CRITICAL_STEPS:
            steps[name] = make_step(name, balance)
            order.append(name)
    else:
        for name in required:
            if not isinstance(steps.get(name), dict):
                steps[name] = make_step(name, balance)
            if name not in order:
                order.append(name)
    aggregate = steps.get("sendCriticalAggregateMessage" if severity == "5" else "sendLowSeverityAggregateMessage")
    if isinstance(aggregate, dict) and integer(aggregate.get("targetEventBalance", -1), "targetEventBalance") != balance:
        aggregate.update({"stepState": 0, "errorMessage": "", "retryNumber": 0, "targetEventBalance": balance, "repeatNumber": 0, "repeatLimit": AGGREGATE_REPEAT, "successfulDeliveryNumber": 0, "messageAttributes": "", "lastMessageID": "", "lastMessageDeliveryTime": "", "nextDeliveryTime": "", "sended": 0})
    package["stepOrder"], package["steps"] = order, steps
    return order != old_order or steps != old_steps


def ready_to_delete(package):
    order, steps = package.get("stepOrder"), package.get("steps")
    if not isinstance(order, list) or not isinstance(steps, dict):
        return False
    if any(not isinstance(steps.get(name), dict) or integer(steps[name].get("stepState", 0), "stepState") != 1 for name in order):
        return False
    if integer(package.get("eventBalance", 0), "eventBalance") != 0:
        return False
    critical = package.get("criticalEvent", {})
    if not isinstance(critical, dict) or any(not isinstance(value, dict) or not str(value.get("endTime", "")).strip() for value in critical.values()):
        return False
    try:
        zero_time = datetime.datetime.strptime(package.get("zeroRecaveryBalance", ""), TIME_FORMAT)
    except (TypeError, ValueError):
        return False
    delay = NIGHT_DELETE_DELAY if zero_time.weekday() in (5, 6) or zero_time.time() >= datetime.time(21) or zero_time.time() < datetime.time(9) else DAY_DELETE_DELAY
    return (datetime.datetime.now() - zero_time).total_seconds() >= delay * 60


def reconcile_state(state):
    changed = 0
    for package in state:
        try:
            if isinstance(package, dict) and reconcile_package(package):
                changed += 1
        except Exception as error:
            log("Reconcile failed for {}: {}".format(package.get("rootKey", "<unknown>") if isinstance(package, dict) else "<invalid>", error), "ERROR")
    deleted = []
    for package in list(state):
        try:
            if isinstance(package, dict) and ready_to_delete(package):
                deleted.append(package.get("rootKey", ""))
                state.remove(package)
        except Exception as error:
            log("Delete readiness failed: {}".format(error), "ERROR")
    return changed, deleted


def add_mode(args):
    for value, name in ((args.event, "--event"), (args.groups, "--groups"), (args.trigger_time, "--triggerTime"), (args.trig_name, "--trigName"), (args.message, "--message"), (args.severity, "--severity")):
        require(value, name)
    if integer(args.event, "event") not in (0, 1) or integer(args.severity, "severity") not in range(6):
        raise ValueError("Unsupported event or severity")
    if integer(args.severity, "severity") == 5:
        require(args.eventid, "--eventid")
    keys = root_keys(args.groups)
    if not keys:
        raise ValueError("No groups starting with SG/ were found")
    with locked_state(args) as state:
        result = {key: apply_event(state, args, key) for key in keys}
        _, deleted = reconcile_state(state)
        save_state(args.state_file, state)
    print(json.dumps({"operation": "add", "results": result, "deleted": deleted}, ensure_ascii=False))
    return 0


def watch_mode(args, output=True):
    with locked_state(args) as state:
        changed, deleted = reconcile_state(state)
        if changed or deleted:
            save_state(args.state_file, state)
    if output:
        print(json.dumps({"operation": "watch", "updated": changed, "deleted": deleted}, ensure_ascii=False))
    return 0


def select_mode(args):
    with locked_state(args) as state:
        root = find_package(state, args.rootkey) if args.rootkey else state
        if args.rootkey and root is None:
            raise ValueError("Root key was not found: {}".format(args.rootkey))
        value = get_path(root, args.path)
    print(json.dumps(value, ensure_ascii=False, indent=4))
    return 0


def update_mode(args):
    require(args.rootkey, "--rootkey")
    value = cli_value(args)
    with locked_state(args) as state:
        package = find_package(state, args.rootkey)
        if package is None:
            raise ValueError("Root key was not found: {}".format(args.rootkey))
        set_path(package, args.path, value)
        _, deleted = reconcile_state(state)
        save_state(args.state_file, state)
    print(json.dumps({"operation": "update", "rootKey": args.rootkey, "deleted": deleted}, ensure_ascii=False))
    return 0


def delete_mode(args):
    require(args.rootkey, "--rootkey")
    with locked_state(args) as state:
        index = find_package_index(state, args.rootkey)
        if index is None:
            raise ValueError("Root key was not found: {}".format(args.rootkey))
        del state[index]
        save_state(args.state_file, state)
    print(json.dumps({"operation": "del", "rootKey": args.rootkey}, ensure_ascii=False))
    return 0


def retry_number(step):
    try:
        return int(step.get("retryNumber", 0))
    except (TypeError, ValueError):
        return 0


def resolve_insight_id(root_key, alert_data, step):
    import db
    result, new = db.GetInsightIdByShortName(root_key), step.copy()
    if result.get("success") is True:
        new.update({"stepState": 1, "errorMessage": "", "insightId": result.get("insightId", "")})
        return True, new
    new.update({"stepState": 2, "errorMessage": result.get("errorMessage", "Unknown InsightID error"), "retryNumber": retry_number(step) + 1, "insightId": ""})
    return False, new


def load_insight_data(root_key, alert_data, step):
    import insight
    source = alert_data.get("steps", {}).get("resolveInsightId", {})
    insight_id = str(source.get("insightId", "")).strip() if isinstance(source, dict) else ""
    new = step.copy()
    if source.get("stepState") != 1 or not insight_id:
        new.update({"stepState": 2, "errorMessage": "InsightID step is not completed", "retryNumber": retry_number(step) + 1, "isActiv": 0, "recipientADUserList": []})
        return False, new
    result = insight.GetInsightData(insight_id, lambda message, level: log(message, level, "insight"))
    if result.get("success") is True:
        new.update({"stepState": 1, "errorMessage": "", "isActiv": int(result.get("isActiv", 0)), "fullName": result.get("fullName", ""), "functionObjectKey": result.get("functionObjectKey", ""), "jiraIncidentTypeKey": result.get("jiraIncidentTypeKey", ""), "recipientADUserList": result.get("recipientADUserList", [])})
        return True, new
    new.update({"stepState": 2, "errorMessage": result.get("errorMessage", "Unknown Insight error"), "retryNumber": retry_number(step) + 1, "isActiv": 0, "recipientADUserList": []})
    return False, new


def handlers():
    import jira_inc
    import ktalk_message
    import mktapi
    return {
        ("InsightID", "resolveInsightId"): resolve_insight_id,
        ("InsightData", "loadInsightData"): load_insight_data,
        ("KTalkUsers", "resolveKTalkUsers"): mktapi.ResolveKTalkUsers,
        ("JiraINC", "createLowSeverityJiraIncident"): jira_inc.CreateLowSeverityJiraIncident,
        ("JiraINC", "createCriticalJiraIncident"): jira_inc.CreateCriticalJiraIncident,
        ("KTalkMessage", "sendLowSeverityRootMessage"): ktalk_message.SendLowSeverityRootMessage,
        ("KTalkMessage", "sendCriticalRootMessage"): ktalk_message.SendCriticalRootMessage,
        ("KTalkMessage", "inviteKTalkUsers"): ktalk_message.InviteKTalkUsers,
        ("KTalkMessage", "mentionKTalkUsers"): ktalk_message.MentionKTalkUsers,
        ("KTalkMessage", "sendLowSeverityAggregateMessage"): ktalk_message.SendLowSeverityAggregateMessage,
        ("KTalkMessage", "sendCriticalAggregateMessage"): ktalk_message.SendCriticalAggregateMessage,
    }


def waits(step):
    value = step.get("nextDeliveryTime", "")
    if not value:
        return False
    try:
        return datetime.datetime.now() < datetime.datetime.strptime(value, TIME_FORMAT)
    except ValueError:
        return False


def next_task(args, attempted):
    with locked_state(args) as state:
        changed, deleted = reconcile_state(state)
        if changed or deleted:
            save_state(args.state_file, state)
        for package in state:
            if not isinstance(package, dict) or not isinstance(package.get("stepOrder"), list) or not isinstance(package.get("steps"), dict):
                continue
            for name in package["stepOrder"]:
                step = package["steps"].get(name)
                if not isinstance(step, dict):
                    break
                if integer(step.get("stepState", 0), "stepState") == 1:
                    continue
                key = (package.get("rootKey"), name)
                if key in attempted or waits(step):
                    break
                return copy.deepcopy(package), name, copy.deepcopy(step)
    return None


def execute_task(mapping, package, name, step):
    handler = mapping.get((step.get("moduleName"), name))
    if handler is None:
        new = step.copy()
        new.update({"stepState": 2, "errorMessage": "Handler is missing", "retryNumber": retry_number(step) + 1})
        return False, new
    try:
        success, new = handler(package["rootKey"], package, step)
        if not isinstance(new, dict):
            raise ValueError("Handler returned invalid step")
    except Exception as error:
        log("Step {} failed for {}: {}\n{}".format(name, package.get("rootKey"), error, traceback.format_exc()), "ERROR")
        success, new = False, step.copy()
        new.update({"stepState": 2, "errorMessage": "{}: {}".format(type(error).__name__, MaskSensitiveText(error)), "retryNumber": retry_number(step) + 1})
    new["stepName"], new["moduleName"] = step.get("stepName", name), step.get("moduleName", "")
    if not success and name in MANDATORY_STEPS:
        new["stepState"] = 2
        if retry_number(new) <= retry_number(step):
            new["retryNumber"] = retry_number(step) + 1
    return bool(success), new


def commit_result(args, package_snapshot, name, step_snapshot, new_step):
    with locked_state(args) as state:
        package = find_package(state, package_snapshot["rootKey"])
        if package is None or package.get("steps", {}).get(name) != step_snapshot:
            log("Result discarded because state changed for {}.{}".format(package_snapshot["rootKey"], name), "WARNING")
            return False
        package["steps"][name] = new_step
        reconcile_state(state)
        save_state(args.state_file, state)
        return True


def timeout_handler(signum, frame):
    log("Watcher maximum runtime exceeded", "ERROR")
    os._exit(124)


def run_mode(args):
    if args.max_steps < 1:
        raise ValueError("--max-steps must be positive")
    from config.config_check import ValidateConfig
    ValidateConfig()
    try:
        run_lock = acquire_lock(RUN_LOCK_FILE, RUN_LOCK_TIMEOUT, RUN_LOCK_RETRY)
    except TimeoutError:
        print(json.dumps({"operation": "run", "skipped": True}, ensure_ascii=False))
        return 0
    attempted, processed, succeeded, failed = set(), 0, 0, 0
    try:
        if hasattr(signal, "SIGALRM") and MAX_RUNTIME > 0:
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(MAX_RUNTIME)
        mapping = handlers()
        while processed < args.max_steps:
            task = next_task(args, attempted)
            if task is None:
                break
            package, name, step = task
            attempted.add((package["rootKey"], name))
            success, new_step = execute_task(mapping, package, name, step)
            committed = commit_result(args, package, name, step, new_step)
            processed += 1
            succeeded += int(committed and success)
            failed += int(committed and not success)
        watch_mode(args, output=False)
    finally:
        if hasattr(signal, "SIGALRM"):
            signal.alarm(0)
        release_lock(run_lock)
    print(json.dumps({"operation": "run", "processed": processed, "success": succeeded, "errors": failed}, ensure_ascii=False))
    return 0


def main():
    global VERBOSE
    args = args_parser()
    VERBOSE = args.verbose
    try:
        return {"add": add_mode, "run": run_mode, "watch": watch_mode, "select": select_mode, "update": update_mode, "del": delete_mode}[args.mode](args)
    except Exception as error:
        log("Execution failed: {}".format(error), "ERROR")
        print(MaskSensitiveText(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
