#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import datetime
import fcntl
import json
import os
import re
import sys
import tempfile
import time

from config.local_settings_and_secrets import LOG_KEEP_SIZE_BYTES, LOG_MAX_SIZE_BYTES


############################### VARS ###############################

STATE_FILE_DEFAULT = "/tmp/alerts.json"
LOG_FILE = "/tmp/alios.log"
LOCK_TIMEOUT_SECONDS_DEFAULT = 30.0
LOCK_RETRY_INTERVAL_SECONDS = 0.01
GROUP_PATTERN = r"SG/([^,/]+)"
VERBOSE = False


############################### ARGS ###############################


def GetArgs():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("add", "select", "update", "patch", "del"))
    parser.add_argument("--event")
    parser.add_argument("--groups")
    parser.add_argument("--triggerTime", dest="trigger_time")
    parser.add_argument("--eventRecoveryTime", dest="event_recovery_time")
    parser.add_argument("--trigName", dest="trig_name")
    parser.add_argument("--message")
    parser.add_argument("--severity")
    parser.add_argument("--eventid")
    parser.add_argument("--state-file", dest="state_file", default=STATE_FILE_DEFAULT)
    parser.add_argument("--lock-file", dest="lock_file")
    parser.add_argument("--lock-timeout", dest="lock_timeout", type=float, default=LOCK_TIMEOUT_SECONDS_DEFAULT)
    parser.add_argument("--path", default="$")
    parser.add_argument("--rootkey", dest="rootkey")
    parser.add_argument("--tags", default="")
    parser.add_argument("--data")
    parser.add_argument("--json-data", dest="json_data")
    parser.add_argument("--patch-json", dest="patch_json")
    parser.add_argument("--expect-json", dest="expect_json")
    parser.add_argument("-l", dest="list_key")
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args()


############################### LOGS ###############################


def TrimLogFileIfNeeded(log_file):
    try:
        if not os.path.exists(log_file) or os.path.getsize(log_file) < LOG_MAX_SIZE_BYTES:
            return
        with open(log_file, "rb") as file:
            if os.path.getsize(log_file) > LOG_KEEP_SIZE_BYTES:
                file.seek(-LOG_KEEP_SIZE_BYTES, os.SEEK_END)
            data = file.read()
        newline_index = data.find(b"\n")
        if newline_index >= 0:
            data = data[newline_index + 1:]
        with open(log_file, "wb") as file:
            file.write(data)
    except Exception as error:
        print("Failed to trim log file {}: {}".format(log_file, error), file=sys.stderr)


def WriteLog(message, level):
    if level == "INFO" and not VERBOSE:
        return
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = "{} [{}] {}".format(now, level, message)
    try:
        TrimLogFileIfNeeded(LOG_FILE)
        with open(LOG_FILE, "a", encoding="utf-8") as file:
            file.write(log_message + "\n")
    except Exception as error:
        print("Failed to write log file {}: {}".format(LOG_FILE, error), file=sys.stderr)
    if VERBOSE:
        print(log_message, file=sys.stderr)


############################### LOCKING ###############################


def GetLockFilePath(args):
    if args.lock_file:
        return args.lock_file
    return args.state_file + ".lock"


def OpenStateFileLock(lock_file_path, timeout_seconds):
    if timeout_seconds < 0:
        raise ValueError("--lock-timeout cannot be negative")
    lock_directory = os.path.dirname(os.path.abspath(lock_file_path))
    if lock_directory and not os.path.exists(lock_directory):
        os.makedirs(lock_directory)
    lock_file = open(lock_file_path, "a+", encoding="utf-8")
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            WriteLog("State lock acquired: {}".format(lock_file_path), "INFO")
            return lock_file
        except BlockingIOError:
            if time.monotonic() >= deadline:
                lock_file.close()
                raise TimeoutError("Timed out waiting for state lock {}".format(lock_file_path))
            time.sleep(LOCK_RETRY_INTERVAL_SECONDS)
        except OSError:
            lock_file.close()
            raise


def CloseStateFileLock(lock_file, lock_file_path):
    if lock_file is None:
        return
    try:
        fcntl.flock(lock_file, fcntl.LOCK_UN)
    finally:
        lock_file.close()
    WriteLog("State lock released: {}".format(lock_file_path), "INFO")


############################### JSON STORAGE ###############################


def RecoverInvalidStateFile(state_file, reason):
    backup_file = state_file + ".back"
    WriteLog("Invalid state JSON detected in {}: {}".format(state_file, reason), "ERROR")
    if os.path.exists(backup_file):
        os.remove(backup_file)
    if os.path.exists(state_file):
        os.replace(state_file, backup_file)
    SaveAlertDictionaryList(state_file, [])
    WriteLog("Invalid state JSON moved to {}".format(backup_file), "ERROR")
    return []


def ValidateAlertDictionaryList(package_list):
    if not isinstance(package_list, list):
        raise ValueError("Invalid state structure: root element must be a list")
    seen_root_keys = set()
    for package in package_list:
        if not isinstance(package, dict):
            raise ValueError("Invalid package structure: each list item must be a dictionary")
        root_key = package.get("rootKey")
        if not isinstance(root_key, str) or not root_key.strip():
            raise ValueError("Invalid rootKey in package")
        if root_key in seen_root_keys:
            raise ValueError("Duplicate rootKey: {}".format(root_key))
        seen_root_keys.add(root_key)
        if not isinstance(package.get("steps"), dict):
            raise ValueError("Invalid steps dictionary for root key {}".format(root_key))
        step_order = package.get("stepOrder")
        if not isinstance(step_order, list):
            raise ValueError("Invalid stepOrder for root key {}".format(root_key))
        if any(not isinstance(step_name, str) or not step_name.strip() for step_name in step_order):
            raise ValueError("Invalid step name in stepOrder for root key {}".format(root_key))
        if len(step_order) != len(set(step_order)):
            raise ValueError("Duplicate step names in stepOrder for root key {}".format(root_key))
        for step_name in step_order:
            if step_name not in package["steps"]:
                raise ValueError("stepOrder references missing step {} for root key {}".format(step_name, root_key))
        if not isinstance(package.get("criticalEvent"), dict):
            raise ValueError("Invalid criticalEvent for root key {}".format(root_key))
        try:
            event_balance = int(package.get("eventBalance", 0))
            severity = int(package.get("severity", 0))
        except (TypeError, ValueError):
            raise ValueError("Invalid numeric package field for root key {}".format(root_key))
        if event_balance < 0:
            raise ValueError("eventBalance is negative for root key {}".format(root_key))
        if severity < 0 or severity > 5:
            raise ValueError("Invalid severity for root key {}".format(root_key))
    return True


def LoadAlertDictionaryList(state_file):
    if not os.path.exists(state_file):
        return []
    try:
        with open(state_file, "r", encoding="utf-8") as file:
            content = file.read()
    except OSError as error:
        WriteLog("Failed to read state file {}: {}".format(state_file, error), "ERROR")
        raise
    if not content.strip():
        return []
    try:
        package_list = json.loads(content)
    except ValueError as error:
        return RecoverInvalidStateFile(state_file, error)
    try:
        ValidateAlertDictionaryList(package_list)
    except ValueError as error:
        return RecoverInvalidStateFile(state_file, error)
    return package_list


def SaveAlertDictionaryList(state_file, package_list):
    ValidateAlertDictionaryList(package_list)
    state_directory = os.path.dirname(os.path.abspath(state_file)) or "."
    if not os.path.exists(state_directory):
        os.makedirs(state_directory)
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=state_directory,
            prefix=os.path.basename(state_file) + ".",
            suffix=".tmp",
            delete=False,
        ) as temp_file:
            temp_path = temp_file.name
            json.dump(package_list, temp_file, ensure_ascii=False, separators=(",", ":"))
            temp_file.write("\n")
            temp_file.flush()
        os.replace(temp_path, state_file)
        temp_path = None
    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)
    WriteLog("State saved to {}".format(state_file), "INFO")


############################### GENERIC JSON HELPERS ###############################


def CheckRequiredValue(value, argument_name):
    if value is None or value == "":
        raise ValueError("Required argument is missing or empty: {}".format(argument_name))


def ParseJsonArgument(value, argument_name):
    CheckRequiredValue(value, argument_name)
    try:
        return json.loads(value)
    except ValueError as error:
        raise ValueError("Invalid JSON in {}: {}".format(argument_name, error))


def FindPackageByRootKey(package_list, root_key):
    for package in package_list:
        if package.get("rootKey") == root_key:
            return package
    return None


def GetPackageByRootKey(package_list, root_key):
    package = FindPackageByRootKey(package_list, root_key)
    if package is None:
        raise ValueError("Root key was not found: {}".format(root_key))
    return package


def GetPathParts(json_path):
    if json_path == "$":
        return []
    if not json_path.startswith("$."):
        raise ValueError("JSON path must start with $ or $.")
    parts = json_path[2:].split(".")
    if any(part == "" for part in parts):
        raise ValueError("JSON path contains an empty part")
    return parts


def GetValueByParts(root_value, path_parts):
    current_value = root_value
    for path_part in path_parts:
        if not isinstance(current_value, dict) or path_part not in current_value:
            raise KeyError(path_part)
        current_value = current_value[path_part]
    return current_value


def SetValueByParts(root_value, path_parts, data):
    if not path_parts:
        raise ValueError("JSON path must point to a package field")
    parent = root_value
    for path_part in path_parts[:-1]:
        if not isinstance(parent, dict) or path_part not in parent:
            raise ValueError("JSON path key was not found: {}".format(path_part))
        parent = parent[path_part]
    if not isinstance(parent, dict):
        raise ValueError("JSON path parent is not a dictionary")
    parent[path_parts[-1]] = data


def GetTopLevelKeyFromPathParts(package_list, path_parts):
    part_count = len(path_parts)
    while part_count > 0:
        possible_root_key = ".".join(path_parts[:part_count])
        if FindPackageByRootKey(package_list, possible_root_key) is not None:
            return possible_root_key, part_count
        part_count -= 1
    raise ValueError("Root key was not found in JSON path")


def GetWildcardValues(current_value):
    if isinstance(current_value, list):
        result = []
        for item in current_value:
            if isinstance(item, dict):
                result.extend(item.values())
            else:
                result.append(item)
        return result
    if isinstance(current_value, dict):
        return list(current_value.values())
    return []


def SelectValueByJsonPath(package_list, json_path):
    if json_path == "$":
        return package_list
    path_parts = GetPathParts(json_path)
    root_key, used_parts = GetTopLevelKeyFromPathParts(package_list, path_parts)
    current_value = GetPackageByRootKey(package_list, root_key)
    for path_part in path_parts[used_parts:]:
        if path_part == "?":
            current_value = GetWildcardValues(current_value)
            continue
        if not isinstance(current_value, dict) or path_part not in current_value:
            raise ValueError("JSON path key was not found: {}".format(path_part))
        current_value = current_value[path_part]
    return current_value


def SelectPackageValue(package, json_path):
    return GetValueByParts(package, GetPathParts(json_path))


def SelectListValuesByKey(package_list, list_key):
    result = {}
    for package in package_list:
        root_key = package["rootKey"]
        if list_key not in package:
            raise ValueError("List key was not found for root key {}: {}".format(root_key, list_key))
        result[root_key] = package[list_key]
    return result


def MatchExpectedValues(package, expected_values):
    if not isinstance(expected_values, dict):
        raise ValueError("expect must be a JSON dictionary")
    for json_path, expected_value in expected_values.items():
        if not isinstance(json_path, str):
            raise ValueError("expect path must be a string")
        try:
            actual_value = SelectPackageValue(package, json_path)
        except KeyError:
            return False, "expected path was not found: {}".format(json_path)
        if actual_value != expected_value:
            return False, "expected value mismatch for {}".format(json_path)
    return True, ""


def MakeOperationResponse(updated=False, deleted=False, conflict=False, reason="", root_key=None):
    response = {
        "updated": bool(updated),
        "deleted": bool(deleted),
        "conflict": bool(conflict),
        "reason": reason,
    }
    if root_key is not None:
        response["rootKey"] = root_key
    return response


############################### EVENT ADD ###############################


def ExtractRootKeysFromGroups(groups):
    result = []
    for match in re.findall(GROUP_PATTERN, groups):
        root_key = match.strip()
        if root_key and root_key not in result:
            result.append(root_key)
    return result


def GetIntegerValue(value, field_name):
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ValueError("Invalid integer value for {}: {}".format(field_name, value))


def CheckAddArgs(args):
    CheckRequiredValue(args.event, "--event")
    CheckRequiredValue(args.groups, "--groups")
    CheckRequiredValue(args.trigger_time, "--triggerTime")
    CheckRequiredValue(args.trig_name, "--trigName")
    CheckRequiredValue(args.message, "--message")
    CheckRequiredValue(args.severity, "--severity")
    if str(args.severity) == "5":
        CheckRequiredValue(args.eventid, "--eventid")


def CreateBasePackage(args, root_key):
    return {
        "rootKey": root_key,
        "event": "1",
        "groups": args.groups,
        "triggerTime": args.trigger_time,
        "trigName": args.trig_name,
        "tags": args.tags or "",
        "message": args.message,
        "severity": str(args.severity),
        "eventBalance": 1,
        "criticalEvent": {},
        "zeroRecaveryBalance": "",
        "stepOrder": [],
        "steps": {},
    }


def IsCriticalEventActive(event_data):
    return isinstance(event_data, dict) and str(event_data.get("endTime", "")).strip() == ""


def GetRecoveryTime(args):
    return args.event_recovery_time if args.event_recovery_time else args.trigger_time


def ApplyEventOne(package_list, root_key, args):
    package = FindPackageByRootKey(package_list, root_key)
    new_severity = GetIntegerValue(args.severity, "severity")
    if package is None:
        package = CreateBasePackage(args, root_key)
        if new_severity == 5:
            package["criticalEvent"][str(args.eventid)] = {
                "startTime": args.trigger_time,
                "endTime": "",
            }
        package_list.append(package)
        return "created"

    old_balance = GetIntegerValue(package.get("eventBalance", 0), "eventBalance")
    old_severity = GetIntegerValue(package.get("severity", 0), "severity")
    if new_severity == 5:
        event_id = str(args.eventid)
        critical_events = package.setdefault("criticalEvent", {})
        if event_id not in critical_events:
            critical_events[event_id] = {"startTime": args.trigger_time, "endTime": ""}
            package["eventBalance"] = old_balance + 1
            package["zeroRecaveryBalance"] = ""
    else:
        package["eventBalance"] = old_balance + 1
        package["zeroRecaveryBalance"] = ""
    if new_severity > old_severity:
        package["severity"] = str(args.severity)
    package["event"] = "1"
    return "updated"


def ApplyEventZero(package_list, root_key, args):
    package = FindPackageByRootKey(package_list, root_key)
    if package is None:
        return "not_found"
    severity = GetIntegerValue(args.severity, "severity")
    old_balance = GetIntegerValue(package.get("eventBalance", 0), "eventBalance")
    if severity == 5:
        event_id = str(args.eventid)
        critical_events = package.setdefault("criticalEvent", {})
        event_data = critical_events.get(event_id)
        if event_data is None or not IsCriticalEventActive(event_data):
            return "unchanged"
        event_data["endTime"] = GetRecoveryTime(args)
        package["eventBalance"] = max(0, old_balance - 1)
    else:
        if old_balance == 0:
            return "unchanged"
        package["eventBalance"] = max(0, old_balance - 1)
    if package["eventBalance"] == 0:
        package["event"] = "0"
        package["zeroRecaveryBalance"] = GetRecoveryTime(args)
    else:
        package["event"] = "1"
    return "updated"


def AddEvent(args):
    CheckAddArgs(args)
    event = GetIntegerValue(args.event, "event")
    severity = GetIntegerValue(args.severity, "severity")
    if event not in (0, 1):
        raise ValueError("Unsupported event value: {}".format(args.event))
    if severity < 0 or severity > 5:
        raise ValueError("Unsupported severity value: {}".format(args.severity))
    root_keys = ExtractRootKeysFromGroups(args.groups)
    if not root_keys:
        raise ValueError("No groups starting with SG/ were found")
    package_list = LoadAlertDictionaryList(args.state_file)
    results = {}
    for root_key in root_keys:
        results[root_key] = ApplyEventOne(package_list, root_key, args) if event == 1 else ApplyEventZero(package_list, root_key, args)
    SaveAlertDictionaryList(args.state_file, package_list)
    print(json.dumps({"operation": "add", "results": results}, ensure_ascii=False))


############################### CRUD OPERATIONS ###############################


def SelectData(args):
    package_list = LoadAlertDictionaryList(args.state_file)
    if args.rootkey:
        package = GetPackageByRootKey(package_list, args.rootkey)
        selected = package if args.path == "$" else SelectPackageValue(package, args.path)
    elif args.list_key:
        selected = SelectListValuesByKey(package_list, args.list_key)
    else:
        selected = SelectValueByJsonPath(package_list, args.path)
    print(json.dumps(selected, ensure_ascii=False, indent=4))


def ParseUpdateValue(args):
    if args.json_data is not None:
        return ParseJsonArgument(args.json_data, "--json-data")
    if args.data is not None:
        return args.data
    raise ValueError("Required argument is missing: --data or --json-data")


def ParseExpectJson(args):
    if args.expect_json is None:
        return {}
    expected = ParseJsonArgument(args.expect_json, "--expect-json")
    if not isinstance(expected, dict):
        raise ValueError("--expect-json must be a JSON dictionary")
    return expected


def UpdateData(args):
    CheckRequiredValue(args.rootkey, "--rootkey")
    package_list = LoadAlertDictionaryList(args.state_file)
    package = GetPackageByRootKey(package_list, args.rootkey)
    matched, reason = MatchExpectedValues(package, ParseExpectJson(args))
    if not matched:
        print(json.dumps(MakeOperationResponse(conflict=True, reason=reason, root_key=args.rootkey), ensure_ascii=False))
        return
    SetValueByParts(package, GetPathParts(args.path), ParseUpdateValue(args))
    SaveAlertDictionaryList(args.state_file, package_list)
    print(json.dumps(MakeOperationResponse(updated=True, root_key=args.rootkey), ensure_ascii=False))


def PatchData(args):
    CheckRequiredValue(args.rootkey, "--rootkey")
    patch_payload = ParseJsonArgument(args.patch_json, "--patch-json")
    if not isinstance(patch_payload, dict):
        raise ValueError("--patch-json must be a JSON dictionary")
    set_values = patch_payload.get("set", {})
    expected_values = patch_payload.get("expect", {})
    if not isinstance(set_values, dict) or not set_values:
        raise ValueError("patch set must be a non-empty JSON dictionary")
    package_list = LoadAlertDictionaryList(args.state_file)
    package = GetPackageByRootKey(package_list, args.rootkey)
    matched, reason = MatchExpectedValues(package, expected_values)
    if not matched:
        print(json.dumps(MakeOperationResponse(conflict=True, reason=reason, root_key=args.rootkey), ensure_ascii=False))
        return
    for json_path, value in set_values.items():
        if not isinstance(json_path, str):
            raise ValueError("patch path must be a string")
        SetValueByParts(package, GetPathParts(json_path), value)
    SaveAlertDictionaryList(args.state_file, package_list)
    print(json.dumps(MakeOperationResponse(updated=True, root_key=args.rootkey), ensure_ascii=False))


def DeleteData(args):
    CheckRequiredValue(args.rootkey, "--rootkey")
    package_list = LoadAlertDictionaryList(args.state_file)
    package = FindPackageByRootKey(package_list, args.rootkey)
    if package is None:
        print(json.dumps(MakeOperationResponse(reason="root key was not found", root_key=args.rootkey), ensure_ascii=False))
        return
    matched, reason = MatchExpectedValues(package, ParseExpectJson(args))
    if not matched:
        print(json.dumps(MakeOperationResponse(conflict=True, reason=reason, root_key=args.rootkey), ensure_ascii=False))
        return
    package_list.remove(package)
    SaveAlertDictionaryList(args.state_file, package_list)
    print(json.dumps(MakeOperationResponse(deleted=True, root_key=args.rootkey), ensure_ascii=False))


############################### BODY ###############################


def Main():
    global VERBOSE
    args = GetArgs()
    VERBOSE = args.verbose
    lock_file_path = GetLockFilePath(args)
    lock_file = None
    try:
        lock_file = OpenStateFileLock(lock_file_path, args.lock_timeout)
        if args.mode == "add":
            AddEvent(args)
        elif args.mode == "select":
            SelectData(args)
        elif args.mode == "update":
            UpdateData(args)
        elif args.mode == "patch":
            PatchData(args)
        elif args.mode == "del":
            DeleteData(args)
        else:
            raise ValueError("Unsupported mode: {}".format(args.mode))
    except Exception as error:
        WriteLog("Execution failed: {}".format(error), "ERROR")
        print(str(error), file=sys.stderr)
        return 1
    finally:
        try:
            CloseStateFileLock(lock_file, lock_file_path)
        except Exception as unlock_error:
            WriteLog("Failed to release state lock: {}".format(unlock_error), "ERROR")
    return 0


if __name__ == "__main__":
    sys.exit(Main())
