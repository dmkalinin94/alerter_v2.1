#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import fcntl
import json
import os
import sys
import tempfile
import time

STATE_FILE_DEFAULT = "/tmp/alerts.json"
LOCK_TIMEOUT_DEFAULT = 30.0
LOCK_RETRY_INTERVAL = 0.01


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("add", "select", "update", "del"))
    parser.add_argument("--state-file", default=STATE_FILE_DEFAULT)
    parser.add_argument("--lock-file")
    parser.add_argument("--lock-timeout", type=float, default=LOCK_TIMEOUT_DEFAULT)
    parser.add_argument("--rootkey")
    parser.add_argument("--path", default="$")
    parser.add_argument("--data")
    parser.add_argument("--json-data")
    return parser.parse_args()


def require(value, name):
    if value is None or value == "":
        raise ValueError("Required argument is missing: {}".format(name))


def parse_value(args):
    if args.json_data is not None:
        return json.loads(args.json_data)
    if args.data is not None:
        return args.data
    raise ValueError("Required argument is missing: --data or --json-data")


def acquire_lock(path, timeout):
    if timeout < 0:
        raise ValueError("--lock-timeout cannot be negative")
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    lock_file = open(path, "a+", encoding="utf-8")
    deadline = time.monotonic() + timeout
    while True:
        try:
            fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return lock_file
        except BlockingIOError:
            if time.monotonic() >= deadline:
                lock_file.close()
                raise TimeoutError("Timed out waiting for lock {}".format(path))
            time.sleep(LOCK_RETRY_INTERVAL)


def release_lock(lock_file):
    if lock_file is None:
        return
    try:
        fcntl.flock(lock_file, fcntl.LOCK_UN)
    finally:
        lock_file.close()


def load_json(path):
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return []
    try:
        with open(path, "r", encoding="utf-8") as file:
            return json.load(file)
    except (OSError, ValueError):
        backup = path + ".back"
        if os.path.exists(backup):
            os.remove(backup)
        os.replace(path, backup)
        return []


def save_json(path, data):
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=directory, delete=False
        ) as temp_file:
            temp_path = temp_file.name
            json.dump(data, temp_file, ensure_ascii=False, separators=(",", ":"))
            temp_file.write("\n")
            temp_file.flush()
            os.fsync(temp_file.fileno())
        os.replace(temp_path, path)
        temp_path = None
    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)


def path_parts(path):
    if path == "$":
        return []
    if not path.startswith("$."):
        raise ValueError("Path must start with $ or $.")
    parts = path[2:].split(".")
    if any(not part for part in parts):
        raise ValueError("Path contains an empty key")
    return parts


def find_root(data, root_key):
    if not isinstance(data, list):
        raise ValueError("JSON root is not a list")
    for item in data:
        if isinstance(item, dict) and item.get("rootKey") == root_key:
            return item
    raise ValueError("Root key was not found: {}".format(root_key))


def selected_root(data, root_key):
    return find_root(data, root_key) if root_key else data


def get_value(root, path):
    value = root
    for part in path_parts(path):
        if isinstance(value, dict):
            if part not in value:
                raise ValueError("Path key was not found: {}".format(part))
            value = value[part]
        elif isinstance(value, list) and part.isdigit():
            value = value[int(part)]
        else:
            raise ValueError("Path cannot continue through {}".format(part))
    return value


def set_value(root, path, new_value):
    parts = path_parts(path)
    if not parts:
        raise ValueError("Update path must point inside selected root")
    parent = get_value(root, "$.{}".format(".".join(parts[:-1]))) if len(parts) > 1 else root
    key = parts[-1]
    if isinstance(parent, dict):
        parent[key] = new_value
    elif isinstance(parent, list) and key.isdigit():
        parent[int(key)] = new_value
    else:
        raise ValueError("Update path parent is not writable")


def add_value(root, path, new_value):
    target = get_value(root, path)
    if not isinstance(target, list):
        raise ValueError("Add path must point to a list")
    target.append(new_value)


def delete_value(data, root_key, path):
    if root_key and path == "$":
        item = find_root(data, root_key)
        data.remove(item)
        return
    root = selected_root(data, root_key)
    parts = path_parts(path)
    if not parts:
        raise ValueError("Delete path must point to a value")
    parent = get_value(root, "$.{}".format(".".join(parts[:-1]))) if len(parts) > 1 else root
    key = parts[-1]
    if isinstance(parent, dict):
        if key not in parent:
            raise ValueError("Path key was not found: {}".format(key))
        del parent[key]
    elif isinstance(parent, list) and key.isdigit():
        del parent[int(key)]
    else:
        raise ValueError("Delete path parent is not writable")


def main():
    args = get_args()
    lock_file = None
    try:
        lock_file = acquire_lock(
            args.lock_file or args.state_file + ".lock", args.lock_timeout
        )
        data = load_json(args.state_file)
        root = selected_root(data, args.rootkey)

        if args.mode == "select":
            print(json.dumps(get_value(root, args.path), ensure_ascii=False, indent=4))
            return 0

        if args.mode == "add":
            add_value(root, args.path, parse_value(args))
        elif args.mode == "update":
            set_value(root, args.path, parse_value(args))
        elif args.mode == "del":
            delete_value(data, args.rootkey, args.path)

        save_json(args.state_file, data)
        return 0
    except Exception as error:
        print(str(error), file=sys.stderr)
        return 1
    finally:
        release_lock(lock_file)


if __name__ == "__main__":
    sys.exit(main())
