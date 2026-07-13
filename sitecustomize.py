#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import warnings

try:
    import urllib3
except ImportError:
    urllib3 = None

if urllib3 is not None:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

warnings.filterwarnings("ignore", category=DeprecationWarning)


def apply_watcher_run_default():
    if len(sys.argv) < 2:
        return
    script_name = os.path.basename(sys.argv[0])
    if script_name != "watcher.py" or sys.argv[1] != "run":
        return
    if "--state-file" in sys.argv:
        return
    sys.argv.extend(["--state-file", "alerts.json"])


apply_watcher_run_default()
