# SPDX-FileCopyrightText: 2018-2022 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
#

import importlib.util
import os
import sys
from importlib.abc import Loader
from typing import Any


def _load_source(name: str, path: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if not spec:
        return None

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    assert isinstance(spec.loader, Loader)
    spec.loader.exec_module(module)
    return module

idf_path = os.path.realpath(os.path.dirname(os.path.abspath(__file__)) + '/../')

# protocomm component related python files generated from .proto files
constants_pb2 = _load_source('constants_pb2', idf_path + '/pb/constants_pb2.py')
sec2_pb2      = _load_source('sec2_pb2',      idf_path + '/pb/sec2_pb2.py')
session_pb2   = _load_source('session_pb2',   idf_path + '/pb/session_pb2.py')
