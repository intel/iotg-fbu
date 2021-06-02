#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2019, Intel Corporation. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#

import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
THIRD_PARTY_DIR = os.path.join(BASE_DIR,"thirdparty")
if sys.platform == 'win32':
    TOOLS_DIR = os.path.abspath(os.path.join(THIRD_PARTY_DIR, "Bin", "Win32"))
    FMMT = os.path.join(TOOLS_DIR, "FMMT.exe")
    GENSEC = os.path.join(TOOLS_DIR, "GenSec.exe")
    GENFFS = os.path.join(TOOLS_DIR, "GenFfs.exe")
    GENFV = os.path.join(TOOLS_DIR, "GenFv.exe")
    LZCOMPRESS = os.path.join(TOOLS_DIR, "LzmaCompress.exe")
elif sys.platform == 'linux':
    TOOLS_DIR = os.path.abspath(os.path.join(THIRD_PARTY_DIR, "Bin", "Linux"))
    FMMT = os.path.join(TOOLS_DIR, "FMMT")
    GENSEC = os.path.join(TOOLS_DIR, "GenSec")
    GENFFS = os.path.join(TOOLS_DIR, "GenFfs")
    GENFV = os.path.join(TOOLS_DIR, "GenFv")
    LZCOMPRESS = os.path.join(TOOLS_DIR, "LzmaCompress")

RSA_HELPER = os.path.join(TOOLS_DIR, "rsa_helper.py")
FMMT_CFG = os.path.join(TOOLS_DIR, "FmmtConf.ini")
IP_OPTIONS_CFG = os.path.join(BASE_DIR, "common", "ip_options.json")

EDK2_CAPSULE_TOOL = os.path.abspath(os.path.join(THIRD_PARTY_DIR,
                                                 "edk2_capsule_tool",
                                                 "GenerateCapsule.py"))
