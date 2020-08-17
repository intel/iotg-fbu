#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2019, Intel Corporation. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#

""" Tool Version Number """

VERSION = "0.7.6"

"""Sub-region configuration for different types of code/data
"""


GUID_DEFINED_LZMA = "EE4E5898-3914-4259-9D6E-DC7BD79403CF"

# element[0][1] section UI name; element[-1][1] is FFS_GUID
IP_OPTIONS = {
    "pse": [
        ["ui", "IntelPseFw"],
        ["raw", "PI_NONE"],
        [None],
        ["lzma", "-e"],  # Compressed section
        ["guid", GUID_DEFINED_LZMA, "PROCESSING_REQUIRED"],
        ["free", "EBA4A247-42C0-4C11-A167-A4058BC9D423", "1K"],
    ],
     "fkm": [
        ["ui", "SiipFkm" ],
        ["raw", "PI_NONE"],
        [None],
        ["lzma", "-e"],  # Compressed section
        ["guid", GUID_DEFINED_LZMA, "PROCESSING_REQUIRED"],
        ["free", "8AFFBA0F-C312-4717-9DD5-6AB1FE5FCB47", "1K"],
    ],
    "tmac": [
        ["ui", "IntelFvTsnMacAddr"],
        ["raw", "PI_NONE"],
        [None],
        ["free", "12E29FB4-AA56-4172-B34E-DD5F4B440AA9", None],
    ],
    "tsnip": [
        ["ui", "IntelPseTsnIpConfig"],
        ["raw", "PI_NONE"],
        [None],
        ["free", "40BD5BCD-094F-43B3-8D8D-1D72F850C3CB", None],
    ],
    "tsn": [
        ["ui", "IntelTsnConfig"],
        ["raw", "PI_NONE"],
        [None],
        ["free", "4FB7994D-D878-4BD1-8FE0-777B732D0A31", None],
    ],
    "tcc": [
        ["ui", "IntelTccConfig"],
        ["raw", "PI_NONE"],
        [None],
        ["free", "7F6AD829-15E9-4FDE-9DD3-0548BB7F56F3", None],
    ],
    "tccc": [
        ["ui", "IntelFvTccCacheCfg"],
        ["raw", "PI_NONE"],
        [None],
        ["free", "0C1A77B3-FD36-46F9-8AD0-598367053641", None],
    ],
    "tccb": [
        ["ui", "IntelFvTccBuffer"],
        ["raw", "PI_NONE"],
        [None],
        ["free", "F20527A7-B7B0-4630-A6BD-ED10CD48B94F", None],
    ],
    "tccp": [
        ["ui", "IntelFvPtcmBinary"],
        ["raw", "PI_NONE"],
        [None],
        ["lzma", "-e"],  # Compressed section
        ["guid", GUID_DEFINED_LZMA, "PROCESSING_REQUIRED"],
        ["free", "0240AD7B-00DA-43AF-9ED4-73B8DF48CD0B", None],
    ],
    "oob": [
        ["ui", "IntelOobConfig"],
        ["raw", "PI_NONE"],
        [None],
        ["free", "4DB2A373-C936-4544-AA6D-8A194AA9CA7F", None],
    ],
    "oob_rootca": [
        ["ui", "IntelOobRootCA"],
        ["raw", "PI_NONE"],
        [None],
        ["free", "2F4DE35A-0D52-44FC-ABF3-75B8AA51F434", None],
    ],
    "vbt": [
        ["ui", "IntelGopVbt"],
        ["raw", "PI_NONE"],
        [None],
        ["free", "56752da9-de6b-4895-8819-1945b6b76c22", None],
    ],
    "obbpei_digest": [
        ["ui", "ObbPeiDigest"],
        ["raw", "PI_NONE"],
        [None],
        ["free", "F57757FC-2603-404F-AAE2-34C6232388E8", None],
    ],
    "obbdxe_digest": [
        ["ui", "ObbDxeDigest"],
        ["raw", "PI_NONE"],
        [None],
        ["free", "32198477-7337-40E4-897D-BC33F018B42F", None],
    ],
    "gop": [
        ["ui", "IntelGopDriver"],
        ["pe32", None],
        [None],
        ["gop", "FF0C8745-3270-4439-B74F-3E45F8C77064", None],
    ],
    "gfxpeim": [
        ["ui", "IntelGraphicsPeim"],
        ["pe32", None],
        [None, "32", "1"],
        ["cmprs", "PI_STD"],
        ["peim", "76ED893A-B2F9-4C7D-A05F-1EA170ECF6CD", None],
    ],
}
