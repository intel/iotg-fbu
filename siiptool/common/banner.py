# -*- coding: utf-8 -*-
#
# Copyright (c) 2019, Intel Corporation. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#

import platform
COPYRIGHT = "2020"

def banner(name, ver_str, extra=""):
    """Create a simple header with version and host information"""

    print("\n" + "#" * 75)
    print("Intel (R) {}. Version: {}".format(name, ver_str))
    print("Copyright (c) {}, Intel Corporation. All rights reserved.\n"\
        .format(COPYRIGHT))
    
    print("Running on {} with Python {}".format(platform.platform(),
                                                    platform.python_version()))
    print("#" * 75 + "\n")
    print(extra)
