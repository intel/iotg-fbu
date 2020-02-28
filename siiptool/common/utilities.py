# @file
# Functions use to suport sub regions tools
#
# Copyright (c) 2019, Intel Corporation. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#

import os
import subprocess
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def execute_cmds(log, cmds):
    """execute commands created from the build list"""

    for _, command in enumerate(cmds):
        try:
            log.info("\n{}".format(" ".join(command)))
            subprocess.check_call(command)
        except subprocess.CalledProcessError as status:
            log.warning("\nStatus Message: {}".format(status))
            return 1
    return 0


def get_key_and_value(dict, lookup_value, value_loc):
    """ Finds the key and associated value from the lookup value based on the location of the lookup value """

    for key, value in dict.items():
        if lookup_value == value[value_loc[0]][value_loc[1]]:
            return key, value
    return None, None


def cleanup(files):
    for file in files:
        try:
            os.remove(file)
        except FileNotFoundError:
            pass
