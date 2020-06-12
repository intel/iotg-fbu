# @file
# Functions use to suport sub regions tools
#
# Copyright (c) 2019, Intel Corporation. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#

import os
import subprocess
import sys
import click
import argparse



sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common.logging as logging

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

def file_not_exist(file):
    """Verify that file does not exist."""

    if os.path.isfile(file):
        if not (click.confirm("\n{} file arleady exist! Do you want to overwrite it".format(file), abort=False)):
           raise argparse.ArgumentTypeError("{} exist!".format(file))
    return file

def check_for_tool(tool, ver_cmd, tool_path=None):
    """Checks tool is installed and return path"""
    
    if tool_path is None:
        tool_path = ""
    else:
        tool_path = os.path.abspath(tool_path)

    path=os.path.join(tool_path, tool)
    
    cmd= f'{path} {ver_cmd}'

    try:
        p = subprocess.run(cmd,
                           stdout=subprocess.PIPE,
                           shell=True,
                           universal_newlines=True)
        print("openssl version: {}".format(p.stdout))
        return path
    except:
        print("OpenSSL is not installed or missing in PATH!\n")
        sys.exit(1)