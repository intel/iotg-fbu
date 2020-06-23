# @file
# Functions use to suport sub regions tools
#
# Copyright (c) 2020, Intel Corporation. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#

import os
import subprocess
import sys
import click
from pathlib import Path
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


def file_not_exist(file, log):
    """Verify that file does not exist."""

    if os.path.isfile(file):
        if not (click.confirm("\n{} file already exists! Do you want to overwrite it".format(file), abort=False)):
           log.warning("%s file already exists. Exiting tool!", file)
           sys.exit(2)
    return file


def file_exist(files,log):
    """Verify that file exist."""
      
    for file in files:
        if not os.path.isfile(file):
            log.warning("\n{} file not found".format(file))
            return 1
    return 0


def check_file_size(log, files):
    """ Check if file is empty or greater than IFWI/BIOS file"""

    bios_size = os.path.getsize(files[0])

    for file in files:
        filesize = os.path.getsize(file)
        if filesize != 0:
            if not (filesize <= bios_size):
                log.warning("\n{} file is size {} file exceeds the size of the BIOS/IFWI file {}!".format(file, filesize, files[0]))
                return 1
        else:
            log.warning("\n{} file is empty!".format(file))
            return 1

    return 0

def check_key(file, key_type, log):
    """ Check if file exist, empty, or over max size"""
    # element[0][1] start of file; element[-1][0] is size of file
    KEY_TYPE = {
        "rsa": [
            "RSA private key",
            ["-----BEGIN RSA PRIVATE KEY-----", 0],
            ["-----END RSA PRIVATE KEY-----", -1],
            [2000],
        ],
        "pubcert": [
            "Public Certificate",
            ["-----BEGIN CERTIFICATE-----", 0],
            ["-----END CERTIFICATE-----", -1],
            [2000],
        ],
        "winsigner": [
            "Certificate Signer",
            ["Bag Attributes", 0],
            ["-----END PRIVATE KEY-----", -1],
            ["localKeyID:", 1, 30],
            ["subject=", 2],
            ["issuer=", 3],
            ["-----BEGIN CERTIFICATE-----", 4],
            ["-----END CERTIFICATE-----", 28],
            ["-----BEGIN PRIVATE KEY-----", 32],
            [4000],
        ]
    }

    if os.path.isfile(file):

        key_info = KEY_TYPE.get(key_type)
        max_size = key_info[-1][0]
        size = os.path.getsize(file)
        key_name = key_info[0]

        FIRSTLINE = key_info[1][0]
        LASTLINE = key_info[2][0]

        if size > max_size or size == 0:
           log.warning("size of {} is {} the key file size must be greater than 0 and less than 2k!".format(file, size))
           return 1
        else:
            with open(file, "r") as key:
                key_lines = key.readlines()
            if not ((FIRSTLINE in key_lines[0]) and (LASTLINE in key_lines[-1])):
               log.warning("{} is not a {}".format(file, key_name))
               #print("error")
               return 1

             # two localkeyId are the same, subject and issuer given, Cert begin and end in file, and Begin Key
            if key_type == "winsigner":
                status = 0
                KEYID =key_info[3][0]
                SUBJECT =key_info[4][0]
                ISSUER = key_info[5][0]
                BEGIN_CERT = key_info[6][0]
                END_CERT = key_info[7][0]
                BEGIN_KEY = key_info[8][0]
                
                if not ((KEYID in key_lines[key_info[3][1]]) and
                 (key_lines[key_info[3][1]] == key_lines[key_info[3][2]])):
                  status = 1
                if not ((SUBJECT in key_lines[key_info[4][1]]) and 
                  (ISSUER in key_lines[key_info[5][1]])):
                  status = 1
                if not ((BEGIN_CERT in key_lines[key_info[6][1]]) and 
                (END_CERT in key_lines[key_info[7][1]])):
                  status = 1
                if not (BEGIN_KEY in key_lines[key_info[8][1]]):
                    status = 1       
                if status != 0 :
                    log.warning("{} is not a {}".format(file, key_name))
                    return 1
    else:
        log.warning("{} does not exist".format(file))
        return 2

    return 0

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