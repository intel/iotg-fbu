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
import common.logger as logging




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
           log.critical("%s file already exists. Exiting tool!", file)
           sys.exit(2)
    return file


def file_exist(files,log):
    """Verify that file exist."""
      
    for file in files:
        if not os.path.isfile(file):
            log.critical("\n{} file not found".format(file))
            return 2
    return 0


def check_file_size(log, files):
    """ Check if file is empty or greater than IFWI/BIOS file"""

    bios_size = os.path.getsize(files[0])

    for file in files:
        filesize = os.path.getsize(file)
        if filesize != 0:
            if not (filesize <= bios_size):
                log.critical("\n{} file is size {} file exceeds the size of the BIOS/IFWI file {}!".format(file, filesize, files[0]))
                return 2
        else:
            log.critical("\n{} file is empty!".format(file))
            return 2

    return 0


def check_key(file, key_type, log):
    """ Check if file exist, empty, or over max size and correct format"""
    # element[0][1] start of file; element[-1][0] is size of file
    KEY_TYPE = {
        "rsa": [
            "RSA private key",
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----END RSA PRIVATE KEY-----",
            3500,
        ],
        "pubcert": [
            "Public Certificate",
            "-----BEGIN CERTIFICATE-----",
            "-----END CERTIFICATE-----",
            2500,
        ],
        "pkcs7": [
           "PKCS7 Signer",
           "Bag Attributes",
           "-----END PRIVATE KEY-----",
           "localKeyID:",
           "subject=",
           "issuer=",
           "-----BEGIN CERTIFICATE-----",
           "-----END CERTIFICATE-----",
           "-----BEGIN PRIVATE KEY-----",
            5500,
        ]
    }
  
    if os.path.isfile(file):

        key_info = KEY_TYPE.get(key_type)
        max_size = key_info[-1]
        size = os.path.getsize(file)
        key_name = key_info[0]

        FIRSTLINE = key_info[1]
        LASTLINE = key_info[2]

        if size > max_size or size == 0:
           log.critical("size of {} is {} the key file size must be greater than 0 and less than {}!".format(file, size, max_size))
           return 2
        else:
            with open(file, "r") as key:
                key_lines = key.readlines()
            if not ((FIRSTLINE in key_lines[0]) and (LASTLINE in key_lines[-1])):
                if key_type == "rsa":
                    # check if key is in format "-----Begin/End Private Key----" instead of -----Begin/End RSA Private Key---"
                    if ( FIRSTLINE.replace(' RSA','') in key_lines[0]) and (LASTLINE.replace(' RSA',"")in key_lines[-1]): 
                        return 0
                log.critical("{} is not in the format of a {}".format(file, key_name))
                return 2

             # veirfy signer format
            if key_type == "pkcs7":
                if verify_signer(key_info, key_lines):
                    log.critical("{} is not in the format of a {}".format(file, key_name))
                    return 2
    else:
        log.critical("{} does not exist".format(file))
        return 2
        
    return 0

def verify_signer(key_info, file_data):
    """ Verify signature key file """

#format of signature file

# Bag attributes
     #localKeyID: "keyid"
#subject="some data"
#issuer="some data"
#-----BEGIN CERTIFICATE-----
#"lines of certificate data"
#-----END CERTIFICATE-----
# Bag attributes
   # localKeyID: "keyid"
#-----BEGIN PRIVATE KEY-----
# "Lines of key data"
#-----END PRIVATE KEY-----

    CORRECT_FORMAT = ["KEY", "SUB", "ISSU", "B_CERT","E_CERT", "KEY", "B_KEY"]
    KEYID =key_info[3]
    SUBJECT =key_info[4]
    ISSUER = key_info[5]
    BEGIN_CERT = key_info[6]
    END_CERT = key_info[7]
    BEGIN_KEY = key_info[8]
    key_indexes = []
    format_pattern = []
    

    # find keywords in file
   
    for i in range(len(file_data)):
        
        if file_data[i].find(KEYID) != -1:
            key_indexes.append(i)
            format_pattern.append('KEY')
        elif file_data[i].find(SUBJECT) != -1:
            format_pattern.append('SUB')
        elif file_data[i].find(ISSUER) != -1:
            format_pattern.append('ISSU')
        elif file_data[i].find(BEGIN_CERT) != -1:
            format_pattern.append('B_CERT')
        elif file_data[i].find(END_CERT) != -1:
            format_pattern.append('E_CERT')
        elif file_data[i].find(BEGIN_KEY) != -1:
            format_pattern.append('B_KEY')
        
    # verify there is two KeyIDs and they are the same, and format is correct for keywords in data file
    if (len(key_indexes) != 2 or (file_data[key_indexes[0]] != file_data[key_indexes[1]]) or
    format_pattern != CORRECT_FORMAT):
        return 1
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