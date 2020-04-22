#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2019, Intel Corporation. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#

"""A stitching utility to replace code/data sub-regions in System BIOS image
"""


import os
import subprocess
import sys
import argparse
import shutil
import re
import uuid
import click
from pathlib import Path


from cryptography.hazmat.primitives import hashes as hashes
from cryptography.hazmat.backends import default_backend

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common.subregion_image as sbrgn_image
import common.utilities as utils
from common.subregion_descriptor import SubRegionDescriptor
from common.subregion_image import generate_sub_region_image
from common.ifwi import IFWI_IMAGE
from common.firmware_volume import FirmwareDevice
from common.siip_constants import IP_OPTIONS
from common.tools_path import FMMT, GENFV, GENFFS, GENSEC, LZCOMPRESS, TOOLS_DIR
from common.tools_path import RSA_HELPER, FMMT_CFG
from common.banner import banner
import common.logging as logging

__prog__ = "siip_stitch"
__version__ = "0.7.5"
TOOLNAME = "SIIP Stitching Tool"

banner(TOOLNAME, __version__)

logger = logging.getLogger("siip_stitch")

if sys.version_info < (3, 6):
    raise Exception("Python 3.6 is the minimal version required")

GUID_FVADVANCED = uuid.UUID("B23E7388-9953-45C7-9201-0473DDE5487A")
GUID_FVSECURITY = uuid.UUID("5A9A8B4E-149A-4CB2-BDC7-C8D62DE2C8CF")

def search_for_fv(inputfile, ipname):
    """Search for the firmware volume."""

    # use to find the name of the firmware to locate the firmware volume
    build_list = IP_OPTIONS.get(ipname)

    ui_name = build_list[0][1]

    logger.info("\nFinding the Firmware Volume")
    fw_vol = None

    command = [FMMT, "-v", os.path.abspath(inputfile)]

    try:
        os.environ["PATH"] += os.pathsep + TOOLS_DIR
        logger.info("TOOLS_DIR  : %s" % TOOLS_DIR)
        logger.info("PATH       : %s" % os.environ["PATH"])
        logger.info("\n{}".format(" ".join(command)))

        p = subprocess.run(command,
                           shell=False,
                           check=True,
                           stdout=subprocess.PIPE,
                           universal_newlines=True,
                           timeout=60)

    except subprocess.CalledProcessError as status:
        logger.warning("\nError using FMMT: {}".format(status))
        return 1, fw_vol
    except subprocess.TimeoutExpired:
        logger.warning(
            "\nFMMT timed out viewing {}! Check input file for correct format".format(inputfile)
        )

        if sys.platform == 'win32':
            result = os.system("taskkill /f /im FMMT.exe")
        elif sys.platform == 'linux':
            result = os.system("killall FMMT")
        if result == 0:
            return 1, fw_vol
        sys.exit("\nError Must kill process")

    # search FFS by name in firmware volumes
    fwvol_found = False

    for line in p.stdout.splitlines():
        print(">> %s" % line)
        match_fv = re.match(r"(^FV\d+) :", line)
        if match_fv:
            fwvol_found = True
            fw_vol = match_fv.groups()[0]
            continue
        if fwvol_found:
            match_name = re.match(r'File "(%s)"' % ui_name, line.lstrip())
            if match_name:
                break
    else:
        fw_vol = None  # firmware volume was not found.
        logger.warning("\nCould not find file {} in {}".format(ui_name, inputfile))

    return 0, fw_vol


def replace_ip(outfile, fw_vol, ui_name, inputfile):
    """ replaces the give firmware value with the input file """

    cmd = [FMMT, "-r", inputfile, fw_vol, ui_name, "tmp.ffs", outfile]
    return cmd


def create_commands(filenames, ipname, fwvol):
    """Create Commands for the merge and replace of firmware section."""

    inputfiles, num_replace_files = sbrgn_image.ip_inputfiles(filenames, ipname)
    build_list = IP_OPTIONS.get(ipname)

    # get the file name to be used to replace firmware volume
    ui_name = build_list[0][1]

    cmd_list = sbrgn_image.build_command_list(build_list, inputfiles, num_replace_files)

    cmd = replace_ip(filenames[len(filenames) - 1], fwvol, ui_name,
                     filenames[0])
    cmd_list.append(cmd)

    return cmd_list


def merge_and_replace(filename, guid_values, fwvol):
    """Perform merge and replace of section using different executables."""

    cmds = create_commands(filename, guid_values, fwvol)

    logger.info("\nStarting merge and replacement of section")

    # Merging and Replacing
    status = utils.execute_cmds(logger, cmds)

    return status


def file_not_exist(file):
    """Verify that file does not exist."""

    if os.path.isfile(file):
        if not (click.confirm("\n{} file arleady exist! Do you want to overwrite it".format(file), abort=False)):
           raise argparse.ArgumentTypeError("{} exist!".format(file))
    return file


def check_key(file):
    """ Check if file exist, empty, or over max size"""

    if os.path.isfile(file):
        FIRSTLINE = "-----BEGIN RSA PRIVATE KEY-----"
        LASTLINE = "-----END RSA PRIVATE KEY-----"
        size = os.path.getsize(file)
        if size > 2000 or size == 0:
            raise argparse.ArgumentTypeError("size of {} is {} the key file size must be greater than 0 and less than 2k!".format(file, size))

        else:
            with open(file, "r") as key:
                key_lines = key.readlines()
            if not ((FIRSTLINE in key_lines[0]) and (LASTLINE in key_lines[-1])):
                raise argparse.ArgumentTypeError("{} is not an RSA private key".format(file))
    else:
        raise argparse.ArgumentTypeError("{} does not exist".format(file))

    return file


def check_file_size(files):
    """ Check if file is empty or greater than IFWI/BIOS file"""

    bios_size = os.path.getsize(files[0])

    for file in files:
        filesize = os.path.getsize(file)
        if filesize != 0:
            if not (filesize <= bios_size):
                logger.warning("\n{} file is size {} file exceeds the size of the BIOS/IFWI file {}!".format(file, filesize, files[0]))
                return 1
        else:
            logger.warning("\n{} file is empty!".format(file))
            return 1

    return 0


def parse_cmdline():
    """ Parsing and validating input arguments."""

    visible_ip_list = list(IP_OPTIONS.keys())
    visible_ip_list.remove("obb_digest")

    epilog = "Supported Sub-Region Names: {}\n".format(visible_ip_list)
    parser = argparse.ArgumentParser(prog=__prog__,
                                     description=__doc__,
                                     epilog=epilog)

    parser.add_argument(
        "IFWI_IN",
        type=argparse.FileType("rb+"),
        help="Input BIOS Binary file(Ex: IFWI.bin) to be updated with the given input IP firmware",
    )
    parser.add_argument(
        "IPNAME_IN",
        type=argparse.FileType("rb"),
        help="Input IP firmware Binary file(Ex: PseFw.Bin to be replaced in the IFWI.bin",
    )
    parser.add_argument(
        "-ip",
        "--ipname",
        help="The name of the IP in the IFWI_IN file to be replaced. This is required.",
        metavar="ipname",
        required=True,
        choices=visible_ip_list,
    )
    parser.add_argument(
        "-k",
        "--private-key",
        type=check_key,
        help="Private RSA key in PEM format. Note: Key is required for stitching GOP features",
    )
    parser.add_argument(
        "-v",
        "--version",
        help="Shows the current version of the BIOS Stitching Tool",
        action="version",
        version="%(prog)s {version}".format(version=__version__),
    )
    parser.add_argument(
        "-o",
        "--outputfile",
        dest="OUTPUT_FILE",
        type=file_not_exist,
        help="IFWI binary file with the IP replaced with the IPNAME_IN",
        metavar="FileName",
        default="BIOS_OUT.bin",
    )

    return parser


def stitch_and_update(ifwi_file, ip_name, file_list, out_file):

    # search for firmware volume
    status, fw_volume = search_for_fv(ifwi_file, ip_name)

    # Check for error in using FMMT.exe or if firmware volume was not found.
    if status == 1 or fw_volume is None:

        to_remove = ["tmp.fmmt.txt", "tmp.payload.bin", "tmp.obb.hash.bin",
                     os.path.join(TOOLS_DIR, "privkey.pem")]

        utils.cleanup(to_remove)

        if status == 0:
            logger.critical("\nError: No Firmware volume found")
        sys.exit(status)

    # firmware volume was found
    logger.info("\nThe Firmware volume is {}\n".format(fw_volume))

    # adding the path name to the output file
    file_list.append(os.path.abspath(out_file))

    # Add firmware volume header and merge it in out_file
    status = merge_and_replace(file_list, ip_name, fw_volume)


def update_obb_digest(ifwi_file, digest_file):
    """Calculate OBB hash according to a predefined range"""

    ifwi = IFWI_IMAGE(ifwi_file)
    if not ifwi.is_ifwi_image():
        logger.critical("Bad IFWI image")
        exit(1)

    ifwi.parse()
    bios_start = ifwi.region_list[1][1]
    bios_limit = ifwi.region_list[1][2]

    logger.info("Parsing BIOS ...")
    bios = FirmwareDevice(0, ifwi.data[bios_start:bios_limit+1])
    bios.ParseFd()

    # Extract FVs belongs to OBB
    obb_fv_idx = bios.get_fv_index_by_guid(GUID_FVSECURITY.bytes_le)
    if not (0 < obb_fv_idx < len(bios.FvList)):
        raise ValueError("Starting OBB FV is not found")

    logger.debug("OBB region starts from FV{}".format(obb_fv_idx))
    obb_offset = bios.FvList[obb_fv_idx].Offset
    obb_length = 0
    if bios.is_fsp_wrapper():
        # FVSECURITY + FVOSBOOT + FVUEFIBOOT_PRIME + FVADVANCED + FVPOSTMEMORY + FSPS
        logger.info("FSP Wrapper BIOS")
        obb_fv_end = obb_fv_idx + 6
    else:
        # FVSECURITY + FVOSBOOT + FVUEFIBOOT_PRIME + FVADVANCED + FVPOSTMEMORY
        logger.info("EDK2 BIOS")
        obb_fv_end = obb_fv_idx + 5
    for fv in bios.FvList[obb_fv_idx:obb_fv_end]:
        obb_length += len(fv.FvData)

    logger.debug("OBB offset: {:x} len {:x}".format(obb_offset, obb_length))

    # Hash it
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(bios.FdData[obb_offset:obb_offset+obb_length])
    result = digest.finalize()
    with open(digest_file, "wb") as hash_fd:
        hash_fd.write(result)

    return


def main():
    """Entry to script."""

    # files created that needs to be remove
    to_remove = ["tmp.fmmt.txt", "tmp.raw", "tmp.ui", "tmp.all", "tmp.cmps",
                 "tmp.guid", "tmp.pe32", "tmp.ffs"]
    try:
        parser = parse_cmdline()
        args = parser.parse_args()

        for f in (FMMT, GENFV, GENFFS, GENSEC, LZCOMPRESS, RSA_HELPER, FMMT_CFG):
            if not os.path.exists(f):
                raise FileNotFoundError("Thirdparty tool not found ({})".format(f))

        # Use absolute path because GenSec does not like relative ones
        IFWI_file = Path(args.IFWI_IN.name).resolve()

        # If input IP file is a JSON file, convert it to binary as the real input file
        if args.IPNAME_IN.name.lower().endswith('.json'):
            logger.info("Found JSON as input file. Converting it to binary ...\n")

            desc = SubRegionDescriptor()
            desc.parse_json_data(args.IPNAME_IN.name)

            # Currently only creates the first file
            generate_sub_region_image(desc.ffs_files[0], output_file="tmp.payload.bin")
            IPNAME_file = Path("tmp.payload.bin").resolve()

            # add to remove files
            to_remove.append("tmp.payload.bin")
        else:
            IPNAME_file = Path(args.IPNAME_IN.name).resolve()

        filenames = [str(IFWI_file), str(IPNAME_file)]
        if args.ipname in ["gop", "gfxpeim", "vbt"]:
            if not args.private_key or not os.path.exists(args.private_key):
                logger.critical("\nMissing RSA key to stitch GOP/PEIM GFX/VBT from command line\n")
                parser.print_help()
                sys.exit(2)
            else:
                key_file = Path(args.private_key).resolve()
                filenames.append(key_file)

        # Verify file is not empty or the IP files are smaller than the input file
        status = check_file_size(filenames)
        if status != 0:
            sys.exit(status)

        # Copy key file to the required name needed for the rsa_helper.py
        if args.private_key:
            shutil.copyfile(key_file, os.path.join(TOOLS_DIR, "privkey.pem"))
            to_remove.append(os.path.join(TOOLS_DIR, 'privkey.pem'))
            filenames.remove(key_file)

        logger.info("*** Replacing {} ...".format(args.ipname))
        stitch_and_update(args.IFWI_IN.name, args.ipname, filenames, args.OUTPUT_FILE)

        # Update OBB digest after stitching any data inside OBB region
        if args.ipname in ["gop", "vbt", "gfxpeim"]:
            ipname = "obb_digest"
            digest_file = "tmp.obb.hash.bin"

            to_remove.append(digest_file)

            update_obb_digest(args.OUTPUT_FILE, digest_file)

            filenames = [str(Path(f).resolve()) for f in [args.OUTPUT_FILE, digest_file]]

            logger.info("*** Replacing {} ...".format(ipname))
            stitch_and_update(args.OUTPUT_FILE, ipname, filenames, args.OUTPUT_FILE)
    finally:
        utils.cleanup(to_remove)


if __name__ == "__main__":

    main()
