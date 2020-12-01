#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2020, Intel Corporation. All rights reserved.
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

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common.subregion_image as sbrgn_image
import common.utilities as utils
from common.subregion_descriptor import SubRegionDescriptor
from common.subregion_image import generate_sub_region_image
from common.ifwi import IFWI_IMAGE
from common.firmware_volume import FirmwareDevice
from common.siip_constants import IP_OPTIONS
from common.tools_path import FMMT, GENFV, GENFFS, GENSEC, LZCOMPRESS, TOOLS_DIR
from common.tools_path import RSA_HELPER, FMMT_CFG
from common.siip_constants import VERSION as __version__
from common.banner import banner
import common.logger as logging

__prog__ = "siip_stitch"

TOOLNAME = "SIIP Stitching Tool"

banner(TOOLNAME, __version__)

logger = logging.getLogger("siip_stitch")

if sys.version_info < (3, 6):
    raise Exception("Python 3.6 is the minimal version required")

GUID_FFS_OBBPEI_HASH = uuid.UUID("F57757FC-2603-404F-AAE2-34C6232388E8")
GUID_FFS_OBBDXE_HASH = uuid.UUID("32198477-7337-40E4-897D-BC33F018B42F")

# Region for OBBPEI digest
GUID_FVOSBOOT = uuid.UUID("13BF8810-75FD-4B1A-91E6-E16C4201F80A")
GUID_FVUEFIBOOT = uuid.UUID("0496D33D-EA79-495C-B65D-ABF607184E3B")
GUID_FVADVANCED = uuid.UUID("B23E7388-9953-45C7-9201-0473DDE5487A")

# Region for OBBDXE digest
GUID_FVPOSTMEMORY = uuid.UUID("9DFE49DB-8EF0-4D9C-B273-0036144DE917")
GUID_FVFSPS = uuid.UUID("8C8CE578-8A3D-4F1C-9935-896185C32DD3")  # EFI_FIRMWARE_FILE_SYSTEM2_GUID


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
    """Perform merge and replace of section using different executable."""

    cmds = create_commands(filename, guid_values, fwvol)

    logger.info("\nStarting merge and replacement of section")

    # Merging and Replacing
    status = utils.execute_cmds(logger, cmds)

    return status


def parse_cmdline():
    """ Parsing and validating input arguments."""

    visible_ip_list = list(IP_OPTIONS.keys())
    visible_ip_list.remove("obbpei_digest")
    visible_ip_list.remove("obbdxe_digest")

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
            status = 1
        sys.exit(status)

    # firmware volume was found
    logger.info("\nThe Firmware volume is {}\n".format(fw_volume))

    # adding the path name to the output file
    file_list.append(os.path.abspath(out_file))

    # Add firmware volume header and merge it in out_file
    status = merge_and_replace(file_list, ip_name, fw_volume)
    if status != 0:
        sys.exit(status)


def calculate_new_obb_digest(ifwi_file, fv_list, digest_file):
    """Calculate new OBB hash for one or more firmware volumes.
       The assumption is all FVs are continuous in one region."""

    bios = bytearray()

    ifwi = IFWI_IMAGE(ifwi_file)
    if not ifwi.is_ifwi_image():
        logger.warn("Invalid IFWI descriptor signature. Assuming BIOS image")
        with open(ifwi_file, "rb") as fd:
            bios = FirmwareDevice(0, bytearray(fd.read()))
    else:
        ifwi.parse()
        bios_start = ifwi.region_list[1][1]
        bios_limit = ifwi.region_list[1][2]
        bios = FirmwareDevice(0, ifwi.data[bios_start:bios_limit+1])

    logger.info("Found BIOS ({}MB)...".format(len(bios.FdData) // (1024 * 1024)))
    bios.ParseFd()

    # Locate FVs (note: only the first FV index is used)
    fv_id_list = []
    for fv in fv_list:
        obb_fv_idx = bios.get_fv_index_by_guid(fv.bytes_le)
        if not (0 < obb_fv_idx < len(bios.FvList)):
            raise ValueError("FV {} for OBB region is not found".format(fv))
        logger.info("Found FV @ index {}".format(obb_fv_idx))
        fv_id_list.append(obb_fv_idx)

    starting_fv_idx = fv_id_list[0]
    logger.info("*** OBB region starts from FV{} (len:{})".format(starting_fv_idx, len(fv_id_list)))
    obb_offset = bios.FvList[starting_fv_idx].Offset
    obb_length = 0
    if bios.is_fsp_wrapper():
        logger.info("FSP Wrapper BIOS")
        obb_fv_end = starting_fv_idx + len(fv_list)
    else:
        logger.critical("EDK2 BIOS image format is not supported any more")
        exit(2)

    # Get total length of OBB
    logger.info("start FV: {} end FV: {}".format(starting_fv_idx, obb_fv_end))
    for fv in bios.FvList[starting_fv_idx:obb_fv_end]:
        logger.info("Adding FV size 0x{:x} ...".format(len(fv.FvData)))
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

        outfile = Path(args.OUTPUT_FILE).resolve()
        outfile = utils.file_not_exist(outfile, logger)

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
                status = utils.check_key(key_file, "rsa", logger)
                if status != 0:
                    sys.exit(status)
                filenames.append(key_file)

        # Verify file is not empty or the IP files are smaller than the input file
        status = utils.check_file_size(logger, filenames)
        if status != 0:
            sys.exit(status)

        # Copy key file to the required name needed for the rsa_helper.py
        if args.private_key:
            shutil.copyfile(key_file, os.path.join(TOOLS_DIR, "privkey.pem"))
            to_remove.append(os.path.join(TOOLS_DIR, 'privkey.pem'))
            filenames.remove(key_file)

        logger.info("*** Replacing {} ...".format(args.ipname))
        stitch_and_update(args.IFWI_IN.name, args.ipname, filenames, outfile)

        # Update OBB digest after stitching any data inside OBB region
        if args.ipname in ["gop", "vbt", "gfxpeim"]:

            if args.ipname == "gop":
                ipname = "obbdxe_digest"
                fv_list = [GUID_FVOSBOOT, GUID_FVUEFIBOOT, GUID_FVADVANCED]
            else:
                ipname = "obbpei_digest"
                fv_list = [GUID_FVPOSTMEMORY, GUID_FVFSPS]

            digest_file = "tmp.obb.hash.bin"

            to_remove.append(digest_file)

            calculate_new_obb_digest(outfile, fv_list, digest_file)

            filenames = [str(Path(f).resolve()) for f in [outfile, digest_file]]

            logger.info("*** Replacing {} ...".format(ipname))
            stitch_and_update(outfile, ipname, filenames, outfile)
    finally:
        utils.cleanup(to_remove)


if __name__ == "__main__":

    main()
