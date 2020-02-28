#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2019, Intel Corporation. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#

"""A capsule image utility to generate UEFI sub-region capsule images
"""


import sys
import os
import argparse
import glob

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common.subregion_descriptor as subrgn_descrptr
import common.subregion_image as sbrgn_image
import common.utilities as utils
from common.tools_path import EDK2_CAPSULE_TOOL
from common.banner import banner
import common.logging as logging

logger = logging.getLogger("subregion_capsule")

if sys.version_info < (3, 7):
    raise Exception("Python 3.7 is the minimal version required")

#
# Globals for help information
#
__prog__ = "subregion_capsule"
__version__ = "0.7.3"

TOOLNAME = "Sub-Region Capsule Tool"

banner(TOOLNAME, __version__)


def generate_sub_region_fv(
        image_file,
        sub_region_descriptor,
        output_fv_file=os.path.join(os.path.curdir, "SubRegion.FV")
):

    sub_region_image = "SubRegionImage.bin"
    fv_ffs_file_list = []

    for file_index, ffs_file in enumerate(sub_region_descriptor.ffs_files):

        sbrgn_image.generate_sub_region_image(ffs_file, sub_region_image)
        ip, ip_ops = sbrgn_image.ip_info_from_guid(ffs_file.ffs_guid)

        # if ffs GUID is not found exit.
        if ip is None:
            print("FFS GUIS {} not found".format(ffs_file.ffs_guid))
            exit(-1)

        # Inputfiles should be minium of two files to work with function.
        inputfiles, num_files = sbrgn_image.ip_inputfiles(
            [None, sub_region_image],
            ip
            )

        cmds = sbrgn_image.build_command_list(ip_ops, inputfiles, num_files)

        if utils.execute_cmds(logger, cmds) == 1:
            exit(-1)

        ffs_file_path = "tmp.{}.ffs".format(file_index)
        os.rename("tmp.ffs", ffs_file_path)
        fv_ffs_file_list.append(ffs_file_path)

        fv_cmd_list = sbrgn_image.build_fv_from_ffs_files(
                     sub_region_descriptor,
                     output_fv_file,
                     fv_ffs_file_list)

    if utils.execute_cmds(logger, fv_cmd_list) == 1:
        print("Error generating FV File")
        exit(-1)


def create_arg_parser():
    def convert_arg_line_to_args(arg_line):
        for arg in arg_line.split():
            if not arg.strip():
                continue
            yield arg

    my_parser = argparse.ArgumentParser(
        prog=__prog__,
        description=__doc__,
        conflict_handler="resolve",
        fromfile_prefix_chars="@",
    )
    my_parser.convert_arg_line_to_args = convert_arg_line_to_args
    my_parser.add_argument(
        "InputFile", help="Input JSON sub region descriptor filename."
    )
    my_parser.add_argument(
        "-o", "--output", dest="OutputCapsuleFile",
        help="Output capsule filename."
    )
    my_parser.add_argument(
        "-s",
        "--signer-private-cert",
        dest="OpenSslSignerPrivateCertFile",
        help="OpenSSL signer private certificate filename.",
    )
    my_parser.add_argument(
        "-p",
        "--other-public-cert",
        dest="OpenSslOtherPublicCertFile",
        help="OpenSSL other public certificate filename.",
    )
    my_parser.add_argument(
        "-t",
        "--trusted-public-cert",
        dest="OpenSslTrustedPublicCertFile",
        help="OpenSSL trusted public certificate filename.",
    )
    my_parser.add_argument(
        "--signing-tool-path",
        dest="SigningToolPath",
        help="Path to signtool or OpenSSL tool. "
             " Optional if path to tools are already in PATH.",
    )
    return my_parser


if __name__ == "__main__":
    parser = create_arg_parser()
    args = parser.parse_args()

    sub_region_fv_file = os.path.join(os.path.curdir, "SubRegionFv.fv")
    sub_region_image_file = os.path.join(os.path.curdir, "SubRegionImage.bin")
    sub_region_desc = subrgn_descrptr.SubRegionDescriptor()
    sub_region_desc.parse_json_data(args.InputFile)
    generate_sub_region_fv(sub_region_image_file, sub_region_desc,
                           sub_region_fv_file)

    gen_cap_cmd = ["python", EDK2_CAPSULE_TOOL]
    gen_cap_cmd += ["--encode"]
    gen_cap_cmd += ["--guid", sub_region_desc.s_fmp_guid]
    gen_cap_cmd += ["--fw-version", str(sub_region_desc.version)]
    gen_cap_cmd += ["--lsv", "0"]
    gen_cap_cmd += ["--capflag", "PersistAcrossReset"]
    gen_cap_cmd += ["--capflag", "InitiateReset"]
    gen_cap_cmd += ["-o", args.OutputCapsuleFile]
    gen_cap_cmd += ["--signer-private-cert", args.OpenSslSignerPrivateCertFile]
    gen_cap_cmd += ["--other-public-cert", args.OpenSslOtherPublicCertFile]
    gen_cap_cmd += ["--trusted-public-cert", args.OpenSslTrustedPublicCertFile]
    gen_cap_cmd += ["-v"]

    if args.SigningToolPath is not None:
        gen_cap_cmd += ["--signing-tool-path", args.SigningToolPath]
    gen_cap_cmd += [sub_region_fv_file]

    status = utils.execute_cmds(logger, [gen_cap_cmd])

    # Creating list of files to remove
    to_remove = glob.glob("tmp.*")
    to_remove.extend(glob.glob("SubRegionFv.*"))
    to_remove.append("SubRegionImage.bin")

    utils.cleanup(to_remove)

    sys.exit(status)
