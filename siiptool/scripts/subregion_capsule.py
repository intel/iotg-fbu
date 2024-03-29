#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2020, Intel Corporation. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#

"""A capsule image utility to generate UEFI sub-region capsule images
"""


import sys
import os
import argparse
import glob
import subprocess

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common.subregion_descriptor as subrgn_descrptr
import common.subregion_image as sbrgn_image
import common.utilities as utils
import thirdparty.edk2_capsule_tool.GenerateCapsule as generate_capsule_tool
from common.siip_constants import VERSION as __version__
from common.banner import banner
import common.logger as logging
from scripts.subregion_sign import sign_subregion

logger = logging.getLogger("subregion_capsule")

if sys.version_info < (3, 6):
    raise Exception("Python 3.6 is the minimal version required")

#
# Globals for help information
#
__prog__ = "subregion_capsule"

TOOLNAME = "Sub-Region Capsule Tool"

def generate_sub_region_fv(
        sub_region_descriptor,
        output_fv_file=os.path.join(os.path.curdir, "SubRegion.FV")
):

    sub_region_image = "SubRegionImage.bin"
    signed_sub_region_image = "SignedSubRegionImage.bin"
    fv_ffs_file_list = []

    for file_index, ffs_file in enumerate(sub_region_descriptor.ffs_files):

        sbrgn_image.generate_sub_region_image(ffs_file, sub_region_image)
        ip, ip_ops = sbrgn_image.ip_info_from_guid(ffs_file.ffs_guid)

        if ffs_file.signing_key is not None:
            sign_subregion(sub_region_image, ffs_file.signing_key, signed_sub_region_image,
             ffs_file.signer_type, ip, ffs_file.vendor_guid)
            sub_region_image = signed_sub_region_image

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
        required=True,
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


def generate_sub_region_capsule( sub_region_desc,
        outputCapsuleFile=os.path.join(os.path.curdir, "capsule.bin"),
        signingToolPath = None,
        OpenSslSignerPrivateCertFile = None,
        OpenSslOtherPublicCertFile = None,
        OpenSslTrustedPublicCertFile = None
    ):
        
    sub_region_fv_file = os.path.join(os.path.curdir, "SubRegionFv.fv")

    if OpenSslSignerPrivateCertFile is None:
        OpenSslSignerPrivateCertFile = sub_region_desc.signer_prv_cert_file
    if OpenSslOtherPublicCertFile is None:
        OpenSslOtherPublicCertFile = sub_region_desc.other_pub_cert_file
    if OpenSslTrustedPublicCertFile is None:
        OpenSslTrustedPublicCertFile = sub_region_desc.trusted_pub_cert_file

    gen_cap_args = []
    if all(
            [
                OpenSslSignerPrivateCertFile,
                OpenSslOtherPublicCertFile,
                OpenSslTrustedPublicCertFile
            ]
    ):
        
        # Check if openssl is installed or at given path
        utils.check_for_tool('openssl', 'version', tool_path=signingToolPath)
        gen_cap_args += ["--signer-private-cert", OpenSslSignerPrivateCertFile]
        gen_cap_args += ["--other-public-cert", OpenSslOtherPublicCertFile]
        gen_cap_args += ["--trusted-public-cert", OpenSslTrustedPublicCertFile]
    elif any(
            [
                OpenSslSignerPrivateCertFile,
                OpenSslOtherPublicCertFile,
                OpenSslTrustedPublicCertFile
            ]
    ):
        print('All-or-none of the certificate files must be provided.')
        return 2
        
    generate_sub_region_fv(sub_region_desc, sub_region_fv_file)

    gen_cap_args += ["--encode"]
    gen_cap_args += ["--guid", sub_region_desc.s_fmp_guid]
    gen_cap_args += ["--fw-version", str(sub_region_desc.version)]
    gen_cap_args += ["--lsv", "0"]
    gen_cap_args += ["--capflag", "PersistAcrossReset"]
    gen_cap_args += ["--capflag", "InitiateReset"]
    gen_cap_args += ["-o", outputCapsuleFile]
    gen_cap_args += ["-v"]

    if signingToolPath is not None:
        gen_cap_args += ["--signing-tool-path", os.path.abspath(signingToolPath)]
    gen_cap_args += [sub_region_fv_file]

    status = generate_capsule_tool.generate_capsule(gen_cap_args)

    # Creating list of files to remove
    to_remove = glob.glob("tmp.*")
    to_remove.extend(glob.glob("SubRegionFv.*"))
    to_remove.append("SubRegionImage.bin")
    to_remove.append("SignedSubRegionImage.bin")

    utils.cleanup(to_remove)

    return status


if __name__ == "__main__":

    banner(TOOLNAME, __version__)
    
    parser = create_arg_parser()
    args = parser.parse_args()
    
    sub_region_desc = subrgn_descrptr.SubRegionDescriptor()
    sub_region_desc.parse_json_data(args.InputFile)
    status = generate_sub_region_capsule (sub_region_desc, args.OutputCapsuleFile, args.SigningToolPath,
     args.OpenSslSignerPrivateCertFile, args.OpenSslOtherPublicCertFile, args.OpenSslTrustedPublicCertFile )
    sys.exit(status)
