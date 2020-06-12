#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2020, Intel Corporation. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#

"""A signing utility for creating and signing a BIOS sub-region for UEFI
"""


from __future__ import print_function

import os
import sys
import subprocess
import argparse
import uuid
import struct
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common.banner import banner
from common.siip_constants import IP_OPTIONS
import common.utilities as utils
import common.logging as logging

LOGGER = logging.getLogger("subregion_sign")

__prog__ = "subregion_sign"
__version__ = "0.7.5"

TOOLNAME = "Sub-Region Signing Tool"

banner(TOOLNAME, __version__)

if sys.version_info < (3, 6):
    raise Exception("Python 3.6 is the minimal version required")


class EfiSubregAuthenClass():
    """ Class define EFI subreation Authentication class """

    # typedef struct {
    #  CERTIFICATE   Hdr;
    #  EFI_GUID     CertType;
    #  } CERTIFICATE_UEFI_GUID

    # typedef struct {
    #    UINT32  dwLength;
    #    UINT16  wRevision;
    #    UINT16  wCertificateType;
    #  } CERTIFICATE;

    _StructFormat = "<LHH16s"
    _StructSize = struct.calcsize(_StructFormat)

    _StructAuthInfoFormat = "<LHH16s"
    _StructAuthInfoSize = struct.calcsize(_StructAuthInfoFormat)

    def __init__(self, cert_info):
        """ intilization variables for structure """

        self._valid = False
        self.dw_length = self._StructAuthInfoSize
        self.w_revision = cert_info["revision"]
        self.w_certificate_type = cert_info["win_cert_type"]
        self.cert_type = cert_info["guid_cert_type"]
        self.cert_data = bytes()
        self.payload = bytes()

    def encode(self):
        """ builds structure for subregion authentication header """

        self.dw_length = self._StructAuthInfoSize + len(self.cert_data)

        efi_subreg_authen_hdr = struct.pack(
            self._StructFormat,
            self.dw_length,
            self.w_revision,
            self.w_certificate_type,
            self.cert_type.bytes_le,
        )
        self._valid = True

        return efi_subreg_authen_hdr + self.cert_data + self.payload

    def dump_info(self):
        """ dump the information of subregion authentication structure """

        if not self._valid:
            raise ValueError

        print(
            "EFI_SUBREGION_AUTHENTICATION.AuthInfo.Hdr.dw_length         = {dw_length:08X}".format(
                dw_length=self.dw_length
            )
        )
        print(
            "EFI_SUBREGION_AUTHENTICATION.AuthInfo.Hdr.w_revision        = {w_revision:04X}".format(
                w_revision=self.w_revision
            )
        )
        print(
            "EFI_SUBREGION_AUTHENTICATION.AuthInfo.Hdr.wCertificateType = {w_certificate_type:04X}"
            .format(w_certificate_type=self.w_certificate_type)
        )
        print(
            "EFI_SUBREGION_AUTHENTICATION.AuthInfo.cert_type             = {Guid}".format(
                Guid=str(self.cert_type).upper()
            )
        )
        print(
            "sizeof (EFI_SUBREGION_AUTHENTICATION.AuthInfo.cert_data)    = {Size:08X}".format(
                Size=len(self.cert_data)
            )
        )
        print(
            "sizeof (payload)                                                = {Size:08X}".format(
                Size=len(self.payload)
            )
        )


def get_certifcation_info(ipname):
    """ returns the certifcate type passed on subregion """

    win_cert_info = {
        "revision": 0x0200,
        "win_cert_type": 0x0EF1,
        "guid_cert_type": uuid.UUID("4aafd29d-68df-49ee-8aa9-347d375665a7"),
    }

    if ipname == "tcc":
        return win_cert_info

    # other regions will be supported once the design is approve and
    # implemented into BIOS (Amol desigh) Tcc design is implemented
    # in new version of BIOS (Curtis design)

    LOGGER.critical("%s is not supported at this time", ipname)
    sys.exit(2)


def build_subreg_signed_file(cert_struct, outfile):
    """ build output file """

    with open(outfile, mode="wb") as signed_file:
        signed_file.write(cert_struct)


def read_file(inputfile):
    """ read input file to bytes """

    try:
        with open(inputfile, mode="rb") as file:
            sign_file = file.read()

    except ValueError:
        LOGGER.critical(
            "\nsubregion_sign.py: can not read payload file: %s", inputfile
        )
        sys.exit(2)

    return sign_file


def generate_signature(tool_path, signerfile, certfile, subregion):
    """ signed input file """

    
    # Convert to absolute path for openSSL
    cert = os.path.abspath(certfile)
    signer = os.path.abspath(signerfile)
    
    

    # Check if openssl is installed
    path = utils.check_for_tool('openssl', 'version', tool_path)

    # Build openssl command to using sign to get signature
    openssl_cmd = f'{path} smime -sign -binary -outform DER -md sha256 -signer {signer} -certfile {cert}'
  
    #
    # Sign the input file using the specified private key and capture signature from STDOUT
    #
    try:
        ssl_process = subprocess.run(
            openssl_cmd,
            input=subregion,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True,
            check=True,
        )
        signature = ssl_process.stdout

    except ValueError:
        LOGGER.warning("\nsubregion_sign: can not run openssl.")
        sys.exit(1)

    if ssl_process.returncode != 0:
        LOGGER.critical("\nsubregion_sign: openssl failed.")
        sys.exit(1)

    return signature


def create_arg_parser():
    """ Parsing and validating input arguments."""

    def convert_arg_line_to_args(arg_line):
        for arg in arg_line.split():
            if not arg.strip():
                continue
            yield arg

    visible_ip_list = list(IP_OPTIONS.keys())
    visible_ip_list.remove("obb_digest")

    my_parser = argparse.ArgumentParser(
        prog=__prog__,
        description=__doc__,
        conflict_handler="resolve",
        fromfile_prefix_chars="@",
    )
    my_parser.convert_arg_line_to_args = convert_arg_line_to_args
    my_parser.add_argument(
        "subregion_file", help="sub region data that needs to be signed."
    )
    my_parser.add_argument(
        "-o",
        "--output",
        dest="signed_file",
        type=utils.file_not_exist,
        help="Output capsule filename.",
        metavar="Filename",
        default="SIGNED_OUT.bin",
    )
    my_parser.add_argument(
        "-ip",
        "--ipname",
        help="The name of the IP subregion to sign. This is required.",
        metavar="ipname",
        required=True,
        choices=visible_ip_list,
    )
    my_parser.add_argument(
        "-s",
        "--signer",
        dest="signerfile",
        required=True,
        help="OpenSSL signer private certificate filename.",
    )
    my_parser.add_argument(
        "-p",
        "--pubCert",
        dest="certfile",
        required=True,
        help="OpenSSL other public certificate filename.",
    )
    my_parser.add_argument(
        "--toolPath",
        dest="tool_path",
        help="Path to signtool or OpenSSL tool. "
        " Optional if path to tools are already in PATH.",
        default=None,
    )
    my_parser.add_argument(
        "--show",
        help="Shows information about the subregion_authentication structure "
        " Optional but requires all information in order to process.",
        action="store_true",
    )
    my_parser.add_argument(
        "-v",
        "--version",
        help="Shows the current version of the BIOS Stitching Tool",
        action="version",
        version="%(prog)s {version}".format(version=__version__),
    )
    return my_parser


def main():
    """Entry to script."""

    parser = create_arg_parser()
    args = parser.parse_args()

    cert_info = get_certifcation_info(args.ipname)

    efi_subreg_authen = EfiSubregAuthenClass(cert_info)

    # read input file to store into structure
    payload = read_file(args.subregion_file)
    efi_subreg_authen.payload = payload
    

    # Convert to absolute path for openSSL
    certfile = os.path.abspath(args.certfile)
    signerfile = os.path.abspath(args.signerfile)

    # calculate the signature store in structure
    cert_data = generate_signature(
        args.tool_path, args.signerfile, args.certfile, payload
    )
    efi_subreg_authen.cert_data = cert_data

    # pack structure with signature and get update size of header
    efi_signed_data = efi_subreg_authen.encode()

    if args.show:
        efi_subreg_authen.dump_info()

    # create output EFI subregion authentication header and signature and original file
    build_subreg_signed_file(efi_signed_data, args.signed_file)


if __name__ == "__main__":
    main()
