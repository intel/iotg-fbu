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
import re
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common.siip_constants import VERSION as __version__
from common.banner import banner
import common.utilities as utils
import common.logger as logging

LOGGER = logging.getLogger("subregion_sign")

__prog__ = "subregion_sign"

TOOLNAME = "Sub-Region Signing Tool"

banner(TOOLNAME, __version__)

if sys.version_info < (3, 6):
    raise Exception("Python 3.6 is the minimal version required")


class UefiSubregAuthenClass:
    """ Class define EFI subreation Authentication class """

    # typedef struct {
    # char                       Name[16 bytes]; // Name of the sub-region
    # EFI_GUID                   VendorGuid;    // Vendor GUID
    # SUB_REGION_VERIFICATION    CertParam;    // Sub-Region Certificate Parameters
    # } EFI_SUB_REGION_AUTHENTICATION;

    # typedef struct {
    # SUB_REGION_HEADER  Hdr;             // Certificate Header
    # UINT8              CertData[1];    // Calculated Signature
    # } SUB_REGION_VERIFICATION;

    # typedef struct {
    # UINT32     Revision;        // Revision of Signature Structure
    # UINT32     Length;          // Length of the Signature + Header
    # EFI_GUID   CertType;         // Signature type
    # } SUB_REGION_HEADER;

    # typedef struct {
    # UINT8     PublicKey[384];  // Public Key pair of the Signing Key
    # UINT8     Signature[384];   // SHA384-RSA3K Signature
    # } EFI_CERT_BLOCK_RSA3072_SHA384;

    _StructAuthInfoFormat = "<16s16sLL16s"
    _StructAuthInfoSize = struct.calcsize(_StructAuthInfoFormat)
    _StructSubRegionHdrFormat = "<LL16s"
    _StructSubRegionHdrSize = struct.calcsize(_StructSubRegionHdrFormat)

    def __init__(self, cert_info):
        """ initialization of the variables for structure """

        self._valid = False
        self.w_name = cert_info["name"]
        self.vendor_guid = cert_info["vendor_guid"]
        self.w_revision = cert_info["revision"]
        self.dw_length = self._StructAuthInfoSize
        self.cert_type = cert_info["cert_type"]
        self.cert_data = bytes()
        self.payload = bytes()

    def encode(self):
        """ builds structure for subregion authentication header """

        self.dw_length = self._StructSubRegionHdrSize + len(self.cert_data)

        uefi_subreg_authen_hdr = struct.pack(
            self._StructAuthInfoFormat,
            self.w_name,
            self.vendor_guid.bytes_le,
            self.w_revision,
            self.dw_length,
            self.cert_type.bytes_le,
        )
        self._valid = True

        return uefi_subreg_authen_hdr + self.cert_data + self.payload

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
            "EFI_SUBREGION_AUTHENTICATION.AuthInfo.Hdr.wCertificateType = {Vendor_guid}".format(
                Vendor_guid=str(self.vendor_guid).upper()
            )
        )
        print(
            "EFI_SUBREGION_AUTHENTICATION.AuthInfo.cert_type             = {cert_type}".format(
                cert_type=str(self.cert_type).upper()
            )
        )
        print(
            "sizeof (EFI_SUBREGION_AUTHENTICATION.AuthInfo.cert_data)    = {Size:08X}".format(
                Size=len(self.cert_data)
            )
        )
        print(
            "sizeof (payload)                                             = {Size:08X}".format(
                Size=len(self.payload)
            )
        )


def get_certifcation_info(cl_inputs, signer):
    """ returns the certifcate type passed on subregion """

    # different signature type supported by tool
    CERT_TYPE = {
        "pkcs7": [
            "4aafd29d-68df-49ee-8aa9-347d375665a7",
            "smime -sign -binary -outform DER -md sha256 -nodetach -signer",
            None,
        ],
        "rsa": [
            "2ee9976f-9d4c-4442-a997-8cad1c875fa1",
            "dgst -binary -keyform PEM -sha384 -sign",
            "rsa -pubout -modulus -noout",
        ],
    }

    # Check if openssl is installed
    path = utils.check_for_tool("openssl", "version", cl_inputs.tool_path)

    # Get signing type information
    cert_info = CERT_TYPE.get(cl_inputs.signer_type)

    # Create openSSL command 1
    cmd = f"{path} {cert_info[1]} {signer}"

    # Create openSSL command 2
    if cert_info[2] is not None:
        cmd2 = f"{path} {cert_info[2]}"
    else:
        cmd2 = cert_info[2]

    certification_info = {
        "revision": 0x01,
        "name": cl_inputs.name.encode("utf-8"),
        "vendor_guid": uuid.UUID(cl_inputs.vendor_guid),
        "cert_type": uuid.UUID(cert_info[0]),
        "openssl_cmd": cmd,
        "openssl_cmd2": cmd2,
    }

    return certification_info


def build_subreg_signed_file(cert_struct, outfile):
    """ build output file """

    try:
        with open(outfile, mode="wb") as signed_file:
            signed_file.write(cert_struct)

    except ValueError:
        LOGGER.critical("\nCannot write payload file: %s", outfile)
        sys.exit(2)


def read_file(inputfile):
    """ read input file to bytes """

    try:
        with open(inputfile, mode="rb") as file:
            sign_file = file.read()

    except ValueError:
        LOGGER.critical("\nCannot read payload file: %s", inputfile)
        sys.exit(2)

    return sign_file


def generate_signature(openssl_cmd, payload):
    """ signed input file """

    # Run OpenSSL command with the specified private key and capture signature from STDOUT

    try:
        ssl_process = subprocess.run(
            openssl_cmd,
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True,
            check=True,
        )
        signature = ssl_process.stdout

    except:
        LOGGER.warning("\nCannot run openssl.")
        sys.exit(1)

    if ssl_process.returncode != 0:
        LOGGER.critical("\nopenssl failed.")
        sys.exit(1)

    return signature


def create_arg_parser():
    """ Parsing and validating input arguments."""

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
        "subregion_file", help="sub region data that needs to be signed."
    )
    my_parser.add_argument(
        "-o",
        "--output",
        dest="signed_file",
        help="Output capsule filename.",
        metavar="Filename",
        default="SIGNED_OUT.bin",
    )
    my_parser.add_argument(
        "-n",
        "--name",
        help="The name of the subregion being signed. Max size is 16 bytes The name is stored in signed file.",
        type=chk_string_size,
        metavar="subregion",
        required=True,
    )
    my_parser.add_argument(
        "-vg",
        "--vendor-guid",
        help="Vender GUID is one specific value given by the vendor for the sub-region being signed.\
        This is required. The format is '00000000-0000-0000-0000-000000000000'",
        type=chk_guid_format,
        metavar="v_guid",
        required=True,
    )
    my_parser.add_argument(
        "-t",
        "--signer_type",
        metavar="sign_type",
        required=True,
        help="Type of Signing pkcs7 or rsa.",
        choices=["pkcs7", "rsa"],
    )
    my_parser.add_argument(
        "-s",
        "--signer",
        dest="signerfile",
        required=True,
        help="OpenSSL signer private certificate filename.",
    )
    my_parser.add_argument(
        "--toolpath",
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


def chk_string_size(string):
    """"Check the size of the string"""

    max_size = 16
    size = len(string.encode("utf-8"))

    msg = "The size of {} is {}. The {} size must not be greter than {}".format(
        string, size, string, max_size
    )
    if size > max_size:
        raise argparse.ArgumentTypeError(str(msg))
    return string


def chk_guid_format(guid):
    """ check for correct formate of GUID """

    # format for guid xxxxxxxx-xxxx-xxxx-xxx-xxxxxxxxxxxx where x can be A-F or 0-9
    guidFormat = re.compile(
        r"([a-f\d]{8}[-][a-f\d]{4}[-][a-f\d]{4}[-][a-f\d]{4}[-]{1}[a-f\d]{12}$)", re.I
    )

    if guidFormat.match(guid) is None:
        raise argparse.ArgumentTypeError(
            "File guild value is not in correct format \
                                       (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx where x can be A-F or 0-9)\
                                       {}".format(guid)
        )
    return guid


def main():
    """Entry to script."""

    parser = create_arg_parser()
    args = parser.parse_args()

    # Use absolute path for openSSL
    sbrgn_file = Path(args.subregion_file).resolve()
    signer_file = Path(args.signerfile).resolve()
    outfile = Path(args.signed_file).resolve()

    filenames = [str(sbrgn_file), str(signer_file)]

    # Verify file input file exist
    status = utils.file_exist(filenames, LOGGER)
    if status != 0:
        sys.exit(status)

    if os.path.getsize(sbrgn_file) == 0:
        LOGGER.critical("size of {} subregion file must be greater than 0!".format(sbrgn_file))
        sys.exit(status)

    status = utils.check_key(signer_file, args.signer_type, LOGGER)
    if status != 0:
        sys.exit(status)

    outfile = utils.file_not_exist(outfile, LOGGER)

    cert_info = get_certifcation_info(args, signer_file)

    uefi_subreg_authen = UefiSubregAuthenClass(cert_info)

    # read input file to store into structure
    payload = read_file(sbrgn_file)
    uefi_subreg_authen.payload = payload

    # add Vendor Guid to Payload
    payload = uefi_subreg_authen.vendor_guid.bytes_le + payload

    # calculate the signature store in structure
    cert_data = generate_signature(cert_info["openssl_cmd"], payload)

    if cert_info["openssl_cmd2"]:
        # Read in the private key
        payload = read_file(signer_file)

        # Extract the public key modulus from private key
        cert_pub = generate_signature(cert_info["openssl_cmd2"], payload)

        # convert public key from bytes to string
        cert_pub_string = cert_pub.decode("utf-8")

        # remove word Moudlus= from the file
        cert_pubkey = cert_pub_string.replace("Modulus=", "")

        # remove end of line from public key
        cert_pubkey = cert_pubkey.rstrip()

        # Conert to hex bytes and add to signature
        cert_pubkey = bytes.fromhex(cert_pubkey)

        # public key and signature are packed back to back
        cert_data = cert_pubkey + cert_data

    uefi_subreg_authen.cert_data = cert_data

    # pack structure with signature and get update size of header
    uefi_signed_data = uefi_subreg_authen.encode()

    if args.show:
        uefi_subreg_authen.dump_info()

    # Create output EFI subregion authentication header and signature and original file
    build_subreg_signed_file(uefi_signed_data, str(outfile))

    print(
        "Signed {} sub-region({}) was successfully generated.".format(
            args.name, outfile
        )
    )


if __name__ == "__main__":
    main()
