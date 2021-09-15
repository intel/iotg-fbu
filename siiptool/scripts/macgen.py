#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2021, Intel Corporation. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#

"""A helper script to simplify MAC address capsule
"""


import sys
import os
import argparse
import glob
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import scripts.subregion_capsule as capsule_tool
import common.subregion_descriptor as subrgn_descrptr
import common.subregion_image as image
import common.utilities as utils
from common.siip_constants import VERSION as __version__
from common.banner import banner
import common.logger as logging

logger = logging.getLogger("macgen")

if sys.version_info < (3, 6):
    raise Exception("Python 3.6 is the minimal version required")

#
# Globals for help information
#
__prog__ = "macgen"

TOOLNAME = "MAC Sub-Region helper Tool"

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
        "DevMac",
        help="dev:mac",
        nargs="*",
        type=str,
    )
    my_parser.add_argument(
        "-o", "--output", dest="Output_Capsule_File",
        help="Output Capsule filename.",
        default="tsnMacCapsule.bin",
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


def build_tsn_mac_address_descreiptor(descriptor, dev_mac_pairs):

    def hex_to_bin(hex, bits):
        binVal = bin(int(hex, 16))[2:].zfill(bits)
        if len(binVal) > bits:
            raise ValueError('Out of range')
        return binVal


    descriptor.fmp_guid = subrgn_descrptr.FMP_CAPSULE_TSN_MAC_ADDRESS_FILE_GUID
    descriptor.s_fmp_guid = (str) (subrgn_descrptr.FMP_CAPSULE_TSN_MAC_ADDRESS_FILE_GUID)
    descriptor.version = 1
    descriptor.s_fv_guid = "1A803C55-F034-4E60-AD9E-9D3F32CE273C"
    descriptor.fv_guid = uuid.UUID(descriptor.s_fv_guid)
    ffs_guid = "12E29FB4-AA56-4172-B34E-DD5F4B440AA9"
    descriptor.ffs_files = []
    data = []

    data.append(["Version", "DECIMAL", 4, 1])
    data.append(["NumPorts", "DECIMAL", 4, len(dev_mac_pairs)])

    for arg in dev_mac_pairs:

        try:
            dm = arg.split(':')
            if len(dm) != 2: # BDF and MAC address must be provided
                raise ValueError('Wrong argument format')

            bdf = dm[0].split('.')
            if len(bdf) != 3: # All 3 parts of BDF must be provided
                raise ValueError('Wrong BDF format')

            hexBus, hexDev, hexFun = bdf
            mac = dm[1]
            if len(mac) != 12: # MAC address must be 12 digits
                raise ValueError('Wrong MAC length')

            binMac = hex_to_bin(mac, 48) # MAC address must be valid Hexa digits
            if binMac.endswith('1'): # Validate MAC address is Unicast not multicast/broadcast
                raise ValueError('Invalid MAC Address, ends with odd number, unicast/multicast bit must be zero')

            # Validate MAC address is not from the invalid list
            invallid_list = [
                '000000000000',
                'FFFFFFFFFFFF'
            ]
            if mac in invallid_list:
                raise ValueError('Invalid MAC Address, from the invalid list {}'.format(invallid_list))          

            # Validate all values are numeric and within range
            binBus = hex_to_bin(hexBus, 8) # 8 bit binary
            binDev = hex_to_bin(hexDev, 5) # 5 bit binary
            binFun = hex_to_bin(hexFun, 3) # 3 bit binary
        except ValueError as error:
            print("{}: {}".format(error,arg))
            exit(2)
            

        binBdf = "0000{bus}{dev}{fun}000000000000".format(bus = binBus, dev = binDev, fun = binFun)

        hexBdf = hex(int(binBdf, 2))[2:].zfill(8)
        print("BDF: {}".format(hexBdf))

        macLow = mac[-8:].upper()
        print("MacLow: {}".format(macLow))

        macHigh = mac[:-8].zfill(8).upper()
        print("MacHigh: {}".format(macHigh))

        data.append( ["BDF",            "HEXADECIMAL",  4, hexBdf   ])
        data.append( ["MacAddressLow",  "HEXADECIMAL",  4, macLow   ])
        data.append( ["MacAddressHigh", "HEXADECIMAL",  4, macHigh  ])
        
    ffs_file = subrgn_descrptr.SubRegionFfsFile(ffs_guid, False, data)

    descriptor.ffs_files.append(ffs_file)


if __name__ == "__main__":

    banner(TOOLNAME, __version__)
        
    parser = create_arg_parser()
    args = parser.parse_args()

    desc = subrgn_descrptr.SubRegionDescriptor()
    build_tsn_mac_address_descreiptor(desc, args.DevMac)
    capsule_tool.generate_sub_region_capsule(desc, args.Output_Capsule_File, args.SigningToolPath,
     args.OpenSslSignerPrivateCertFile, args.OpenSslOtherPublicCertFile, args.OpenSslTrustedPublicCertFile )
        


