#!/usr/bin/env python
#
# Copyright (c) 2019, Intel Corporation. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#

"""A simple IFWI image parser"""

import sys
import uuid
from ctypes import Structure
from ctypes import c_char, c_uint32, c_uint8, c_uint64, c_uint16, sizeof, ARRAY
from functools import reduce

from common.firmware_volume import FirmwareDevice


class SPI_DESCRIPTOR(Structure):
    DESC_SIGNATURE = 0x0FF0A55A
    FLASH_REGIONS = {
        "descriptor": 0x00,
        "bios": 0x04,
        "txe": 0x08,
        "gbe": 0x0C,
        "pdr": 0x10,
        "dev_expansion": 0x14,
    }
    _pack_ = 1
    _fields_ = [
        ("reserved", ARRAY(c_char, 16)),
        ("fl_val_sig", c_uint32),
        ("fl_map0", c_uint32),
        ("fl_map1", c_uint32),
        ("fl_map2", c_uint32),
        ("remaining", ARRAY(c_char, 0x1000 - 0x20)),
    ]


class IFWI_IMAGE:
    def __init__(self, filename):
        self.region_list = []
        with open(filename, "rb") as fd:
            self.data = bytearray(fd.read())
        self.spi_desc = SPI_DESCRIPTOR.from_buffer(self.data)

    def is_ifwi_image(self):
        return self.spi_desc.fl_val_sig == self.spi_desc.DESC_SIGNATURE

    def find_ifwi_region(self, rgn_name):
        frba = ((self.spi_desc.fl_map0 >> 16) & 0xFF) << 4
        fl_reg = self.spi_desc.FLASH_REGIONS[rgn_name] + frba
        rgn_off = c_uint32.from_buffer(self.spi_desc, fl_reg)
        rgn_base = (rgn_off.value & 0x7FFF) << 12
        rgn_limit = ((rgn_off.value & 0x7FFF0000) >> 4) | 0xFFF
        if rgn_limit <= rgn_base:
            return None, None
        else:
            return (rgn_base, rgn_limit)

    def parse_bios_region(self):
        pass

    def parse(self):
        if len(self.data) < 0x1000:
            return None

        rgn_dict = sorted(
            SPI_DESCRIPTOR.FLASH_REGIONS, key=SPI_DESCRIPTOR.FLASH_REGIONS.get
        )
        for rgn in rgn_dict:
            rgn_start, rgn_limit = self.find_ifwi_region(rgn)
            if rgn_start is None:
                continue
            print(
                "Found region {}: off {:x} len {:x}".format(
                    rgn, rgn_start, rgn_limit + 1 - rgn_start
                )
            )
            self.region_list.append((rgn, rgn_start, rgn_limit))


def main():

    # Sample code
    ifwi = IFWI_IMAGE(sys.argv[1])
    if not ifwi.is_ifwi_image():
        print("Bad IFWI image")
        exit(1)

    ifwi.parse()
    bios_start = ifwi.region_list[1][1]
    bios_limit = ifwi.region_list[1][2]

    print("Parsing BIOS ...")
    bios = FirmwareDevice(0, ifwi.data[bios_start : bios_limit + 1])
    bios.ParseFd()


if __name__ == "__main__":
    sys.exit(main())
