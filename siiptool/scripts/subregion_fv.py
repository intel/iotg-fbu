#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2020, Intel Corporation. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#

"""A utility to generate UEFI sub-region FV images
"""


import sys
import os
import argparse
import glob

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import scripts.subregion_capsule as capsule_tool
import common.subregion_descriptor as subrgn_descrptr
import common.utilities as utils
from common.siip_constants import VERSION as __version__
from common.banner import banner
import common.logger as logging

logger = logging.getLogger("subregion_fv")

if sys.version_info < (3, 6):
    raise Exception("Python 3.6 is the minimal version required")

#
# Globals for help information
#
__prog__ = "subregion_fv"

TOOLNAME = "Sub-Region FV Tool"

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
        "-o", "--output", dest="OutputFvFile",
        required=True,
        help="Output FV filename."
    )

    return my_parser


if __name__ == "__main__":

    banner(TOOLNAME, __version__)
    
    parser = create_arg_parser()
    args = parser.parse_args()

    sub_region_desc = subrgn_descrptr.SubRegionDescriptor()
    sub_region_desc.parse_json_data(args.InputFile)
    capsule_tool.logger = logger
    capsule_tool.generate_sub_region_fv(None, sub_region_desc, args.OutputFvFile)


    # Creating list of files to remove
    to_remove = glob.glob("tmp.*")
    to_remove.extend(glob.glob(args.OutputFvFile+".*"))
    to_remove.append("SubRegionImage.bin")

    utils.cleanup(to_remove)

