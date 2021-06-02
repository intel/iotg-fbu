# @file
# Converts Sub Regions JSON into binary image
#
# Copyright (c) 2019, Intel Corporation. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
from io import open
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import subregion_descriptor as subrgn_descptr
from common.utilities import get_key_and_value
from common.tools_path import GENFV, GENFFS, GENSEC, LZCOMPRESS, IP_OPTIONS_CFG

##############################################################################
#
# Gets the options needed to create commands to replace the ip
#
# The Each List represents a command that needs to be created to replace the
#  given IP
# The following list is for GenSec.exe
# 'ui' creates EFI_SECTION_USER_INTERFACE
# 'raw' creates EFI_SECTION_RAW
# None creaetes EFI_SECTION_ALL that does not require a section header
# 'guid' creates EFI_SECTION_GUID_DEFINED
# 'pe32' creates EFI_SECTION_PE32
# 'depex' creates EFI_SECTION_PEI_DEPEX
# 'cmprs' creates EFI_SECTION_COMPRESSION
#
# 'lzma' calls the LzmaCompress
#
# The following list is for GenFfs.exe
# 'free' creates EFI_FV_FILETYPE_FREEFORM
# 'gop' creates EFI_FV_FILETYPE_DRIVER
# 'peim' creates EFI_FV_FILETYPE_PEIM
##############################################################################
# gets the section type needed for gensec.exe
GENSEC_SECTION = {
    "ui": ["tmp.ui", "-s", "EFI_SECTION_USER_INTERFACE", "-n"],
    "raw": ["tmp.raw", "-s", "EFI_SECTION_RAW", "-c"],
    "guid": ["tmp.guid", "-s", "EFI_SECTION_GUID_DEFINED", "-g"],
    "pe32": ["tmp.pe32", "-s", "EFI_SECTION_PE32"],
    "depex": ["tmp.dpx", "-s", "EFI_SECTION_PEI_DEPEX"],
    "cmprs": ["tmp.cmps", "-s", "EFI_SECTION_COMPRESSION", "-c"]
}

# gets the firmware file system type needed for genFFs
FFS_FILETYPE = {
    "free": "EFI_FV_FILETYPE_FREEFORM",
    "dxe": "EFI_FV_FILETYPE_DRIVER",
    "peim": "EFI_FV_FILETYPE_PEIM",
}

with open(IP_OPTIONS_CFG) as ip_options_config_file:
    ip_options = json.load(ip_options_config_file)

# Translate IP_OPTIONS dict into a GUID-to-NAME lookup dict
section_name_lookup_table = {
    option[-1][1]: option[0][1] for option in ip_options.values()}


def ip_info_from_guid(lookup_val):
    """ returns the key and corresponding value """
    return get_key_and_value(ip_options, lookup_val, [-1, 1])


def guid_section(sec_type, guid, guid_attrib, inputfile):
    """ generates the GUID defined section """
    cmd = ["tmp.guid", "-s", "EFI_SECTION_GUID_DEFINED", "-g"]
    cmd += [guid, "-r", guid_attrib, inputfile]
    return cmd


def generate_section(inputfiles, align_sizes):
    """ generates the all section """

    cmd = ["tmp.all"]

    for index, file in enumerate(inputfiles):
        cmd += [file]
        if align_sizes != [None]:
            # the first input is None
            cmd += ["--sectionalign", align_sizes[index + 1]]
    return cmd


def create_gensec_cmd(cmd_options, inputfile):
    """Create genSec commands for the merge and replace of firmware section."""

    cmd = [GENSEC, "-o"]

    if cmd_options[0] == "guid":
        sec_type, guid, attrib = cmd_options
        cmd += guid_section(sec_type, guid, attrib, inputfile[0])
        # EFI_SECTION_RAW, EFI_SECTION_PE32, EFI_SECTION_COMPRESSION or
        # EFI_SECTION_USER_INTERFACE
    elif cmd_options[0] is not None:
        sec_type, option = cmd_options
        cmd += GENSEC_SECTION.get(sec_type)
        if option is not None:
            cmd += [option]
        if sec_type != "ui":
            cmd += [inputfile[0]]
    else:
        cmd += generate_section(inputfile, cmd_options)
    return cmd


def compress(compress_method, inputfile):
    """ compress the sections """

    cmd = [LZCOMPRESS, compress_method, "-o", "tmp.cmps", inputfile]
    return cmd


def create_ffs_cmd(filetype, guild, align, inputfile):
    """ generates the firmware volume according to file type"""

    fv_filetype = FFS_FILETYPE.get(filetype)
    cmd = [GENFFS, "-o", "tmp.ffs", "-t", fv_filetype, "-g",
           guild, "-i", inputfile]
    if align is not None:
        cmd += ["-a", align]
    return cmd


def ip_inputfiles(filenames, ipname):
    """Create input files per IP"""

    inputfiles = [None, "tmp.raw", "tmp.ui", "tmp.all"]

    num_infiles = 1
    if ipname in ["pse", "fkm", "tccp"]:
        inputfiles.extend(["tmp.cmps", "tmp.guid"])
    elif ipname in ["gop", "gfxpeim", "undi"]:
        inputfiles.remove("tmp.raw")
        inputfiles.insert(1, "tmp.pe32")
        if ipname == "gfxpeim":
            inputfiles.append("tmp.cmps")

    # add user given input files
    infiles = filenames[1:num_infiles + 1]
    inputfiles[1:1] = infiles

    return inputfiles, num_infiles


def build_command_list(build_list, inputfiles, num_replace_files):
    """ Builds command list for firmware files system """

    cmd_list = []

    for instr in build_list:
        if GENSEC_SECTION.get(instr[0]) or instr[0] is None:
            files = [inputfiles.pop(0)]
            if instr[0] is None:
                for _ in range(num_replace_files):
                    files += [inputfiles.pop(0)]
            cmd = create_gensec_cmd(instr, files)
        elif instr[0] == "lzma":
            cmd = compress(instr[1], inputfiles.pop(0))
        elif FFS_FILETYPE.get(instr[0]):
            filetype, guild, align = instr
            cmd = create_ffs_cmd(filetype, guild, align, inputfiles.pop(0))
        else:
            sys.exit("unexpected error from create_command function")

        cmd_list.append(cmd)

    return cmd_list


def build_fv_from_ffs_files(sub_region_desc, out_file, ffs_file_list):
    """ Build FV file with multi firmware file syste """

    fv_cmd_list = []
    for file_index, file in enumerate(ffs_file_list):
        if file_index > 0:
            # Use other files just add with file input option in the same command;
            fv_cmd += ["-f", file]
        else:
            fv_cmd = create_gen_fv_command(sub_region_desc.s_fv_guid, out_file, file)

    fv_cmd_list.append(fv_cmd)

    return fv_cmd_list


def create_gen_fv_command(fv_guid, output_fv_file, ffs_file, input_fv_file=None,):
    gen_fv_cmd = [GENFV]
    if input_fv_file is not None:
        gen_fv_cmd += ["-i", input_fv_file]
    gen_fv_cmd += ["-o", output_fv_file]
    gen_fv_cmd += ["-b", "0x1000"]
    gen_fv_cmd += ["-f", ffs_file]
    gen_fv_cmd += [
        "-g",
        "8C8CE578-8A3D-4F1C-9935-896185C32DD3",
    ]  # gEfiFirmwareFileSystem2Guid
    gen_fv_cmd += ["--FvNameGuid", fv_guid]
    return gen_fv_cmd


def create_buffer_from_data_field(data_field):
    buffer = None
    if data_field.Type == subrgn_descptr.data_types.FILE:
        if data_field.ByteSize == 0:   # Read the whole file
            with open(data_field.Value, "rb") as DataFile:
                buffer = DataFile.read()
        else:
            buffer = bytearray(data_field.ByteSize)  # Allocate the buffer
            with open(data_field.Value, "rb") as DataFile:
                tmp = DataFile.read(data_field.ByteSize)
            buffer[:len(tmp)] = tmp  # copy data to the beginning of the buffer

    if data_field.Type == subrgn_descptr.data_types.STRING:
        fmt = "{}s".format(data_field.ByteSize)
        if data_field.Value == "_STDIN_":
            buffer = struct.pack(fmt, bytes(sys.stdin.readline(), "utf-8"))
        else:
            buffer = struct.pack(fmt, bytes(data_field.sValue, "utf-8"))

    if data_field.Type in [subrgn_descptr.data_types.DECIMAL,
                           subrgn_descptr.data_types.HEXADECIMAL]:
        buffer = data_field.dValue.to_bytes(data_field.ByteSize, "little")

    return buffer


def generate_sub_region_image(ffs_file, output_file="./output.bin"):
    with open(output_file, "wb") as out_buffer:
        for data_field in ffs_file.data:
            line_buffer = create_buffer_from_data_field(data_field)
            out_buffer.write(line_buffer)


if __name__ == "__main__":

    if len(sys.argv) != 3:
        print("Usage: script <json-file> <out-file-name>")
        sys.exit(2)

    json_file = sys.argv[1]
    outfile = sys.argv[2]
    desc = subrgn_descptr.SubRegionDescriptor()
    desc.parse_json_data(json_file)

    # Currently only creates the first file
    generate_sub_region_image(desc.ffs_files[0], output_file=outfile)
