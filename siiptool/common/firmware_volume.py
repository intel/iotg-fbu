#!/usr/bin/env python
#
# Copyright (c) 2019, Intel Corporation. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#

"""A simple UEFI firmware volume parser"""

# import os
import sys
import uuid

from ctypes import Structure
from ctypes import c_char, c_uint32, c_uint8, c_uint64, c_uint16, sizeof, ARRAY
from functools import reduce


class EFI_FV_FILETYPE:
    ALL = 0x00
    RAW = 0x01
    FREEFORM = 0x02
    SECURITY_CORE = 0x03
    PEI_CORE = 0x04
    DXE_CORE = 0x05
    PEIM = 0x06
    DRIVER = 0x07
    COMBINED_PEIM_DRIVER = 0x08
    APPLICATION = 0x09
    SMM = 0x0A
    FIRMWARE_VOLUME_IMAGE = 0x0B
    COMBINED_SMM_DXE = 0x0C
    SMM_CORE = 0x0D
    OEM_MIN = 0xC0
    OEM_MAX = 0xDF
    DEBUG_MIN = 0xE0
    DEBUG_MAX = 0xEF
    FFS_MIN = 0xF0
    FFS_MAX = 0xFF
    FFS_PAD = 0xF0


class EFI_SECTION_TYPE:
    """Enumeration of all valid firmware file section types."""

    ALL = 0x00
    COMPRESSION = 0x01
    GUID_DEFINED = 0x02
    DISPOSABLE = 0x03
    PE32 = 0x10
    PIC = 0x11
    TE = 0x12
    DXE_DEPEX = 0x13
    VERSION = 0x14
    USER_INTERFACE = 0x15
    COMPATIBILITY16 = 0x16
    FIRMWARE_VOLUME_IMAGE = 0x17
    FREEFORM_SUBTYPE_GUID = 0x18
    RAW = 0x19
    PEI_DEPEX = 0x1B
    SMM_DEPEX = 0x1C


def align(offset, alignment=8):
    return (offset + alignment - 1) & ~(alignment - 1)


def bytes2val(bytes):
    return reduce(lambda x, y: (x << 8) | y, bytes[::-1])


def valu2bytes(value, blen):
    return [(value >> (i * 8) & 0xFF) for i in range(blen)]


class c_uint24(Structure):
    """Little-Endian 24-bit Unsigned Integer"""

    _pack_ = 1
    _fields_ = [("Data", (c_uint8 * 3))]

    def __init__(self, val=0):
        self.set_value(val)

    def __str__(self, indent=0):
        return "0x%.6x" % self.value

    def __int__(self):
        return self.get_value()

    def set_value(self, val):
        self.Data[0:3] = valu2bytes(val, 3)

    def get_value(self):
        return bytes2val(self.Data[0:3])

    value = property(get_value, set_value)


class EFI_FIRMWARE_VOLUME_HEADER(Structure):
    _fields_ = [
        ("ZeroVector", ARRAY(c_uint8, 16)),
        ("FileSystemGuid", ARRAY(c_uint8, 16)),
        ("FvLength", c_uint64),
        ("Signature", ARRAY(c_char, 4)),
        ("Attributes", c_uint32),
        ("HeaderLength", c_uint16),
        ("Checksum", c_uint16),
        ("ExtHeaderOffset", c_uint16),
        ("Reserved", c_uint8),
        ("Revision", c_uint8),
    ]


class EFI_FIRMWARE_VOLUME_EXT_HEADER(Structure):
    _fields_ = [("FvName", ARRAY(c_uint8, 16)), ("ExtHeaderSize", c_uint32)]


class EFI_FFS_INTEGRITY_CHECK(Structure):
    _fields_ = [("Header", c_uint8), ("File", c_uint8)]


class EFI_FFS_FILE_HEADER(Structure):
    _fields_ = [
        ("Name", ARRAY(c_uint8, 16)),
        ("IntegrityCheck", EFI_FFS_INTEGRITY_CHECK),
        ("Type", c_uint8),
        ("Attributes", c_uint8),
        ("Size", c_uint24),
        ("State", c_uint8),
    ]


class EFI_COMMON_SECTION_HEADER(Structure):
    _fields_ = [("Size", c_uint24),
                ("Type", c_uint8)]


class EFI_GUID_DEFINED_SECTION(Structure):
    _fields_ = [
        ("SectionDefinitionGuid", ARRAY(c_uint8, 16)),
        ("DataOffset", c_uint16),
        ("Attributes", c_uint16),
        ("Type", c_uint8),
        ("Attributes", c_uint8),
    ]


class EFI_COMPRESSED_SECTION(Structure):
    _fields_ = [
        ("UncompressedLength", c_uint32),
        ("CompressionType", c_uint8),
    ]


class VARIABLE_STORE_HEADER(Structure):
    _fields_ = [
        ("Signature", ARRAY(c_uint8, 16)),
        ("Size", c_uint32),
        ("Format", c_uint8),
        ("State", c_uint8),
        ("Reserved", c_uint16),
        ("Reserved1", c_uint32),
    ]


class FTW_HEADER(Structure):
    _fields_ = [
        ("Signature", ARRAY(c_uint8, 16)),
        ("Crc", c_uint32),
        ("Reserved", c_uint32),
        ("WriteQueueSize", c_uint64),
    ]


GUIDED_SECTION_COMPRESSED = uuid.UUID("ee4e5898-3914-4259-9d6e-dc7bd79403cf")
GUIDED_SECTION_RSASHA256 = uuid.UUID("a7717414-c616-4977-9420-844712a735bf")

GUID_VARIABLE_STORE_SIGNATURE = uuid.UUID("aaf32c78-947b-439a-a180-2e144ec37792")
GUID_FTW_WORKING_BLOCK_SIGNATURE = uuid.UUID("9e58292b-7c68-497d-a0ce-6500fd9f1b95")
GUID_MICROCODE_SIGNATURE = uuid.UUID("197DB236-F856-4924-90F8-CDF12FB875F3")
GUID_FSP_INFO_HEADER = uuid.UUID("912740BE-2284-4734-B971-84B027353F0C")
GUID_EMPTY = uuid.UUID("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF")

class FirmwareDevice:
    def __init__(self, offset, data):
        self.FvList = []
        self.Offset = 0
        self.FdData = bytearray(data)

    def ParseFd(self):
        offset = 0
        fdsize = len(self.FdData)
        self.FvList = []
        padding_size = 0
        while offset < fdsize:
            fvh = EFI_FIRMWARE_VOLUME_HEADER.from_buffer(self.FdData, offset)
            if b"_FVH" != fvh.Signature:  # TODO: need more work to determine padding
                offset += 0x1000  # Advance 4KB
                padding_size += 0x1000
                continue
            if padding_size > 0:
                print(
                    "WARNING: Invalid FV header signature. Possible filler data between FVs"
                )
                fv_gap_file = PaddingFile(
                    offset - padding_size, self.FdData[offset - padding_size : offset]
                )
                self.FvList.append(fv_gap_file)
                padding_size = 0

            fv = FirmwareVolume(offset, self.FdData[offset : offset + fvh.FvLength])
            print(
                "\n=== FV {} @ {:x} len:{:x} ===".format(
                    len(self.FvList), offset, len(fv.FvData)
                )
            )
            fv.ParseFv()
            self.FvList.append(fv)
            offset += fv.FvHdr.FvLength

    def get_fv_index_by_guid(self, guid):
        """Return the index of FV within FvList, -1 if not found"""
        for idx, fv in enumerate(self.FvList):
            if isinstance(guid, bytes) and isinstance(fv, FirmwareVolume):
                if guid == fv.Name:
                    return idx
        return -1

    def is_fsp_wrapper(self):
        for i in self.FvList:
            if isinstance(i, FirmwareVolume) and i.FspExists:
                return True
        return False


class MiscFile:
    def __init__(self, name, offset, data):
        self.Name = name[:]
        self.Offset = offset
        self.Data = data[:]


class PaddingFile:
    def __init__(self, offset, data):
        self.Offset = offset
        self.Data = data[:]


class FirmwareVolume:
    def __init__(self, offset, fvdata):
        self.FvHdr = EFI_FIRMWARE_VOLUME_HEADER.from_buffer(fvdata, 0)
        self.FvData = fvdata[0 : self.FvHdr.FvLength]
        self.Offset = offset
        self.FspExists = False
        self.FfsList = []
        if self.FvHdr.ExtHeaderOffset > 0:
            self.FvExtHdr = EFI_FIRMWARE_VOLUME_EXT_HEADER.from_buffer(
                self.FvData, self.FvHdr.ExtHeaderOffset
            )
            self.Name = bytes(self.FvExtHdr.FvName)
        else:
            self.FvExtHdr = None
            self.Name = bytes(self.FvHdr.FileSystemGuid)

    def ParseFv(self):
        fvsize = len(self.FvData)
        if self.FvExtHdr:
            offset = self.FvHdr.ExtHeaderOffset + self.FvExtHdr.ExtHeaderSize
        else:
            offset = self.FvHdr.HeaderLength
        offset = align(offset)
        while offset < fvsize:
            ffshdr = EFI_FFS_FILE_HEADER.from_buffer(self.FvData, offset)
            ffs_name = uuid.UUID(bytes_le=bytes(ffshdr.Name))
            if (ffs_name == GUID_EMPTY) and (ffshdr.Type == EFI_FV_FILETYPE.FFS_PAD):
                print(
                    "  Padding file (off:{:x} len:{:x})".format(
                        offset, int(ffshdr.Size)
                    )
                )
                pad_file = PaddingFile(
                    offset, self.FvData[offset : offset + int(ffshdr.Size)]
                )
                self.FfsList.append(pad_file)
                offset += int(ffshdr.Size)
            elif (ffs_name == GUID_EMPTY) and (int(ffshdr.Size) == 0xFFFFFF):
                print(
                    "  Free space (off: {:x} len: {:x})".format(offset, fvsize - offset)
                )
                pad_file = PaddingFile(offset, self.FvData[offset:fvsize])
                self.FfsList.append(pad_file)
                offset = fvsize
            elif ffs_name == GUID_VARIABLE_STORE_SIGNATURE:
                print("  VSS file")
                vsshdr = VARIABLE_STORE_HEADER.from_buffer(self.FvData, offset)
                vss = MiscFile(
                    vsshdr.Signature, offset, self.FvData[offset : offset + vsshdr.Size]
                )
                self.FfsList.append(vss)
                offset += vsshdr.Size
            elif ffs_name == GUID_FTW_WORKING_BLOCK_SIGNATURE:
                print("  FTW file")
                ftwhdr = FTW_HEADER.from_buffer(self.FvData, offset)
                ftw = MiscFile(
                    ftwhdr.Signature,
                    offset,
                    self.FvData[
                        offset : offset + ftwhdr.WriteQueueSize + sizeof(FTW_HEADER)
                    ],
                )
                self.FfsList.append(ftw)
                offset += ftwhdr.WriteQueueSize + sizeof(FTW_HEADER)
            elif ffs_name == GUID_MICROCODE_SIGNATURE:
                print("  Microcode file")
                ucode = MiscFile(
                    ffshdr.Name, offset, self.FvData[offset : offset + int(ffshdr.Size)]
                )
                self.FfsList.append(ucode)
                offset += int(ffshdr.Size)
            elif ffs_name == GUID_FSP_INFO_HEADER:
                print("  FSP Info Header file")
                self.FspExists = True
                ffs = FirmwareFile(offset, self.FvData[offset : offset + int(ffshdr.Size)])
                self.FfsList.append(ffs)
                offset += int(ffshdr.Size)
            else:
                print("  FFS file")
                ffs = FirmwareFile(
                    offset, self.FvData[offset : offset + int(ffshdr.Size)]
                )
                ffs.ParseFfs()
                self.FfsList.append(ffs)
                offset += int(ffshdr.Size)

            # Make sure 8-byte aligned
            offset = align(offset)


class FirmwareFile:
    def __init__(self, offset, filedata):
        self.FfsHdr = EFI_FFS_FILE_HEADER.from_buffer(filedata, 0)
        self.FfsData = filedata[0 : int(self.FfsHdr.Size)]
        self.Offset = offset
        self.SecList = []
        self.Name = self.FfsHdr.Name

    def ParseFfs(self):
        ffssize = len(self.FfsData)
        offset = sizeof(self.FfsHdr)
        if self.FfsHdr.Name != "\xff" * 16:
            while offset < ffssize:
                sechdr = EFI_COMMON_SECTION_HEADER.from_buffer(self.FfsData, offset)
                sec = Section(offset, self.FfsData[offset : offset + int(sechdr.Size)])
                self.SecList.append(sec)
                offset += int(sechdr.Size)
                offset = align(offset, 4)


class Section:
    def __init__(self, offset, secdata):
        self.SecHdr = EFI_COMMON_SECTION_HEADER.from_buffer(secdata, 0)
        self.SecData = secdata[0 : int(self.SecHdr.Size)]
        self.Offset = offset
        self.Type = self.SecHdr.Type
        if self.SecHdr.Type == EFI_SECTION_TYPE.USER_INTERFACE:
            self.Name = self.SecData[4:].decode("utf-16le").rstrip("\0")
        elif self.SecHdr.Type == EFI_SECTION_TYPE.FIRMWARE_VOLUME_IMAGE:
            fv_sec = EFI_FIRMWARE_VOLUME_HEADER.from_buffer(
                                           self.SecData,
                                           sizeof(EFI_COMMON_SECTION_HEADER))
            self.Name = fv_sec.FileSystemGuid
        elif self.SecHdr.Type == EFI_SECTION_TYPE.GUID_DEFINED:
            guided_sec = EFI_GUID_DEFINED_SECTION.from_buffer(
                                self.SecData,
                                sizeof(EFI_COMMON_SECTION_HEADER))
            self.Name = guided_sec.SectionDefinitionGuid
        else:
            self.Name = self.SecData[4:20]  # Any data

    def __str__(self, indent=0):
        if (self.Type == EFI_SECTION_TYPE.FIRMWARE_VOLUME_IMAGE):
            name = uuid.UUID(bytes_le=bytes(self.Name))
            name = "Volume Image ({})".format(name)
        elif (self.Type == EFI_SECTION_TYPE.GUID_DEFINED):
            name = uuid.UUID(bytes_le=bytes(self.Name))
            if (name == GUIDED_SECTION_COMPRESSED):
                name = "LZMA Compressed".format(name)
            elif (name == GUIDED_SECTION_RSASHA256):
                name = "RSA Signed".format(name)
        elif (self.Type == EFI_SECTION_TYPE.USER_INTERFACE):
            name = self.Name
        elif (self.Type == EFI_SECTION_TYPE.RAW):
            name = "Raw Data"
        elif (self.Type == EFI_SECTION_TYPE.FREEFORM_SUBTYPE_GUID):
            name = "Free Form"
        else:
            name = "TBD"

        return "Type:%02x Size:%x Info:%s" % (
                    self.Type,
                    len(self.SecData),
                    name)


def main():
    with open(sys.argv[1], "rb") as input_fd:
        data = input_fd.read()
        fd = FirmwareDevice(0, data)
        fd.ParseFd()

    print("\nFound total {} Firmware Volumes:".format(len(fd.FvList)))
    for idx, fv in enumerate(fd.FvList):
        if isinstance(fv, PaddingFile):
            print("PAD%d:" % idx)
            print("  Offset : 0x%08X" % fv.Offset)
            print("  Length : 0x%08X" % len(fv.Data))
            continue

        if not fv.FvExtHdr:
            name = fv.FvHdr.FileSystemGuid
        else:
            name = fv.FvExtHdr.FvName
            if not name:
                name = "\xff" * 16

        if sys.version_info[0] < 3:
            name = str(bytearray(name))
        else:
            name = bytes(name)

        guid = uuid.UUID(bytes_le=name)
        print("\n\nFV%d:" % idx)
        print("  GUID   : %s" % str(guid).upper())
        print("  Offset : 0x%08X" % fv.Offset)
        print("  Length : 0x%08X" % fv.FvHdr.FvLength)
        for j, ffs in enumerate(fv.FfsList):
            if isinstance(ffs, FirmwareFile):
                print(
                    "    [%d] FFS (len:%x sections:%d guid:%s)"
                    % (
                        j,
                        len(ffs.FfsData),
                        len(ffs.SecList),
                        uuid.UUID(bytes_le=bytes(ffs.Name)),
                    )
                )
                for k, sec in enumerate(ffs.SecList):
                    print("       | SEC%d (%s)" % (k, sec))
            elif isinstance(ffs, PaddingFile):
                print("    [%d] FREE (len:%x)" % (j, len(ffs.Data)))
            elif isinstance(ffs, MiscFile):
                print(
                    "    [%d] MISC (len:%x guid:%s)"
                    % (j, len(ffs.Data), uuid.UUID(bytes_le=bytes(ffs.Name)))
                )

    print("\n")


if __name__ == "__main__":
    sys.exit(main())
