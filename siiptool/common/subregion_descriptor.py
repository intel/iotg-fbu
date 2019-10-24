# @file
# Descriptor definition for BIOS Sub Regions
#
# Copyright (c) 2019, Intel Corporation. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#

import json
import uuid

FMP_CAPSULE_TSN_MAC_ADDRESS_FILE_GUID = uuid.UUID("6fee88ff-49ed-48f1-b77b-ead15771abe7")
FMP_CAPSULE_TSN_IP_CONFIG_FILE_GUID = uuid.UUID("697f0ea1-b630-4b93-9b08-eaffc5d5fc45")
FMP_CAPSULE_PSE_TSN_MAC_CONFIG_FILE_GUID = uuid.UUID("90c9751d-fa74-4ea6-8c4b-f44d2be8cd4b")
FMP_CAPSULE_PSE_FW_FILE_GUID = uuid.UUID("aad1e926-23b8-4c3a-8b44-0c9a031664f2")
FMP_CAPSULE_TCC_ARB_FILE_GUID = uuid.UUID("a7ee90b1-fb4a-4478-b868-367ee9ec97e2")
FMP_CAPSULE_OOB_MANAGEABILITY_FILE_GUID = uuid.UUID("bf2ae378-01e0-4605-9e3b-2ee2fc7339de")


class EnumDataTypes(set):
    def __getattr__(self, name):
        if name in self:
            return name
        raise AttributeError


data_types = EnumDataTypes(["DECIMAL", "HEXADECIMAL", "STRING", "FILE"])


class UnknownSubRegionError(Exception):
    def __init__(self):
        pass

    def __str__(self):
        return repr("Sub Region is unknown.")


class SubRegionDescSyntaxError(Exception):
    def __init__(self, key):
        self.key = key
        pass

    def __str__(self):
        return repr(
            "Sub Region descriptor invalid syntax. Problem with {} field in "
            "JSON file.".format(self.key)
        )


class SubRegionFfsFile(object):
    def __init__(self, ffs_guid, compression, data):
        self.s_ffs_guid = ffs_guid
        try:
            self.ffs_guid = uuid.UUID(self.s_ffs_guid)
        except ValueError:
            raise SubRegionDescSyntaxError("ffs_guid")
        self.ffs_guid = ffs_guid
        self.compression = compression
        self.data = []
        for data_field in data:
            self.data.append(SubRegionDataField(data_field))


class SubRegionDataField(object):
    def __init__(self, data_field):
        self.name = data_field[0]
        self.Type = data_field[1]
        self.ByteSize = data_field[2]
        self.Value = data_field[3]
        if self.Type == data_types.DECIMAL:
            if data_field[3] is not None:
                self.dValue = int(data_field[3])
                self.sValue = str(data_field[3])
        elif self.Type == data_types.HEXADECIMAL:
            if data_field[3] is not None:
                self.sValue = str(data_field[3])
                self.dValue = int(self.sValue, 16)
        else:
            self.dValue = None
            self.sValue = str(data_field[3])


class SubRegionDescriptor(object):
    ValidGuidList = [
        FMP_CAPSULE_TSN_MAC_ADDRESS_FILE_GUID,
        FMP_CAPSULE_PSE_TSN_MAC_CONFIG_FILE_GUID,
        FMP_CAPSULE_PSE_FW_FILE_GUID,
        FMP_CAPSULE_TCC_ARB_FILE_GUID,
        FMP_CAPSULE_OOB_MANAGEABILITY_FILE_GUID,
        FMP_CAPSULE_TSN_IP_CONFIG_FILE_GUID
    ]

    def __init__(self):
        self.s_fmp_guid = None
        self.fmp_guid = None
        self.version = None
        self.fv = None
        self.s_fv_guid = None
        self.fv_guid = None
        self.ffs_files = []

    def parse_json_data(self, json_file):
        with open(json_file, "r") as file_handle:
            desc_buffer = json.loads(file_handle.read())
            try:
                self.s_fmp_guid = desc_buffer["FmpGuid"]
                try:
                    self.fmp_guid = uuid.UUID(self.s_fmp_guid)
                    if not self.is_known_guid(self.fmp_guid):
                        raise UnknownSubRegionError
                except ValueError:
                    raise SubRegionDescSyntaxError("FmpGuid")
                self.version = desc_buffer["Version"]

                self.fv = desc_buffer["FV"]
                self.s_fv_guid = self.fv["FvGuid"]
                try:
                    self.fv_guid = uuid.UUID(self.s_fv_guid)
                except ValueError:
                    raise SubRegionDescSyntaxError("FvGuid")
                except TypeError:
                    raise SubRegionDescSyntaxError("FvGuid")

                ffs_file_list = self.fv["FfsFiles"]
                for ffs_file in ffs_file_list:
                    ffs_guid = ffs_file["FileGuid"]
                    compression = ffs_file["Compression"]
                    data = ffs_file["Data"]
                    self.ffs_files.append(SubRegionFfsFile(ffs_guid, compression, data))

                for ffs_file in self.ffs_files:
                    if not self.check_file_good(ffs_file):
                        raise SubRegionDescSyntaxError("FfsFile")
            except (KeyError, IndexError) as e:
                raise SubRegionDescSyntaxError(str(e))

    def check_file_good(self, ffs_file):
        valid_file = True

        if ffs_file.compression not in [False, True]:
            valid_file = False

        for data_field in ffs_file.data:
            if type(data_field.name) not in [str]:
                valid_file = False
            if data_field.Type not in data_types:
                valid_file = False
            if data_field.ByteSize < 0:
                valid_file = False
            if type(data_field.Value) not in [str, int]:
                valid_file = False

        return valid_file

    def is_known_guid(self, guid):
        return guid in self.ValidGuidList
