#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2019, Intel Corporation. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#

"""A signing utility to create manifest data according to SIIP specification
"""


from __future__ import print_function

import os
import sys
import argparse
from datetime import datetime

from enum import Enum
import struct
from ctypes import Structure
from ctypes import c_char, c_uint32, c_uint8, c_uint64, c_uint16, sizeof, ARRAY

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common.banner import banner
import common.logging as logging

logger = logging.getLogger("siip_sign")

try:
    from cryptography.hazmat.primitives import hashes as hashes
    from cryptography.hazmat.primitives import serialization as serialization
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import padding as crypto_padding

    # Check its version
    import cryptography

    if cryptography.__version__ < "2.2.2":
        logger.critical(
            "Error: Cryptography version must be 2.2.2 or higher"
            " (installed version: {})".format(cryptography.__version__)
        )
        exit(1)

except ImportError:
    logger.critical("Error: Cryptography could not be found, please install using pip")
    sys.exit(1)


__prog__ = "siip_sign"
__version__ = "0.7.5"

TOOLNAME = "SIIP Signing Tool"

banner(TOOLNAME, __version__)

if sys.version_info < (3, 6):
    raise Exception("Python 3.6 is the minimal version required")

KB = 1024
MB = 1024 * KB

HASH_CHOICES = {
    "sha256": (hashes.SHA256(), 2, 0x10000),
    "sha384": (hashes.SHA384(), 3, 0x11000),
    "sha512": (hashes.SHA512(), 4, 0x12000),
}

# SIGNING_DATE = int(datetime.now().strftime('%Y%m%d'), 16)
SIGNING_DATE = 0x20191115  # Hardcode it for now for identical signature

class SUBPART_DIR_HEADER(Structure):
    _pack_ = 1
    _fields_ = [
        ("header_marker", c_uint32),
        ("num_of_entries", c_uint32),
        ("header_version", c_uint8),
        ("entry_version", c_uint8),
        ("header_length", c_uint8),
        ("reserved", c_uint8),
        ("subpart_name", ARRAY(c_char, 4)),
        ("crc32", c_uint32),
    ]


class SUBPART_DIR_ENTRY(Structure):
    _pack_ = 1
    _fields_ = [
        ("name", ARRAY(c_char, 12)),
        ("offset", c_uint32),
        ("length", c_uint32),
        ("module_type", c_uint32),
    ]


class METADATA_FILE_STRUCT(Structure):
    _pack_ = 1
    _fields_ = [
        ("size", c_uint32),
        ("id", c_uint32),
        ("version", c_uint32),
        ("flags", c_uint32),
        ("num_of_modules", c_uint32),

        # Repeat per module. Currently only one is supported
        ("module_id", ARRAY(c_char, 12)),
        ("module_size", c_uint32),
        ("module_version", c_uint32),
        ("module_entry_point", c_uint32),
        ("module_offset", c_uint32),
        ("module_hash_algorithm", c_uint32),
        ("module_hash_size", c_uint32),
        ("module_hash_value", ARRAY(c_uint8, 64)),
        ("num_of_keys", c_uint32),
        ("key_usage_id", ARRAY(c_uint8, 16)),
        ("non_std_section_size", c_uint32),
        # Followed by the non-standard section data
    ]

class METADATA_ENTRY(Structure):
    _pack_ = 1
    _fields_ = [
        ("id", c_uint32),
        ("type", c_uint8),
        ("hash_algorithm", c_uint8),
        ("hash_size", c_uint16),
        ("metadata_size", c_uint32),
        ("hash", ARRAY(c_uint8, 64)),
    ]


class FIRMWARE_MANIFEST_HEADER(Structure):
    _pack_ = 1
    _fields_ = [
        ("type", c_uint32),
        ("length", c_uint32),
        ("version", c_uint32),  # SHA related flags
        ("flags", c_uint32),
        ("vendor", c_uint32),
        ("date", c_uint32),
        ("size", c_uint32),  # in DWORDS. max 2K
        ("id", c_uint32),  # '$MN2'
        ("num_of_metadata", c_uint32),
        ("structure_version", c_uint32),
        ("reserved", ARRAY(c_uint8, 80)),
        ("modulus_size", c_uint32),
        ("exponent_size", c_uint32),
        ("public_key", ARRAY(c_uint8, 384)),  # Take RSA 3072 key length
        ("exponent", ARRAY(c_uint8, 4)),
        ("signature", ARRAY(c_uint8, 384)),  # Take RSA 3072 key length
    ]


class KEY_USAGE_STRUCTURE(Structure):
    _pack_ = 1
    _fields_ = [
        ("key_usage", ARRAY(c_uint8, 16)),
        ("key_reserved", ARRAY(c_uint8, 16)),
        ("key_policy", c_uint8),
        ("key_hash_algorithm", c_uint8),
        ("key_hash_size", c_uint16),
        ("key_hash", ARRAY(c_uint8, 64)),
    ]


class FIRMWARE_KEY_MANIFEST(Structure):
    number_of_keys = 1
    _pack_ = 1
    _fields_ = [
        ("manifest_header", FIRMWARE_MANIFEST_HEADER),
        ("extension_type", c_uint32),
        ("extension_length", c_uint32),
        ("key_manifest_type", c_uint32),
        ("key_manifest_svn", c_uint32),
        ("oem_id", c_uint16),
        ("key_manifest_id", c_uint8),
        ("reserved", c_uint8),
        ("reserved2", ARRAY(c_uint8, 12)),
        ("num_of_keys", c_uint32),
        ("key_usage_array", ARRAY(KEY_USAGE_STRUCTURE, number_of_keys)),
    ]


class FIRMWARE_BLOB_MANIFEST(Structure):
    _pack_ = 1
    _fields_ = [
        ("manifest_header", FIRMWARE_MANIFEST_HEADER),
        ("extension_type", c_uint32),
        ("extension_length", c_uint32),
        ("package_name", c_uint32),
        ("version_control_num", c_uint64),
        ("usage_bitmap", ARRAY(c_uint8, 16)),
        ("svn", c_uint32),
        ("fw_type", c_uint8),
        ("fw_subtype", c_uint8),
        ("reserved", c_uint16),
        ("num_of_devices", c_uint32),
        ("device_list", ARRAY(c_uint32, 8)),
        ("metadata_entries", ARRAY(METADATA_ENTRY, 1)),
    ]


class ModuleType(Enum):
    FKM = 0
    FBM = 1
    META = 2
    MODULE = 3


def hex_dump(data, n=16, indent=0, msg="Hex Dump", format=0):
    logger.info("%s (%d Bytes):" % (msg, len(data)))
    for i in range(0, len(data), n):
        line = bytearray(data[i:i+n])
        if (format == 0):
            hex = " ".join("%02x" % c for c in line)
            text = "".join(chr(c) if 0x21 <= c <= 0x7E else "." for c in line)
            logger.info("%*s%-*s %s" % (indent, "", n * 3, hex, text))
        else:
            hex = ", ".join("0x%02X" % c for c in line)
            logger.info("%s" % hex)


def pack_num(val, minlen=0):
    buf = bytearray()
    while val > 0:
        if sys.version_info > (3, 0):
            buf += bytes([val & 0xFF])
        else:
            buf += chr(val & 0xFF)
        val >>= 8
    buf += bytearray(max(0, minlen - len(buf)))
    return buf


def compute_hash(data, hash_option):
    """Compute hash from data"""

    digest = hashes.Hash(HASH_CHOICES[hash_option][0],
                         backend=default_backend())
    digest.update(data)
    result = digest.finalize()

    return result


def get_key_length(key_pem, is_privkey=True):
    """Get key size (in bytes) from PEM file"""

    with open(key_pem, "rb") as key_fd:
        if is_privkey:
            key = serialization.load_pem_private_key(
                    key_fd.read(),
                    password=None,
                    backend=default_backend())
        else:
            key = serialization.load_pem_public_key(
                    key_fd.read(),
                    backend=default_backend())

    if key.key_size < 2048:
        raise Exception("{}-bit RSA key size is too short Use 2048-bit "
                        "or 3072-bit RSA key for signing".format(key.key_size))

    return (key.key_size + 8 - 1) // 8   # Number of bytes to store all bits


def get_pubkey_from_privkey(privkey_pem):
    """Extract public key from private key in PEM format"""

    with open(privkey_pem, "rb") as privkey_file:
        key = serialization.load_pem_private_key(
            privkey_file.read(), password=None, backend=default_backend()
        )

    return key.public_key()


def get_hash_from_pubkey(pubkey_pem, hash_option):
    """Calculate public key hash from a public key in PEM format"""

    with open(pubkey_pem, "rb") as pubkey_pem_fd:
        puk = serialization.load_pem_public_key(
            pubkey_pem_fd.read(), backend=default_backend()
        )

    puk_num = puk.public_numbers()

    key_len = get_key_length(pubkey_pem, is_privkey=False)
    mod_buf = pack_num(puk_num.n, key_len)
    exp_buf = pack_num(puk_num.e, 4)

    pubkey_data = mod_buf[::-1] + exp_buf[::-1]  # Match public key endian
    hash_result = compute_hash(bytes(pubkey_data), hash_option)

    hex_dump(mod_buf[::-1],
             msg="Public key (%s, %s, modulus reversed) " % (pubkey_pem,
                                                             hash_option))
    hex_dump(hash_result, msg="Key Hash")

    return hash_result


def compute_signature(data, privkey_pem, hash_option):
    """Compute signature from data"""

    with open(privkey_pem, "rb") as privkey_file:
        key = serialization.load_pem_private_key(
            privkey_file.read(), password=None, backend=default_backend()
        )

    # Calculate signature using private key
    signature = key.sign(bytes(data),
                         crypto_padding.PKCS1v15(),
                         HASH_CHOICES[hash_option][0])

    return (signature, key)


def verify_signature(signature, data, pubkey_pem, hash_option):
    """Verify signature with public key"""

    with open(pubkey_pem, "rb") as pubkey_file:
        puk = serialization.load_pem_public_key(
            pubkey_file.read(), backend=default_backend()
        )

    # Raises InvalidSignature error if not match
    puk.verify(signature,
               data,
               crypto_padding.PKCS1v15(),
               HASH_CHOICES[hash_option][0])


def compute_pubkey_hash(pubkey_pem_file, hash_option):
    """Compute hash of the public key provided in PEM file"""

    with open(pubkey_pem_file, "rb") as pubkey_pem_fd:
        puk = serialization.load_pem_public_key(
            pubkey_pem_fd.read(), backend=default_backend()
        )
    key_len = (puk.key_size + 8 - 1) // 8
    puk_num = puk.public_numbers()
    mod_buf = pack_num(puk_num.n, key_len)
    exp_buf = pack_num(puk_num.e, 4)

    puk_hash = compute_hash(bytes(mod_buf + exp_buf), hash_option)

    return puk_hash


def calculate_sum32(data):
    """sum of all elements from a buffer of 32-bit values."""

    if (len(data) & 0x3) != 0:
        raise ValueError("Length of data is not multiple of DWORDs")

    fmt = "<{}I".format(len(data) // 4)
    buffer32 = struct.unpack(fmt, data)
    result32 = sum(buffer32) & 0xffffffff
    result32 = 0xFFFFFFFF - result32 + 1

    return result32


def build_fkm(privkey, pubkey_list, hash_option, outfile, svn):
    """Generate FKM data from a list of public keys"""

    if (svn < 0 or svn > 15):
        logger.critical("Bad SVN value. 0-15 only.")
        exit(2)

    fkm_data = bytearray(sizeof(FIRMWARE_KEY_MANIFEST))

    fkm = FIRMWARE_KEY_MANIFEST.from_buffer(fkm_data, 0)
    fkm.manifest_header.type = 0x4
    fkm.manifest_header.length = sizeof(FIRMWARE_MANIFEST_HEADER)
    fkm.manifest_header.version = HASH_CHOICES[hash_option][2]
    fkm.manifest_header.flags = 0x0
    fkm.manifest_header.vendor = 0x8086  # Intel device
    fkm.manifest_header.date = SIGNING_DATE
    fkm.manifest_header.size = sizeof(FIRMWARE_KEY_MANIFEST)
    fkm.manifest_header.id = 0x324E4D24  # '$MN2'
    fkm.manifest_header.num_of_metadata = 0  # FKM has no metadata appended
    fkm.manifest_header.structure_version = 0x1000
    # In DWORD
    fkm.manifest_header.modulus_size = get_key_length(privkey,
                                                      is_privkey=True) // 4
    fkm.manifest_header.exponent_size = 1  # In DWORD

    # 3: SIIP OEM Firmware Manifest; 4: SIIP Intel Firmware Manifest
    fkm.extension_type = 14  # CSE Key Manifest Extension Type
    fkm.key_manifest_type = 4
    fkm.key_manifest_svn = svn
    fkm.oem_id = 0
    fkm.key_manifest_id = 0  # Not used
    fkm.num_of_keys = FIRMWARE_KEY_MANIFEST.number_of_keys
    fkm.extension_length = 36 + 68 * fkm.num_of_keys  # Hardcoded from now
    fkm.key_usage_array[0].key_usage[7] = 0x08  # 1 << 59 in arr[16]
    fkm.key_usage_array[0].key_reserved[:] = [0] * 16

    # key_policy: 0 - No FKM verification. Else - verification required
    digest_size = HASH_CHOICES[hash_option][0].digest_size
    print(pubkey_list)
    if pubkey_list[0] is not None:
        fkm.key_usage_array[0].key_policy = 1
        fkm.key_usage_array[0].key_hash_algorithm = HASH_CHOICES[hash_option][1]
        fkm.key_usage_array[0].key_hash_size = digest_size
        # Calculate public key hash used by payload and store it in FKM
        # TBD: support one key for now
        hash_result = get_hash_from_pubkey(pubkey_list[0], hash_option)
        fkm.key_usage_array[0].key_hash[:] = (hash_result +
                                              bytes(64 - digest_size))
    else:
        logger.warning("FBM verification is disabled!")
        fkm.key_usage_array[0].key_policy = 0
        fkm.key_usage_array[0].key_hash_algorithm = 0
        fkm.key_usage_array[0].key_hash_size = 0
        fkm.key_usage_array[0].key_hash[:] = [0xFF] * 64

    # Calculate FKM signature (except signature and public key)
    # and store it in FKM header
    (signature, key) = compute_signature(fkm_data, privkey, hash_option)
    puk = get_pubkey_from_privkey(privkey)
    puk_num = puk.public_numbers()

    fkm_hash = compute_hash(fkm_data, hash_option)
    hex_dump(fkm_hash, msg="FKM Hash:")

    key_len = get_key_length(privkey, is_privkey=True)
    mod_buf = pack_num(puk_num.n, key_len)
    exp_buf = pack_num(puk_num.e, 4)
    hex_dump((mod_buf + exp_buf), msg="FKM Public Key")

    fkm.manifest_header.public_key[:key_len] = mod_buf[::-1]
    fkm.manifest_header.exponent[:] = exp_buf[::-1]
    fkm.manifest_header.signature[:key_len] = signature

    hex_dump(signature, msg="FKM Signature")

    cpd_data = create_cpd_header([("FKM", len(fkm_data), ModuleType.FKM)])
    with open(outfile, "wb") as fkm_fd:
        fkm_fd.write(cpd_data)
        fkm_fd.write(fkm_data)

    return fkm_data


def create_cpd_header(files_info):
    """Create a new CPD directory"""

    data = bytearray(sizeof(SUBPART_DIR_HEADER) +
                     len(files_info) * sizeof(SUBPART_DIR_ENTRY))
    ptr = 0

    cpd = SUBPART_DIR_HEADER.from_buffer(data, ptr)
    cpd.header_marker = 0x44504324  # '$CPD'
    cpd.num_of_entries = len(files_info)
    cpd.header_version = 2  # 1: layout v1.5/1.6/2.0; 2: layout v1.7
    cpd.entry_version = 1
    cpd.header_length = sizeof(SUBPART_DIR_HEADER)
    cpd.reserved = 0  # was 8-bit checksum
    cpd.subpart_name = bytes("SIIP", encoding="Latin-1")
    cpd.crc32 = 0  # New in layout 1.7

    ptr += sizeof(SUBPART_DIR_HEADER)
    offset = len(data)
    for f in files_info:
        cpd_entry = SUBPART_DIR_ENTRY.from_buffer(data, ptr)
        cpd_entry.name = bytes(f[0], encoding="Latin-1")
        cpd_entry.offset = offset
        cpd_entry.length = f[1]
        cpd_entry.module_type = f[2].value
        ptr += sizeof(SUBPART_DIR_ENTRY)
        offset += f[1]

    # Fill CRC32 checksum
    cpd.crc32 = calculate_sum32(data)
    logger.info("CPD len 0x%x bytes (check_sum:0x%X)" % (len(data), cpd.crc32))

    return data


def parse_cpd_header(cpd_data):
    """Parse CPD header and return files information"""

    ptr = 0
    cpd = SUBPART_DIR_HEADER.from_buffer(cpd_data, 0)
    if cpd.header_marker != 0x44504324:
        logger.critical("Invalid input file. CPD signature not found.")
        exit(1)

    files = []
    entry_count = cpd.num_of_entries

    expected_crc = cpd.crc32
    cpd.crc32 = 0
    cpd_length = sizeof(SUBPART_DIR_HEADER) + (entry_count *
                                               sizeof(SUBPART_DIR_ENTRY))
    actual_crc = calculate_sum32(cpd_data[0:cpd_length])

    if expected_crc != actual_crc:
        logger.critical(
            "CPD header CRC32 invalid (exp: 0x%x, actual: 0x%x)"
            % (expected_crc, actual_crc)
        )
        exit(1)

    ptr += sizeof(SUBPART_DIR_HEADER)
    for i in range(entry_count):
        cpd_entry = SUBPART_DIR_ENTRY.from_buffer(cpd_data, ptr)
        files.append((cpd_entry.name.decode(),
                      cpd_entry.offset,
                      cpd_entry.length,
                      cpd_entry.module_type))
        ptr += sizeof(SUBPART_DIR_ENTRY)

    return files


def create_image(payload_file, outfile, privkey, hash_option, svn):
    """Create a new image with manifest data in front it"""

    if (svn < 0 or svn > 255):
        logger.critical("Bad SVN value. 0-255 only.")
        exit(2)

    digest_size = HASH_CHOICES[hash_option][0].digest_size

    logger.info("Hashing Algorithm : %s" % HASH_CHOICES[hash_option][0].name)
    if digest_size * 8 < 384:
        logger.warning("Security guideline recommends using digest size "
                       "384-bit or longer for hashing algorithm")

    key_len = get_key_length(privkey, is_privkey=True)
    logger.info("FBM signing key : %s (%d-bit)" % (privkey, key_len*8))

    if (key_len * 8) < 3072:
        logger.warning("Security guideline recommends using 3072-bit "
                       "(or stronger) RSA key for signing")

    # Create the rest (FBM, Meta Data and payload) in one piece
    with open(payload_file, "rb") as in_fd:
        in_data = bytearray(in_fd.read())

    fbm_length = sizeof(FIRMWARE_BLOB_MANIFEST)
    metadata_length = sizeof(METADATA_FILE_STRUCT)
    payload_length = len(in_data)

    files_info = [
        ("FBM", fbm_length, ModuleType.FBM),
        ("METADATA", metadata_length, ModuleType.META),
        ("PAYLOAD", payload_length, ModuleType.MODULE),
    ]
    cpd_data = create_cpd_header(files_info)

    cpd_length = sizeof(SUBPART_DIR_HEADER) + (
        len(files_info) * sizeof(SUBPART_DIR_ENTRY)
    )
    fbm_offset = cpd_length
    metadata_offset = fbm_offset + fbm_length

    total_length = cpd_length
    total_length += fbm_length + metadata_length + payload_length
    data = bytearray(total_length)

    data[0:len(cpd_data)] = cpd_data

    # Create FBM
    fbm = FIRMWARE_BLOB_MANIFEST.from_buffer(data, fbm_offset)
    fbm.manifest_header.type = 0x4
    fbm.manifest_header.length = sizeof(FIRMWARE_BLOB_MANIFEST)
    # Strage but required by specification
    fbm.manifest_header.version = HASH_CHOICES[hash_option][2]
    fbm.manifest_header.flags = 0x0
    fbm.manifest_header.vendor = 0x8086  # Intel device
    fbm.manifest_header.date = SIGNING_DATE
    fbm.manifest_header.size = fbm.manifest_header.length
    fbm.manifest_header.id = 0x324E4D24  # '$MN2'
    fbm.manifest_header.num_of_metadata = 1  # FBM has exactly one metadata
    fbm.manifest_header.structure_version = 0x1000
    # In DWORDs
    fbm.manifest_header.modulus_size = get_key_length(privkey,
                                                      is_privkey=True) // 4
    fbm.manifest_header.exponent_size = 1  # In DWORDs
    fbm.extension_type = 15  # CSME Signed Package Info Extension type

    fbm.package_name = 0x45534F24  # '$OSE'
    fbm.version_control_num = 0
    fbm.usage_bitmap[7] = 0x08  # Bit 59: OSE firmware
    fbm.svn = svn
    fbm.fw_type = 0
    fbm.fw_subtype = 0
    fbm.reserved = 0
    fbm.num_of_devices = 8
    fbm.device_list[:] = [0] * fbm.num_of_devices

    fbm.metadata_entries[0].id = 0xDEADBEEF
    # 0: process; 1: shared lib; 2: data (for SIIP)
    fbm.metadata_entries[0].type = 2
    fbm.metadata_entries[0].hash_algorithm = HASH_CHOICES[hash_option][1]
    fbm.metadata_entries[0].hash_size = digest_size
    fbm.metadata_entries[0].metadata_size = sizeof(METADATA_FILE_STRUCT)
    fbm.metadata_entries[0].hash[:] = [0] * 64

    fbm.extension_length = sizeof(FIRMWARE_BLOB_MANIFEST)

    # Create Meta Data
    metadata = METADATA_FILE_STRUCT.from_buffer(data, metadata_offset)
    metadata.size = sizeof(METADATA_FILE_STRUCT)
    # Match one of FBM metadata entries by ID
    metadata.id = fbm.metadata_entries[0].id
    metadata.version = 0
    metadata.flags = 0
    metadata.num_of_modules = 1  # Only one module is supported
    metadata.module_id = bytes("PSEFW", encoding="Latin-1")
    metadata.module_size = len(in_data)
    metadata.module_version = 0
    metadata.module_entry_point = 0  # Not used by PSE loading
    metadata.module_offset = 0  # Not used by PSE loading
    metadata.module_hash_algorithm = HASH_CHOICES[hash_option][1]
    metadata.module_hash_size = digest_size

    # STEP 1: Calculate payload hash and store it in Metadata file
    hash_result = compute_hash(bytes(in_data), hash_option)
    hex_dump(hash_result, msg="Payload Hash")

    metadata.module_hash_value[:digest_size] = hash_result
    metadata.num_of_keys = 1
    metadata.key_usage_id[7] = 0x08  # Bit 59: OSE firmware
    metadata.non_std_section_size = 0  # Empty non-standard section for now

    # STEP 2: Calculate Metadata file hash and store it in FBM
    metadata_limit = metadata_offset + metadata_length

    hash_result = compute_hash(bytes(data[metadata_offset:metadata_limit]),
                               hash_option)
    hex_dump(hash_result, msg="Metadata Hash")
    fbm.metadata_entries[0].hash[:digest_size] = hash_result

    # STEP 3: Calculate signature of FBM (except signature and public keys)
    #         and store it in FBM header
    fbm_limit = fbm_offset + fbm_length
    fbm.manifest_header.public_key[:] = [0] * 384
    fbm.manifest_header.exponent[:] = [0] * 4
    fbm.manifest_header.signature[:] = [0] * 384
    (signature, key) = compute_signature(bytes(data[fbm_offset:fbm_limit]),
                                         privkey,
                                         hash_option)
    hex_dump(signature, msg="FBM signature")

    puk = get_pubkey_from_privkey(privkey)
    puk_num = puk.public_numbers()

    key_len = (puk.key_size + 8 - 1) // 8
    mod_buf = pack_num(puk_num.n, key_len)
    exp_buf = pack_num(puk_num.e, 4)
    hex_dump((mod_buf + exp_buf), msg="FBM Public Key")

    fbm.manifest_header.public_key[:key_len] = mod_buf[::-1]
    fbm.manifest_header.exponent[:] = exp_buf[::-1]
    fbm.manifest_header.signature[:key_len] = signature

    # STEP 4: Append payload data as is
    data[total_length-payload_length:total_length] = in_data

    files = parse_cpd_header(data[0:cpd_length])

    for idx, (name, ioff, ilen, itype) in enumerate(files):
        logger.info("[%d] %s.bin @ [0x%08x-0x%08x] len:0x%x (%d) type:%d"
              % (idx, name, ioff, (ioff+ilen), ilen, ilen, itype))

    logger.info("Writing... ")
    with open(outfile, "wb") as out_fd:
        out_fd.write(data)
    logger.info("Okay")


def decompose_image(infile_signed):
    """Decompose image to individual files"""

    with open(infile_signed, "rb") as in_fd:
        in_data = bytearray(in_fd.read())

    files = parse_cpd_header(
        in_data[0:sizeof(SUBPART_DIR_HEADER) + 4 * sizeof(SUBPART_DIR_ENTRY)]
    )

    # Extract images
    if not os.path.exists("extract"):
        os.makedirs("extract")
    for idx, (name, ioff, ilen, itype) in enumerate(files):
        with open(os.path.join("extract", "%s.bin" % name), "wb") as out_fd:
            out_fd.write(in_data[ioff:ioff+ilen])
            logger.info("[%d] %s.bin @ [0x%08x-0x%08x] len:0x%x (%d) type:%d"
                  % (idx, name, ioff, (ioff+ilen), ilen, ilen, itype))


def verify_fkm(infile_signed, pubkey_pem_file, fbm_pubkey_file=None):
    """Verify a signed FKM with public key"""

    with open(infile_signed, "rb") as fkm_fd:
        fkm_data = bytearray(fkm_fd.read())

    files = parse_cpd_header(fkm_data)

    name, ioff, ilen, itype = files[0]  # FKM
    fkm_offset = ioff
    fkm_limit = fkm_offset + ilen
    fkm = FIRMWARE_KEY_MANIFEST.from_buffer(fkm_data, fkm_offset)
    if fkm.manifest_header.id != 0x324E4D24:
        logger.critical("Bad FKM signature.")
        exit(1)

    # Validate FBM key hash
    if fbm_pubkey_file:
        logger.info("Verifying FBM Key hash ...")
        hash_expected = fkm.key_usage_array[0].key_hash

        # Calculate public key hash in FKM header
        if fkm.key_usage_array[0].key_hash_algorithm == 2:
            hash_option = "sha256"
        elif fkm.key_usage_array[0].key_hash_algorithm == 3:
            hash_option = "sha384"
        elif fkm.key_usage_array[0].key_hash_algorithm == 4:
            hash_option = "sha512"
        else:
            raise ValueError("Invalid hash algorithm in FKM key usage data")

        # Verify FBM public key with FKM data
        hash_actual = get_hash_from_pubkey(fbm_pubkey_file, hash_option)
        if bytes(hash_actual) != bytes(hash_expected[:len(hash_actual)]):
            hex_dump(hash_actual, indent=4, msg="Actual")
            hex_dump(hash_expected[:len(hash_actual)],
                     indent=4, msg="Expected")
            raise Exception("Hash values mismatch!")

    # Verify FKM signature
    try:
        logger.info("Verifying FKM Signature ...")

        key_len = fkm.manifest_header.modulus_size * 4
        fkm_sig = fkm.manifest_header.signature[:key_len]

        # Clear public key and signature data first
        fkm.manifest_header.public_key[:] = [0] * 384
        fkm.manifest_header.exponent[:] = [0] * 4
        fkm.manifest_header.signature[:] = [0] * 384

        if fkm.manifest_header.version == 0x10000:
            hash_option = "sha256"
        elif fkm.manifest_header.version == 0x11000:
            hash_option = "sha384"
        elif fkm.manifest_header.version == 0x12000:
            hash_option = "sha512"
        else:
            raise ValueError("Invalid hash algorithm in FKM header")

        # Convert public key into PEM file
        verify_signature(fkm_sig,
                         bytes(fkm_data[fkm_offset:fkm_limit]),
                         pubkey_pem_file,
                         hash_option)

        logger.info("Okay")
    except Exception as e:
        logger.critical("Failed (%s)..." % type(e))
        exit(1)


def verify_image(infile_signed, pubkey_pem_file, hash_option):
    """Verify a signed image with public key end-to-end"""

    with open(infile_signed, "rb") as in_fd:
        in_data = bytearray(in_fd.read())

    key_len = get_key_length(pubkey_pem_file, is_privkey=False)

    # STEP 1: Validate FBM key hash, signature and metadata hashes
    hash_expected = compute_pubkey_hash(pubkey_pem_file, hash_option)

    files = parse_cpd_header(in_data)
    name, ioff, ilen, itype = files[0]  # FBM
    fbm_offset = ioff
    fbm_limit = fbm_offset + ilen

    fbm = FIRMWARE_BLOB_MANIFEST.from_buffer(in_data, fbm_offset)
    if fbm.manifest_header.id != 0x324E4D24:
        logger.critical("Bad FBM signature.")
        exit(1)

    pubkey_n = fbm.manifest_header.public_key[:key_len][::-1]
    pubkey_e = fbm.manifest_header.exponent[::-1]

    hash_actual = compute_hash(bytes(pubkey_n + pubkey_e), hash_option)

    if hash_expected != hash_actual:
        logger.critical("Verification failed: FBM key hash mismatch")
        exit(1)

    # Validate FBM
    fbm_sig = fbm.manifest_header.signature[:key_len]

    try:
        logger.info("Verifying FBM ...")

        # Clear public key and signature data first
        fbm.manifest_header.public_key[:] = [0] * 384
        fbm.manifest_header.exponent[:] = [0] * 4
        fbm.manifest_header.signature[:] = [0] * 384

        verify_signature(fbm_sig,
                         bytes(in_data[fbm_offset:fbm_limit]),
                         pubkey_pem_file,
                         hash_option)
        logger.info("Okay")
    except Exception:
        logger.critical("Failed")
        exit(1)

    # STEP 2: Validate Metadata hash
    name, ioff, ilen, itype = files[1]  # Metadata
    metafile_offset = ioff
    metafile_limit = metafile_offset + ilen

    metadata = METADATA_FILE_STRUCT.from_buffer(in_data, metafile_offset)

    hash_actual = compute_hash(bytes(in_data[metafile_offset:metafile_limit]),
                               hash_option)
    hash_actual = [x for x in hash_actual]  # Convert to list

    hash_expected = fbm.metadata_entries[0].hash[: len(hash_actual)]
    if hash_actual != hash_expected:
        raise Exception("Verification failed: Metadata hash mismatch")

    # STEP 3: Validate payload
    name, ioff, ilen, itype = files[2]  # Payload
    payload_offset = ioff
    payload_limit = payload_offset + ilen

    hash_actual = compute_hash(bytes(in_data[payload_offset:payload_limit]),
                               hash_option)
    hash_actual = [x for x in hash_actual]  # Convert to list

    hash_expected = metadata.module_hash_value[: len(hash_actual)]
    if hash_actual != hash_expected:
        raise Exception("Verification failed: payload hash mismatch")

    logger.info("Verification success!")


def main():

    ap = argparse.ArgumentParser(prog=__prog__, description=__doc__)

    sp = ap.add_subparsers(help="command")

    def cmd_fkmgen(args):
        logger.info("Creating FKM using key {}".format(args.private_key))
        build_fkm(args.private_key,
                  [args.pubkey_pem_file],
                  args.hash_option,
                  args.output_file,
                  args.svn)

    fkmp = sp.add_parser("fkmgen", help="Generate Firmware Key Manifest (FKM)")
    fkmp.add_argument(
        "-k",
        "--private-key",
        required=True,
        type=str,
        help="RSA signing key in PEM format"
    )
    fkmp.add_argument(
        "-p",
        "--pubkey-pem-file",
        type=str,
        help="Public key in PEM format. If not provided, No FBM verification.",
    )
    fkmp.add_argument(
        "-s",
        "--hash-option",
        default="sha384",
        choices=list(HASH_CHOICES.keys()),
        help="Hashing algorithm",
    )
    fkmp.add_argument(
        "-o",
        "--output-file",
        type=str,
        required=True,
        help="Output FKM file"
    )
    fkmp.add_argument(
        "-n",
        "--svn",
        default=0,
        type=int,
        help="Secure Version Number (SVN): 0-15 (default is 0)",
    )
    fkmp.set_defaults(func=cmd_fkmgen)

    def cmd_create(args):
        logger.info("Signing image using key %s (svn=%d)..." % (
                    args.private_key, args.svn))
        create_image(args.input_file,
                     args.output_file,
                     args.private_key,
                     args.hash_option,
                     args.svn)

    signp = sp.add_parser("sign", help="Sign an image")
    signp.add_argument(
        "-i",
        "--input-file",
        required=True,
        type=str,
        help="Input unsigned file"
    )
    signp.add_argument(
        "-o", "--output-file", required=True, type=str, help="Output file"
    )
    signp.add_argument(
        "-k",
        "--private-key",
        required=True,
        type=str,
        help="RSA signing key in PEM format",
    )
    signp.add_argument(
        "-s",
        "--hash-option",
        default="sha384",
        choices=list(HASH_CHOICES.keys()),
        help="Hashing algorithm",
    )
    signp.add_argument(
        "-n",
        "--svn",
        default=0,
        type=int,
        help="Secure Version Number (SVN): 0-255 (default is 0)",
    )
    signp.set_defaults(func=cmd_create)

    def cmd_decomp(args):
        logger.info("Decomposing %s ..." % args.input_file)
        decompose_image(args.input_file)

    decompp = sp.add_parser("decompose", help="Decompose a signed image")
    decompp.add_argument(
        "-i", "--input-file", required=True, type=str, help="Input image"
    )
    decompp.set_defaults(func=cmd_decomp)

    def cmd_fkmverify(args):
        logger.info("Verifying FKM ...")
        verify_fkm(args.input_file, args.pubkey_pem_file, args.fbm_pubkey_file)

    fkmverifyp = sp.add_parser("fkmcheck", help="Check if FKM image is valid")
    fkmverifyp.add_argument("-i", "--input-file",
                            required=True,
                            type=str,
                            help="Input signed image")
    fkmverifyp.add_argument(
        "-p",
        "--pubkey-pem-file",
        required=True,
        type=str,
        help="FKM Public key in PEM format",
    )
    fkmverifyp.add_argument(
        "-t",
        "--fbm-pubkey-file",
        type=str,
        help="FBM Public key in PEM format",
    )
    fkmverifyp.set_defaults(func=cmd_fkmverify)

    def cmd_verify(args):
        logger.info("Verifying a signed image ...")
        verify_image(args.input_file, args.pubkey_pem_file, args.hash_option)

    verifyp = sp.add_parser("verify", help="Verify a signed image")
    verifyp.add_argument(
        "-i", "--input-file", required=True, type=str, help="Input image"
    )
    verifyp.add_argument(
        "-p",
        "--pubkey-pem-file",
        required=True,
        type=str,
        help="Public key in PEM format",
    )
    verifyp.add_argument(
        "-s",
        "--hash-option",
        default="sha384",
        choices=list(HASH_CHOICES.keys()),
        help="Hashing algorithm",
    )
    verifyp.set_defaults(func=cmd_verify)

    ap.add_argument(
        "-V", "--version", action="version", version="%(prog)s " + __version__
    )

    args = ap.parse_args()
    print(args)
    if "func" not in args:
        ap.print_usage()
        sys.exit(2)
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
