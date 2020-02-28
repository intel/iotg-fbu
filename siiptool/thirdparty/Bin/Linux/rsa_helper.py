#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2019, Intel Corporation. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#

import os
import sys
import argparse
import uuid

from cryptography.hazmat.primitives import hashes as hashes
from cryptography.hazmat.primitives import serialization as serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding as crypto_padding

#
# GUID for SHA 256 Hash Algorithm from UEFI Specification
#
EFI_HASH_ALGORITHM_SHA256_GUID = \
    uuid.UUID("{51aa59de-fdf2-4ea3-bc63-875fb7842ee9}")

RSA_KEYMOD_SIZE = 256
RSA_KEYEXP_SIZE = 4
KB = 1024
MB = 1024 * KB


def pack_num(val, minlen=0):
    """Convert a large integer into bytearray, filling with 0 if needed"""

    buf = bytearray()
    while val > 0:
        if sys.version_info > (3, 0):
            buf += bytes([val & 0xFF])
        else:
            buf += chr(val & 0xFF)
        val >>= 8
    buf += bytearray(max(0, minlen - len(buf)))
    return buf


def get_pubkey_from_privkey(privkey_pem):
    """Extract public key from private key in PEM format"""

    with open(privkey_pem, "rb") as privkey_file:
        key = serialization.load_pem_private_key(
            privkey_file.read(), password=None, backend=default_backend()
        )

    return key.public_key()


def compute_signature(data, privkey_pem):
    """Compute signature from data"""

    with open(privkey_pem, "rb") as privkey_file:
        key = serialization.load_pem_private_key(
            privkey_file.read(), password=None, backend=default_backend()
        )

    if key.key_size < 2048:
        raise Exception("Key size {} bits is too small.".format(key.key_size))

    # Calculate signature using private key
    signature = key.sign(bytes(data), crypto_padding.PKCS1v15(),
                         hashes.SHA256())

    return (signature, key)


def main():
    """A helper script as a GUIDed tool called by FMMT"""

    parser = argparse.ArgumentParser(
        description="Strip or create signature for a GUIDed section"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-d",
        action="store_true",
        dest="decode",
        help="decode file"
    )
    group.add_argument(
        "-e",
        action="store_true",
        dest="encode",
        help="encode file"
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="output_file",
        type=str,
        metavar="filename",
        help="specify the output filename",
        required=True,
    )
    parser.add_argument(
        "--private-key",
        dest="privkey_file",
        default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "privkey.pem"),
        help="specify the private key filename. If not specified,"
             "a test signing key is used."
    )
    parser.add_argument(
        metavar="input_file",
        dest="input_file",
        help="specify the input filename"
    )

    args = parser.parse_args()

    with open(args.input_file, "rb") as in_fd:
        in_data = in_fd.read()

    # Strip GUID (16B), public key modulus (256B) and signature (256B)
    if args.decode:
        with open(args.output_file, "wb") as out_fd:
            out_fd.write(in_data[0x210:])

    # Prepend GUID (16B), public key modulus (256B) and signature (256B)
    if args.encode and args.privkey_file:
        pubkey = get_pubkey_from_privkey(args.privkey_file)
        (signature, key) = compute_signature(in_data, args.privkey_file)

        puk = get_pubkey_from_privkey(args.privkey_file)
        puk_num = puk.public_numbers()
        mod_buf = pack_num(puk_num.n, RSA_KEYMOD_SIZE)

        with open(args.output_file, "wb") as out_fd:
            out_fd.write(EFI_HASH_ALGORITHM_SHA256_GUID.bytes_le)
            out_fd.write(mod_buf[::-1])  # Reverse byte-order before saving
            out_fd.write(signature)
            out_fd.write(in_data)


if __name__ == "__main__":
    main()
