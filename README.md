DISCONTINUATION OF PROJECT

This project will no longer be maintained by Intel.

Intel has ceased development and contributions including, but not limited to, maintenance, bug fixes, new releases, or updates, to this project.  

Intel no longer accepts patches to this project.

If you have an ongoing need to use this project, are interested in independently developing it, or would like to maintain patches for the open source software community, please create your own fork of this project.  

Contact: webadmin@linux.intel.com
# Firmware and BIOS Utilities (FBU)

The project contains command line Python scripts to stitch sub-region images to Intel FirmWare Image (IFWI) and create UEFI capsule images. Optionally, signing tool is
included to generate signed sub-region image.

It supports Windows 10, Ubuntu Linux, or Yocto Linux.

- [Firmware and BIOS Utilities (FBU)](#firmware-and-bios-utilities-fbu)
  - [Guidelines for Using Signing Keys](#guidelines-for-using-signing-keys)
  - [Installation](#installation)
  - [Usage](#usage)
    - [Sub-region capsule tool](#sub-region-capsule-tool)
      - [JSON Input Format](#json-input-format)
      - [Certificate files](#certificate-files)
      - [Create capsule image](#create-capsule-image)
    - [Stitching tool](#stitching-tool)
    - [Signing tool](#signing-tool)
  - [License](#license)

## Guidelines for Using Signing Keys

SIIP tools supports signing method using asymmetric algorithms with RSA key. The following guidelines should be followed in performing digital signatures:

* RSA-3072 with hash function SHA384,512 and message formatting PSS
* Use appropriately sized keys and key parameters 
    * For Integer Factorization or Discrete Logarithm algorithms use modulus size of at least 3072 bits.
    * Use RSA public exponent value equal to 65537
    * Use approved curve for EC algorithms: NIST P-384, NIST P-521 or Ed448

> **_NOTE:_** This repository does NOT provide any keys for security reasons.


## Installation

* Install Python v3.6 and additional [modules](requirements.txt)

```
pip install -r requirements.txt
```

* Install openssl

Manually install OpenSSL to the host and add it to the system environment variable **PATH**.

Pre-compiled OpenSSL for Windows can be downloaded from [here](https://wiki.openssl.org/index.php/Binaries). You may use `apt-get` to install openssl on Ubuntu Linux.

## Usage

### Sub-region capsule tool

#### JSON Input Format

Input file to run sub-region capsule requires a JSON format that describes the data structure and field values to be serialized into binary format.

Format of the JSON payload descriptor file:

```json
  {
     "FmpGuid": <string (GUID)>,
     "Version": <integer>,
     "FV" :
     {
       "FvGuid": <string (GUID)>,
       "FfsFiles":
       [
         {
          "FileGuid": <string (GUID)>,
          "Compression": <boolean>,

          "signingKey": <string (file)>,
          "VendorGuid": <string (GUID)>,
          "signerType": <string (pkcs7 or rsa)>,

          "Data" :
          [
             [<string (member_name)>, <string (data_type)>, <integer (byte_size)>, <integer|string (member_value)>],
            ...
          ]
        }
      ]
    }
  }
```

Supported `data_type` values are "DECIMAL", "HEXADECIMAL", "STRING" or "FILE".

signingKey is optional, but if set  VendorGuid and signerType must be set as well and then subregion will be built from Data and signed using signingKey, VendorGuid, and signerType.

#### Certificate files

If the signed capsule is required, you shall provide certificates from the command line. For testing purpose, they can be downloaded from [here](https://github.com/tianocore/edk2/tree/master/BaseTools/Source/Python/Pkcs7Sign).

```
TestCert.pem
TestSub.pub.pem
TestRoot.pub.pem
```

> **_NOTE:_** if certificate files does not match the ones built in BIOS, the capsule cannot be updated.


#### Create capsule image

> **_NOTE:_** JSON_FILE should be obtained from the owners of sub-region data.


```shell
$ python3 subregion_capsule.py -o capsule.out.bin -s TestCert.pem -p TestSub.pub.pem -t TestRoot.pub.pem <JSON_FILE>

Output messages :
Read binary input file ./SubRegionFv.fv
FMP_PAYLOAD_HEADER.Signature              = 3153534D (MSS1)
FMP_PAYLOAD_HEADER.HeaderSize             = 00000010
FMP_PAYLOAD_HEADER.FwVersion              = 00000001
FMP_PAYLOAD_HEADER.LowestSupportedVersion = 00000000
...
...
EFI_CAPSULE_HEADER.CapsuleImageSize = 00001B5D
sizeof (Payload)                    = 00001B3D
Write binary output file capsule.out.bin
Success
```

The capsule file `capsule.out.bin` is generated and should be used as input file for [fwupdate](https://github.com/rhboot/fwupdate) tool on the target device to trigger capsule update.

### Stitching tool

The stitch tool can change or merge a supported sub-region file inside a full IFWI image based on UEFI Firmware Volume format.

To get a list of supported sub-regions, run:

```
$ python3 siip_stitch.py -h

usage: siip_stitch [-h] -ip ipname [-k PRIVATE_KEY] [-v] [-o FileName]
                   IFWI_IN IPNAME_IN

...
...
Supported Sub-Region Names: ['pse', 'fkm', 'tmac', 'tsnip', 'tsn', 'tcc',
'oob', 'oob_rootca', 'vbt', 'gop', 'gfxpeim']
```

To stitch a sub-region, provide the sub-region name (e.g. `pse`), IFWI image to be updated, and the sub-region file. For example:

```
$python3 siip_stitch.py -ip pse -o new.ifwi.bin ifwi.bin pse.bin

...
siip_stitch INFO *** Replacing pse ...
...
...
Decoding
Decoding
Decoding
Decoding
Decoding
Decoding
Decoding
Decoding
Create New FD file successfully.

Done!

```

### SIIP Signing tool

The SIIP Signing tool generates security signatures and auxiliary data for a _payload_ file. When BIOS loads the payload (code or data) during boot, it verifies the payload authenticity and integrity first.

For example, to sign an image with `priv3k.pem` which is a RSA-PSS private key with SHA384 hashing, run:

```
python3 siip_sign.py sign -i pse.bin -k priv3k.pem -s sha384 -m pss -o pse.signed.bin
```

The signed image (e.g. `pse.signed.bin`), is the input file to be either stitched into IFWI image, or for creating a capsule image for firmware update.

> **_NOTE:_** SIIP signing tool supports only PSE firmware signing.

### Sub-region Signing tool

The Sub-region Signing tool allows users to generate a signed BIOS Sub-Region before loading it into the BIOS UEFI to enhance the security of the sub-region firmware.

For example, to sign a TCC sub-region provided by a vendor with the given Vendor GUID 7F6AD829-15E9-4FDE-9DD3-0548BB7F56F3 using RSA private key `signing.pem`, run:

```
python3 subregion_sign.py --name  tcc --signer signing.pem --signer_type rsa
                          --vendor-guid 7F6AD829-15E9-4FDE-9DD3-0548BB7F56F3
                          TccConfigData_Raw.bin --output TccConfigData_signed.bin

```

> **_NOTE 1_:** Vendor GUID is specific value given by the vendor to the subregion being signed. Check BIOS implementation for the correct value.

> **_NOTE 2_:** The Vendor GUID used above is a default non-production GUID for sub-region.

The signed image (e.g. `TccConfigData_signed`), is the input file to be either stitched into IFWI image, or for creating a capsule image for firmware update.

> **_NOTE 3_:** Sub-region signing tool only test with a TCC sub-region. The PKCS#7 signing has not been tested at this time.

## License

See [LICENSE](LICENSE) for details.
