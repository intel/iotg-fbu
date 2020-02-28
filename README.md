# Firmware and BIOS Utilities

The project contains Python scripts to stitch sub-region images to Intel FirmWare Image (IFWI) and create UEFI capsule for these sub-region images.

These scripts are command line and requires Python3.

## Host Requirement

- Windows 10 or Ubuntu Linux
- Python 3.7 or newer and additional [modules](requirements.txt)
- openssl

## Get Started

### Install required dependencies

```
pip install -r requirements.txt
```

### Install openssl

Manually install OpenSSL to the host and add it to the system environment variable **PATH**.

Pre-compiled OpenSSL for Windows can be downloaded from [here](https://wiki.openssl.org/index.php/Binaries). You may use `apt-get` to install openssl on Ubuntu Linux.

## sub-region capsule tool

### JSON Input Format

The main input to run sub-region capsule is in JSON format that describes the data values to be serialized into binary format.

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

### Certificate files

For security reasons, certificates are not provided in this project. For testing purpose, you can download them from [here](https://github.com/tianocore/edk2/tree/master/BaseTools/Source/Python/Pkcs7Sign).

```
TestCert.pem
TestSub.pub.pem
TestRoot.pub.pem
```

> **_NOTE:_** if certificate files does not match the ones built in BIOS, the capsule cannot be updated.


### Create sub-region capsule image

```shell
python3 subregion_capsule.py -o capsule.out.bin --signer-private-cert=TestCert.pem --other-public-cert=TestSub.pub.pem --trusted-public-cert=TestRoot.pub.pem <JSON_FILE>
```

The content of `JSON_FILE` should be obtained from sub-region owner team.


```
Output messages :
Read binary input file ./SubRegionFv.fv
FMP_PAYLOAD_HEADER.Signature              = 3153534D (MSS1)
FMP_PAYLOAD_HEADER.HeaderSize             = 00000010
FMP_PAYLOAD_HEADER.FwVersion              = 00000001
FMP_PAYLOAD_HEADER.LowestSupportedVersion = 00000000
sizeof (Payload)                          = 00001000
EFI_FIRMWARE_IMAGE_AUTHENTICATION.MonotonicCount                = 0000000000000000
EFI_FIRMWARE_IMAGE_AUTHENTICATION.AuthInfo.Hdr.dwLength         = 00000AED
EFI_FIRMWARE_IMAGE_AUTHENTICATION.AuthInfo.Hdr.wRevision        = 0200
EFI_FIRMWARE_IMAGE_AUTHENTICATION.AuthInfo.Hdr.wCertificateType = 0EF1
EFI_FIRMWARE_IMAGE_AUTHENTICATION.AuthInfo.CertType             = 4AAFD29D-68DF-49EE-8AA9-347D375665A7
sizeof (EFI_FIRMWARE_IMAGE_AUTHENTICATION.AuthInfo.CertData)    = 00000AD5
sizeof (Payload)                                                = 00001010
EFI_FIRMWARE_MANAGEMENT_CAPSULE_HEADER.Version             = 00000001
EFI_FIRMWARE_MANAGEMENT_CAPSULE_HEADER.EmbeddedDriverCount = 00000000
EFI_FIRMWARE_MANAGEMENT_CAPSULE_HEADER.PayloadItemCount    = 00000001
EFI_FIRMWARE_MANAGEMENT_CAPSULE_HEADER.ItemOffsetList      =
  0000000000000010
EFI_FIRMWARE_MANAGEMENT_CAPSULE_IMAGE_HEADER.Version                = 00000002
EFI_FIRMWARE_MANAGEMENT_CAPSULE_IMAGE_HEADER.UpdateImageTypeId      = 6FEE88FF-49ED-48F1-B77B-EAD15771ABE7
EFI_FIRMWARE_MANAGEMENT_CAPSULE_IMAGE_HEADER.UpdateImageIndex       = 00000001
EFI_FIRMWARE_MANAGEMENT_CAPSULE_IMAGE_HEADER.UpdateImageSize        = 00001B05
EFI_FIRMWARE_MANAGEMENT_CAPSULE_IMAGE_HEADER.UpdateVendorCodeSize   = 00000000
EFI_FIRMWARE_MANAGEMENT_CAPSULE_IMAGE_HEADER.UpdateHardwareInstance = 0000000000000000
sizeof (Payload)                                                    = 00001B05
sizeof (VendorCodeBytes)                                            = 00000000
EFI_CAPSULE_HEADER.CapsuleGuid      = 6DCBD5ED-E82D-4C44-BDA1-7194199AD92A
EFI_CAPSULE_HEADER.HeaderSize       = 00000020
EFI_CAPSULE_HEADER.Flags            = 00050000
  OEM Flags                         = 0000
  CAPSULE_FLAGS_PERSIST_ACROSS_RESET
  CAPSULE_FLAGS_INITIATE_RESET
EFI_CAPSULE_HEADER.CapsuleImageSize = 00001B5D
sizeof (Payload)                    = 00001B3D
Write binary output file capsule.out.bin
Success
```

The capsule file `capsule.out.bin` is generated and should be used as input file for [fwupdate](https://github.com/rhboot/fwupdate) tool on the target device to trigger capsule update.

## License

See [LICENSE.txt](LICENSE.txt) for details.

