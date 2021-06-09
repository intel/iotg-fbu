#!/usr/bin/env python

"""Release script to package required files"""

import os
import sys
import zipfile
import subprocess
from datetime import datetime
import fileinput
from shutil import move

OUTDIR = "dist"

BOM = [
    "scripts",
    "common",
    "thirdparty",
    "bin"
]

g_fmmt_config_file = "FmmtConf.ini"
g_rsa_helper_exe = ""
g_fmmt_path = ""
g_fmmt_config_path = ""
g_backup_extention = '.bak'

def change_fmmt_conf():
    global g_fmmt_path
    global g_rsa_helper_exe
    if sys.platform == 'win32':
        g_fmmt_path= os.path.join(os.path.dirname(__file__),
                                  "thirdparty", "Bin", "Win32")
        g_rsa_helper_exe = "rsa_helper.exe"
    elif sys.platform == 'linux':
        g_fmmt_path = os.path.join(os.path.dirname(__file__),
                                   "thirdparty", "Bin", "Linux")
        g_rsa_helper_exe = "rsa_helper"
    global g_fmmt_config_path
    g_fmmt_config_path = os.path.join(g_fmmt_path, g_fmmt_config_file)
    with fileinput.FileInput(g_fmmt_config_path, inplace=True, backup=g_backup_extention) as file:
        for line in file:
            print(line.replace("rsa_helper.py", g_rsa_helper_exe), end='')

def cleanup():
    move(g_fmmt_config_path + g_backup_extention, g_fmmt_config_path)
    os.remove(os.path.join(g_fmmt_path, g_rsa_helper_exe))

def generate_rsa_helper_exe():
    if sys.platform == 'win32':
        subprocess.check_call(r"pyinstaller thirdparty/Bin/Win32/rsa_helper.py "
					  r"--onefile --distpath ./thirdparty/Bin/Win32")
    elif sys.platform == 'linux':
        subprocess.check_call(r"pyinstaller thirdparty/Bin/Linux/rsa_helper.py "
				  r"--onefile --distpath ./thirdparty/Bin/Linux",
				  shell=True)

def generate_exe():
    generate_rsa_helper_exe()
    change_fmmt_conf()
    if sys.platform == 'win32':
        subprocess.check_call(r"pyinstaller scripts/siip_sign.py "
                              r"--onefile --distpath ./bin")
        subprocess.check_call(r"pyinstaller scripts/siip_stitch.py "
                              r"--add-binary "
                              r"thirdparty/Bin/Win32/;thirdparty/Bin/Win32 "
                              r"--add-data "
                              r"common/ip_options.json;common "
                              r"--onefile --distpath ./bin")
        subprocess.check_call(r"pyinstaller scripts/subregion_capsule.py "
                              r"--add-binary "
                              r"thirdparty/Bin/Win32/;thirdparty/Bin/Win32 "
                              r"--add-data "
                              r"common/ip_options.json;common "
                              r"--onefile --distpath ./bin")
        subprocess.check_call(r"pyinstaller scripts/subregion_sign.py "
                              r"--add-binary "
                              r"thirdparty/Bin/Win32/;thirdparty/Bin/Win32 "
                              r"--onefile --distpath ./bin")
    elif sys.platform == 'linux':
        subprocess.check_call(r"pyinstaller scripts/siip_sign.py "
                              r"--onefile --distpath ./bin",
                              shell=True)
        subprocess.check_call(r"pyinstaller scripts/siip_stitch.py "
                              r"--add-binary "
                              r"thirdparty/Bin/Linux/:thirdparty/Bin/Linux "
                              r"--add-data "
                              r"common/ip_options.json;common "
                              r"--onefile --distpath ./bin",
                              shell=True)
        subprocess.check_call(r"pyinstaller scripts/subregion_capsule.py "
                              r"--add-binary "
                              r"thirdparty/Bin/Linux/:thirdparty/Bin/Linux "
                              r"--add-data "
                              r"common/ip_options.json;common "
                              r"--onefile --distpath ./bin",
                              shell=True)
        subprocess.check_call(r"pyinstaller scripts/subregion_sign.py "
                              r"--add-binary "
                              r"thirdparty/Bin/Linux/:thirdparty/Bin/Linux "
                              r"--onefile --distpath ./bin",
                              shell=True)

def create_archive(out_zip, file_list):

    dest_list = []
    for name in file_list:
        if os.path.isdir(name):
            for root, dirs, files in os.walk(name):
                for f in files:
                    if "__pycache__" in root:
                        continue
                    ff = os.path.join(root, f)
                    dest_list.append(ff)
        else:
            dest_list.append(name)

    with zipfile.ZipFile(out_zip, "w") as zip_fd:
        for f in dest_list:
            zip_fd.write(f)
        zip_fd.printdir()
        print("*** Total files: {}".format(len(zip_fd.namelist())))

def main():

    date_created = datetime.now().strftime('%Y%m%d')
    os_str = sys.platform.lower()
    if os_str.startswith('win'):
        os_str = 'win'
    zip_file = os.path.join(OUTDIR, "fbu_siiptool_{}_{}.zip"
                            .format(os_str, date_created))
    generate_exe()

    if not os.path.exists(OUTDIR):
        os.mkdir(OUTDIR)
    create_archive(zip_file, BOM)
    cleanup()


if __name__ == "__main__":
    sys.exit(main())
