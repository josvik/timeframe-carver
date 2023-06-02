#!/usr/bin/python3
# Script: agentdvr_extract.py
# Author: Jostein Magnussen-Vik
# Created: 24.04.2023
# Modified: 24.04.2023
# Purpose: Scans .mkv files carved from AgentDVR system.
#          Files that fall outside a timeframe regex is moved to another directory.
#          Searches timestamps stored as metadata in mkv EBML header.
# Version: 0.1
import argparse
import glob
import os
import re
import shutil

STARTTIMESIGNATURE = b"STARTTIME..."  # \x44\x87\x92"


def getBytesFromString(string):
    # Returns a string converted to bytes. Hex-values converted, but not other characters.
    # Example: "[\x41-\x5A]" =>b'[A-Z]'
    result_bytes = b''
    i = 0
    while i < len(string):
        if string[i] == "\\" and i + 4 <= len(string):
            result_bytes += bytes.fromhex(string[i+2:i+4])
            i += 4
        else:
            result_bytes += bytes(string[i], 'utf-8')
            i += 1
    return result_bytes

def carveInBytes(data, carve_string):
    if carve_string:
        carve_list = [(match.start(), match.end()) for match in re.finditer(carve_string, data, flags=re.DOTALL)]
        return carve_list
    return []

def scanMKVfile(mkv_file_path, carve_string):
    folder_path, mkv_file = os.path.split(os.path.realpath(mkv_file_path))

    with open(mkv_file_path, "rb") as mkv_filehandle:
        # Read four clusers to make sure we get the EMBL header
        header = mkv_filehandle.read(2048)
        offsets = carveInBytes(header, carve_string)
        if offsets:
            outputHeadersFile.write(header[offsets[0][0]:offsets[0][1]])
        else:
            new_file_path = os.path.join(folder_path, "not")
            if not os.path.exists(new_file_path):
                os.makedirs(new_file_path)
            new_file_path = os.path.join(new_file_path, mkv_file)
            os.rename(mkv_file_path, new_file_path)
            print(f"Moved to {new_file_path}")

# 638031422079299991
# 638032[5-7][0-9]{11}
# 6380[0-2][0-9]{13}
outputHeadersFile = open("/media/MasterData4/AgentDVR-Win/headers.1b", "wb")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Scans .mkv files within a timeframe")
    parser.add_argument('path', help='File or folder to extract from.')
    parser.add_argument('timeframe', help='Regex-string for timeframe search.')

    args = parser.parse_args()

    carve_string = STARTTIMESIGNATURE + getBytesFromString(args.timeframe)

    if os.path.isfile(args.path):
        scanMKVfile(args.path, carve_string)
    elif os.path.isdir(args.path):
        mkv_files = glob.glob(os.path.join(args.path, "*.mkv"))
        for mkv_file in mkv_files:
            scanMKVfile(mkv_file, carve_string)
    else:
        print("File/folder not found: " + args.path)

    outputHeadersFile.close()

