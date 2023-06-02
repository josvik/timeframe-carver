#!/usr/bin/python3
# Script: mirasys_extract.py
# Author: Jostein Magnussen-Vik
# Created: 06.02.2023
# Modified: 13.02.2023
# Purpose: Extracts frame data from dvrfilexxxxx.dat files.
# Version: 0.2

import argparse
import glob
import os
import re
import struct
from datetime import datetime


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


filehandle = None

carve_string_length = 18
carve_haystack_length = 4096

frame_signature = "\\x97\\x57\\x20\\x58"
frame_header_length = 35
frame_footer_length = 20

frame_header_date = (10, 8)
frame_header_size = (31, 4)
frame_carve_string = getBytesFromString(frame_signature)


full_haystack_length = carve_haystack_length + carve_string_length


def readFromImage(offset, size):
    filehandle.seek(offset)
    return filehandle.read(size)

def searchBytes(offset, size, carve_string):
    data = readFromImage(offset, size)
    carve_list = [match.start() for match in re.finditer(carve_string, data, flags=re.DOTALL)]
    return carve_list


def searchBytes(offset, size, carve_string):
    data = readFromImage(offset, size)
    carve_list = [match.start() for match in re.finditer(carve_string, data, flags=re.DOTALL)]
    return carve_list


EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as filetime
HUNDREDS_OF_NS = 10000000
# 01.01.1970 in Microsoft Ticks (LE) : 0080B5F7F57F9F08 = 621355968000000000
# 01.01.1970 in Windows Filetime (LE): 00803ED5DEB19D01 = 116444736000000000
EPOCH_DIFF = 504911232000000000


def getIntLittleEndian(value):
    return struct.unpack("<I", value)[0]


def extractSize(header):
    size_bytes = header[frame_header_size[0]: frame_header_size[0] + frame_header_size[1]]
    return getIntLittleEndian(size_bytes)


def saveBodyToFile(file_path, start_offset, body_size):
    with open(file_path, 'ab') as f:
        f.write(readFromImage(start_offset, body_size))


def searchChunksOfData(total_size, output_file):
    offset = 0

    while offset < total_size:
        hits = searchBytes(offset, full_haystack_length, frame_carve_string)
        if len(hits) > 0:
            for hit in hits:
                hit_offset = offset + hit
                header = readFromImage(hit_offset, frame_header_length)
                body_size = extractSize(header)
                # Save the body to file
                saveBodyToFile(output_file, offset + frame_header_length, body_size)
                offset = hit_offset + frame_header_length + body_size + frame_footer_length
        else:
            offset += carve_haystack_length

    result_text = "File saved: " + output_file + os.linesep
    result_text += "The videodata is not correctly stored in a video-container." + os.linesep
    result_text += "Recommended videoplayer: ffplay (ffmpeg) " + os.linesep
    print(result_text)


def extractDataFromFile(dvr_file_path, output_path):
    global filehandle
    folder_path, dvr_file = os.path.split(os.path.realpath(dvr_file_path))

    # Open file
    print("Opening {} ...".format(dvr_file))
    filehandle = open(dvr_file_path, 'rb')
    total_size = os.fstat(filehandle.fileno()).st_size
    print("Success.")

    if not output_path:
        output_path = os.path.join(folder_path, "output")
        if not os.path.exists(output_path):
            os.makedirs(output_path)

    # Base for file or folders are 'output/dvrfile_yyyy-mm-dd_hhmmss-hhmmss'
    output_file = os.path.join(output_path, dvr_file[:32] + ".mirasys")

    searchChunksOfData(total_size, output_file)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Extracts frame data from dvrfilexxxxx.dat files")
    parser.add_argument('path', help='File or folder to extract from.')
    parser.add_argument('-o', '--output', help='Output folder. Default is "output" in path')

    args = parser.parse_args()
    if os.path.isfile(args.path):
        extractDataFromFile(args.path, args.output)
    elif os.path.isdir(args.path):
        dvr_files = glob.glob(os.path.join(args.path, "dvrfile*.dat"))
        for dvr_file in dvr_files:
            extractDataFromFile(dvr_file, args.output)
    else:
        print("File/folder not found: " + args.path)

