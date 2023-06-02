#!/usr/bin/python3
# Script: detec_extract.py
# Author: Jostein Magnussen-Vik
# Created: 13.04.2023
# Modified: 21.04.2023
# Purpose: Extracts frame data from xxxxx.detec files.
# Version: 0.1

import argparse
import glob
import os
import re
import struct
from datetime import datetime

# Global variables
haystack_length = 1024

frame_signature = b'\xFF\xFF\xFF\xFF'
frame_signature_offset = 8

frame_header_length = 28
frame_header_date = 0
frame_header_size = 24
frame_footer_length = 20

filehandle = None
total_size = 0
output_writer = None

resume_offset = 0


def readFromImage(offset, size):
    if offset < 0:
        return None
    filehandle.seek(offset)
    return filehandle.read(size)


def carveInImage(offset, size, carve_string):
    result = []
    # Return empty if there is nothing to search for
    if not carve_string:
        return result

    data = readFromImage(offset, size + len(carve_string))

    result = [match.start() for match in re.finditer(carve_string, data, flags=re.DOTALL)]
    return result


def getIntFromBytes(value):
    if value is None:
        return 0
    return struct.unpack('<I', value)[0]


def saveBodyToFile(file_path, start_offset, body_size):
    with open(file_path, 'ab') as f:
        f.write(readFromImage(start_offset, body_size))


def searchChunksOfData(output_file):
    offset = resume_offset

    while offset < total_size:
        # Search for frames.
        hits = carveInImage(offset, haystack_length, frame_signature)
        if len(hits) > 0:
            offset_skip = 0
            for hit in hits:
                # Frame found, get info from header.
                frame_start = offset + hit
                frame_header = readFromImage(frame_start, frame_header_length)
                frame_size = getIntFromBytes(frame_header[frame_header_size: frame_header_size + 4])

                # Save the body to file
                saveBodyToFile(output_file, offset + frame_header_length, frame_size)

                offset_skip += frame_header_length + frame_size
            offset += offset_skip
        else:
            offset += haystack_length


def extractDataFromFile(file_path, output_path):
    global filehandle, total_size
    folder_path, dvr_file = os.path.split(os.path.realpath(file_path))

    # Open file
    print("Opening {} ...".format(dvr_file))
    filehandle = open(file_path, 'rb')
    total_size = os.fstat(filehandle.fileno()).st_size
    print("Success.")

    if not output_path:
        output_path = os.path.join(folder_path, "output")
        if not os.path.exists(output_path):
            os.makedirs(output_path)

    # Base for file or folders are 'output/dvrfile_yyyy-mm-dd_hhmmss-hhmmss'
    output_file_path = os.path.join(output_path, dvr_file + ".detec")

    searchChunksOfData(output_file_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extracts frame data from xxxxx.detec files")
    parser.add_argument('path', help='File or folder to extract from.')
    parser.add_argument('-o', '--output', help='Output folder. Default is "output" in path')

    args = parser.parse_args()
    if os.path.isfile(args.path):
        extractDataFromFile(args.path, args.output)
    elif os.path.isdir(args.path):
        dvr_files = glob.glob(os.path.join(args.path, "*.detec"))
        for dvr_file in dvr_files:
            extractDataFromFile(dvr_file, args.output)
    else:
        print("File/folder not found: " + args.path)
