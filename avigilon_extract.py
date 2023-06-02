#! /usr/bin/python
import argparse
import glob
#
# Scans ewf-files (E01) for blocks in blk-files. blk-files from Milestone XProtect video surveillance system.
# Reads timestamp and offset for block and tries to concatenate subsequent blocks into one blk-file.
#
#
#
# Usage: python ../1_carve_blk.py FILE [RESUMEOFFSET]
# FILE is ewf-file (.E01).
# RESUMEOFFSET (optional) is offset to start from.
#

import os
import struct
import sys
from datetime import datetime
from math import ceil

# if len(sys.argv) >= 2:
#     filesString = sys.argv[1]
# else:
#     print("Usage: python3 ../avigilon_extract.py FILE")
#     print("FILE is dvrfilexxxxx.dat")
#     quit()

BLOCK_SIGNATURE = b'\x64\x61\x74\x70'  # datp
BLOCK_SIGN_LENGTH = len(BLOCK_SIGNATURE)
BLOCK_HEADER_LENGTH = 32
OFFSET_SKIP = 512


def readFromFile(filehandle, size, offset):
    filehandle.seek(offset)
    return filehandle.read(size)


def hasBlockSignature(header):
    return header[4:4+BLOCK_SIGN_LENGTH] == BLOCK_SIGNATURE


def getLongLittleEndian(value):
    return struct.unpack("<L", value)[0]


def getLongBigEndian(value):
    return struct.unpack(">L", value)[0]


def getShortLittleEndian(value):
    return struct.unpack("<H", value)[0]


def extractBodySize(header):
    # body_size_data = readFromFile(4, blkOffset + 36)
    body_size_data = header[0:4]
    return getLongBigEndian(body_size_data)


def saveBodyToFile(file_path, filehandle, start_offset, body_size):
    with open(file_path, 'ab') as f:
        f.write(readFromFile(filehandle, body_size, start_offset))


def searchChunksOfData(filehandle, total_size, base_output_path):
    offset = 0
    block_seq = 0
    file_path = base_output_path + ".avigilon"
    first_block_date = None

    while offset + BLOCK_HEADER_LENGTH < total_size:
        header = readFromFile(filehandle, BLOCK_HEADER_LENGTH, offset)

        if hasBlockSignature(header):
            block_seq += 1
            body_size = extractBodySize(header)

            first_block_date = True

            # Save the body to file
            saveBodyToFile(file_path, filehandle, offset + BLOCK_HEADER_LENGTH, body_size)
            # Save the header
            saveBodyToFile(base_output_path + ".headers", filehandle, offset, BLOCK_HEADER_LENGTH)

        offset = offset + OFFSET_SKIP

    if first_block_date:
        # Create a summary for the user.
        result_text = "Frames: " + str(block_seq) + os.linesep

        result_text += "File saved: " + file_path + os.linesep
        result_text += "The videodata is not correctly stored in a mpeg4-container." + os.linesep
        result_text += "Recomended videoplayer: Media Player Classic" + os.linesep
        print(result_text)


def extractDataFromFile(dvr_file_path, output_path):
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
    base_output_path = os.path.join(output_path, dvr_file)

    searchChunksOfData(filehandle, total_size, base_output_path)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Extracts frame data from dvrfilexxxxx.dat files")
    parser.add_argument('path', help='File or folder to extract from.')
    parser.add_argument('-o', '--output', help='Output folder. Default is "output" in path')

    args = parser.parse_args()
    if os.path.isfile(args.path):
        extractDataFromFile(args.path, args.output)
    elif os.path.isdir(args.path):
        dvr_files = glob.glob(os.path.join(args.path, "*.avd"))
        for dvr_file in dvr_files:
            extractDataFromFile(dvr_file, args.output)
    else:
        print("File/folder not found: " + args.path)

