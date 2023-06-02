#! /usr/bin/python
# Script: avigilon_extract.py
# Author: Jostein Magnussen-Vik
# Created: 02.03.2023
# Modified: 17.03.2023
# Purpose: Extracts frame data from xxxxx.avd files.
# Version: 0.2

import argparse
import glob
import os
import struct

frame_signature = b'datp'
frame_signature_offset = 4
frame_header_length = 32
OFFSET_SKIP = 512


def readFromFile(filehandle, size, offset):
    filehandle.seek(offset)
    return filehandle.read(size)


def hasBlockSignature(header):
    return header[frame_signature_offset : frame_signature_offset + len(frame_signature)] == frame_signature


def getLongBigEndian(value):
    return struct.unpack(">L", value)[0]


def extractBodySize(header):
    body_size_data = header[0:4]
    return getLongBigEndian(body_size_data)


def saveBodyToFile(file_path, filehandle, start_offset, body_size):
    with open(file_path, 'ab') as f:
        f.write(readFromFile(filehandle, body_size, start_offset))


def searchChunksOfData(filehandle, total_size, output_file):
    offset = 0
    block_seq = 0

    while offset + frame_header_length < total_size:
        header = readFromFile(filehandle, frame_header_length, offset)

        if hasBlockSignature(header):
            block_seq += 1
            body_size = extractBodySize(header)

            # Save the body to file
            saveBodyToFile(output_file, filehandle, offset + frame_header_length, body_size)
            # Save the header
            #saveBodyToFile(output_file + ".headers", filehandle, offset, frame_header_length)

        offset = offset + OFFSET_SKIP

    if block_seq > 0:
        # Create a summary for the user.
        result_text = "Frames: " + str(block_seq) + os.linesep
        result_text += "File saved: " + output_file + os.linesep
        result_text += "The videodata is not correctly stored in a mpeg4-container." + os.linesep
        result_text += "Recomended videoplayer: ffplay " + os.linesep
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
    output_file_path = os.path.join(output_path, dvr_file + ".avigilon")

    searchChunksOfData(filehandle, total_size, output_file_path)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Extracts frame data from xxxxx.avd files")
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

