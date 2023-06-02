#!/usr/bin/python3
# Script: mirasys_extract.py
# Author: Jostein Magnussen-Vik
# Created: 03.06.2019
# Modified: 08.02.2023
# Purpose: Scans image-files (RAW or EWF) for video files within a timeframe.
#          Video files from Milestone XProtect video surveillance system.
#          Reads timestamp and offset for block and tries to concatenate subsequent blocks into one blk-file.
# Dependencies: pyewf (If file is in E01 / EWF format)
# Version: 0.7

import argparse
import os
import re
import struct
from datetime import datetime

parser = argparse.ArgumentParser(description='Scans image-files (RAW or EWF) for video files within a timeframe.'
                                             'Video files from Milestone XProtect video surveillance system.'
                                             'Reads timestamp and offset for block and tries to concatenate subsequent blocks into one blk-file.')
parser.add_argument('filename', help='Image-file to scan. RAW or EFW-format')
parser.add_argument('timeframe', help='Regex-string for timeframe search.')
parser.add_argument('-o', '--output', help='Path to output result, default is image folder + "/output/"')
parser.add_argument('-r', '--resume', type=int, help='Resume from offset.')
args = parser.parse_args()

if not os.path.isfile(args.filename):
    print("File not found: " + args.filename)
    exit(1)

image_file_path = args.filename
image_folder_path, image_file = os.path.split(os.path.realpath(image_file_path))

output_path = os.path.join(image_folder_path, "output")
if args.output:
    output_path = args.output

resume_offset = 0
if args.resume:
    resume_offset = args.resume


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


date_regex = getBytesFromString(args.timeframe)

total_size = 0
filehandle = None

carve_string = "<TIMEFRAME><TIMEFRAME>.{16}<TIMEFRAME><TIMEFRAME>"
header_length = 32
header_date_offset = 0
header_date_length = 8
header_size_offset = 24
header_size_length = 4
carve_string_length = 48
carve_haystack_length = 512

carve_string = getBytesFromString(carve_string)
carve_string = carve_string.replace(b'<TIMEFRAME>', date_regex)

offset_skip = carve_haystack_length
full_haystack_length = carve_haystack_length + carve_string_length


def readFromImage(size, offset):
    filehandle.seek(offset)
    return filehandle.read(size)


def searchBytes(size, offset):
    data = readFromImage(size, offset)
    carve_list = [match.start() for match in re.finditer(carve_string, data, flags=re.DOTALL)]
    return carve_list


EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as filetime
HUNDREDS_OF_NS = 10000000


def getFiletime(date_data):
    date_long_value = struct.unpack("<Q", date_data)[0]

    # Code from https://github.com/jleclanche/winfiletime Because pip winfiletime contains an error.
    # Get seconds and remainder in terms of Unix epoch
    s, ns100 = divmod(date_long_value - EPOCH_AS_FILETIME, HUNDREDS_OF_NS)
    # Convert to datetime object, with remainder as microseconds.
    date_value = datetime.utcfromtimestamp(s).replace(microsecond=(ns100 // 10))

    return date_value


def getLongBigEndian(value):
    return struct.unpack(">L", value)[0]


def getLongLittleEndian(value):
    return struct.unpack("<L", value)[0]


def getDateTimeString(value):
    return datetime.strftime(value, '%Y-%m-%d_%H%M%S')


def extractDate(header):
    date_bytes = header[header_date_offset : header_date_offset + header_date_length]
    return getDateTimeString(getFiletime(date_bytes))


def extractSize(header):
    size_bytes = header[header_size_offset : header_size_offset + header_size_length]
    return getLongLittleEndian(size_bytes)


def saveToFile(start_offset, end_offset, count, start_date, end_date):
    if not os.path.exists(output_path):
        os.makedirs(output_path)
    filename = "blk_" + start_date + "-" + end_date + "_" + str(count) + "_" + str(
        start_offset) + "_" + str(end_offset) + ".blk"
    output_file = os.path.join(output_path, filename)
    print(output_file)
    with open(output_file, 'wb') as f:
        f.write(readFromImage((end_offset - start_offset), start_offset))


def searchChunksOfData():
    if not os.path.exists(output_path):
        os.makedirs(output_path)

    offset = resume_offset
    current_blk_start_offset = 0
    current_blk_end_offset = 0
    current_blk_count = 0
    current_blk_start_date = "null"
    current_blk_end_date = "null"

    progress_report = total_size / 100
    next_progress_report = 0
    log_offset_counter = 0
    log_offset_to_file = 200000
    log_file = os.path.join(output_path, "currentOffset.log")

    while offset < total_size:
        log_offset_counter += 1
        if log_offset_counter > log_offset_to_file:
            log_offset_counter = 0
            with open(log_file, 'w') as f:
                f.write(str(offset))

        if offset >= next_progress_report:
            print("Searching... " + str(100 * offset // total_size) + "% Current offset: " + str(
                offset) + " / " + str(total_size))
            next_progress_report = next_progress_report + progress_report

        hits = searchBytes(full_haystack_length, offset)
        if len(hits) > 0:
            for hit in hits:
                hit_offset = offset + hit
                header = readFromImage(header_length, hit_offset)
                blk_date = extractDate(header)

                if hit_offset > current_blk_end_offset:
                    if current_blk_count > 0:
                        saveToFile(current_blk_start_offset, current_blk_end_offset, current_blk_count,
                                   current_blk_start_date, current_blk_end_date)
                        current_blk_count = 0
                    current_blk_start_offset = hit_offset
                    current_blk_start_date = blk_date
                current_blk_size = extractSize(header)
                current_blk_end_offset = hit_offset + header_length + current_blk_size
                current_blk_end_date = blk_date[11:17]
                current_blk_count = current_blk_count + 1

        offset = offset + offset_skip
    if current_blk_count > 0:
        saveToFile(current_blk_start_offset, current_blk_end_offset, current_blk_count, current_blk_start_date,
                   current_blk_end_date)


# Open file
print("Opening {} ...".format(image_file))
if image_file[-4:].upper() == ".E01":
    import pyewf

    filenames = pyewf.glob(image_file_path)
    filehandle = pyewf.handle()
    filehandle.open(filenames, 'rb')
    total_size = filehandle.get_media_size()
else:
    filehandle = open(image_file_path, 'rb')
    total_size = os.fstat(filehandle.fileno()).st_size

searchChunksOfData()
