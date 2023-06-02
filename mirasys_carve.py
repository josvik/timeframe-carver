#!/usr/bin/python3
# Script: mirasys_extract.py
# Author: Jostein Magnussen-Vik
# Created: 23.01.2023
# Modified: 13.02.2023
# Purpose: Scans image-files (RAW or EWF) for video files within a timeframe.
#          Video files from Mirasys video surveillance system.
#          Searches for indexes or frames within timeframe and tries recover as much as possible of video data.
# Dependencies: pyewf (If file is in E01 / EWF format)
# Version: 0.2

import argparse
import os
import re
import struct
from datetime import datetime

parser = argparse.ArgumentParser(description='Scans image-files (RAW or EWF) for video files within a timeframe. '
                                             'Video files from Mirasys video surveillance system. '
                                             'Searches for indexes or frames within timeframe and tries recover as much as possible of video data.')
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

file_signature = "\\x03\\xE0\\xDD\\x00"
file_offset_to_index_overview = 30
index_overview_pattern = "<TIMEFRAME><OFFSET><SIZE>"

index_signature = "\\x95\\xFD\\xB7\\x14"
index_length = 4096
index_frames_count = (10, 4)
index_frames_start = 14
index_frame_signature = "\\xA6\\x4B"
index_frame_carve_string = "\\xA6\\x4B.{3}<TIMEFRAME>"
index_frame_length = 32
index_frame_date = (5, 13)
index_frame_offset = (13, 21)
index_frame_size = (21, 25)

frame_signature = "\\x97\\x57\\x20\\x58"
frame_carve_string = "\\x97\\x57\\x20\\x58.{6}<TIMEFRAME>"
frame_header_length = 35
frame_header_date = (10, 8)
frame_header_size = (31, 4)
footer_length = 20
carve_string_length = 18
carve_haystack_length = 4096

index_signature = getBytesFromString(index_signature)
index_frame_signature = getBytesFromString(index_frame_signature)
index_frame_carve_string = getBytesFromString(index_frame_carve_string)
index_frame_carve_string = index_frame_carve_string.replace(b'<TIMEFRAME>', date_regex)

frame_signature = getBytesFromString(frame_signature)
frame_carve_string = getBytesFromString(frame_carve_string)
frame_carve_string = frame_carve_string.replace(b'<TIMEFRAME>', date_regex)

offset_skip = carve_haystack_length
full_haystack_length = carve_haystack_length + carve_string_length


def readFromImage(offset, size):
    filehandle.seek(offset)
    return filehandle.read(size)

def searchBytes(offset, size, carve_string):
    data = readFromImage(offset, size)
    carve_list = [match.start() for match in re.finditer(carve_string, data, flags=re.DOTALL)]
    return carve_list


EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as filetime
HUNDREDS_OF_NS = 10000000
# 01.01.1970 in Microsoft Ticks (LE) : 0080B5F7F57F9F08 = 621355968000000000
# 01.01.1970 in Windows Filetime (LE): 00803ED5DEB19D01 = 116444736000000000
EPOCH_DIFF = 504911232000000000


def getTicksTime(value):
    date_long_value = getLongLongLittleEndian(value)
    date_long_value -= EPOCH_DIFF

    # Code from https://github.com/jleclanche/winfiletime Because pip winfiletime contains an error.
    # Get seconds and remainder in terms of Unix epoch
    s, ns100 = divmod(date_long_value - EPOCH_AS_FILETIME, HUNDREDS_OF_NS)
    # Convert to datetime object, with remainder as microseconds.
    date_value = datetime.utcfromtimestamp(s).replace(microsecond=(ns100 // 10))

    return date_value


def getLongLongLittleEndian(value):
    return struct.unpack("<Q", value)[0]


def getIntLittleEndian(value):
    return struct.unpack("<I", value)[0]


def getDateTimeString(dateTimeValue):
    return datetime.strftime(dateTimeValue, '%Y-%m-%d_%H%M%S')


def extractDatetimeFromFrameHeader(header):
    date_bytes = header[frame_header_date[0] : frame_header_date[0] + frame_header_date[1]]
    date_value = getTicksTime(date_bytes)
    return date_value


def extractDatetimeStringFromFrameHeader(header):
    return getDateTimeString(extractDatetimeFromFrameHeader(header))


def extractSize(header):
    size_bytes = header[frame_header_size[0]: frame_header_size[0] + frame_header_size[1]]
    return getIntLittleEndian(size_bytes)


def saveToFile(start_offset, end_offset, count, start_date, end_date):
    if not os.path.exists(output_path):
        os.makedirs(output_path)

    filename = "dvrfile_" + start_date + "-" + end_date[11:17] + "_" + str(count) + "_" + str(
        start_offset) + "_" + str(end_offset) + ".dat"
    output_file = os.path.join(output_path, filename)
    print(output_file)
    with open(output_file, 'wb') as f:
        f.write(readFromImage(start_offset, (end_offset - start_offset)))


def getIndex(offset):
    index_bytes = readFromImage(offset, index_length)
    if checkSignature(index_bytes, index_signature):
        # Bytes start with a valid signature.
        return index_bytes
    elif all(b == 0 for b in index_bytes):
        # Allocated indexes containing only zeros, return empty list.
        return []
    # Not a valid index, return None
    return None


def checkSignature(bytes_value, signature):
    return bytes_value[0:len(signature)] == signature


def getFrameInfoFromIndex(found_index):
    result = []
    offset = index_frames_start
    while offset < len(found_index):
        frame_bytes = found_index[offset: offset+index_frame_length]
        if checkSignature(frame_bytes, index_frame_signature):
            date_bytes = frame_bytes[index_frame_date[0]: index_frame_date[1]]
            offset_bytes = frame_bytes[index_frame_offset[0]: index_frame_offset[1]]
            size_bytes = frame_bytes[index_frame_size[0]: index_frame_size[1]]

            result += [(getTicksTime(date_bytes), getLongLongLittleEndian(offset_bytes), getIntLittleEndian(size_bytes))]
            offset += index_frame_length
        else:
            # Reached end of index. Pattern doesn't start with index_frame_signature
            break
    return result


def isIndexSameAsFrame(index, offset):
    potential_frame_header = readFromImage(offset, frame_header_length)
    if checkSignature(potential_frame_header, frame_signature):
        frame_date = extractDatetimeFromFrameHeader(potential_frame_header)
        # If the date in the first index is the same date in frame header. We have a hit.
        return index[0] == frame_date
    return False


def searchChunksOfData():
    if not os.path.exists(output_path):
        os.makedirs(output_path)

    offset = resume_offset
    current_file_start = 0
    current_file_end = 0
    current_file_count = 0
    current_file_start_date = None
    current_file_end_date = None

    progress_report = total_size / 100
    next_progress_report = offset
    log_offset_counter = 0
    log_offset_to_file = 200000
    log_file = os.path.join(output_path, "currentOffset.log")

    current_index = []

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

        index_frame_hits = searchBytes(offset, full_haystack_length, index_frame_carve_string)
        if len(index_frame_hits) > 0:
            # Index starts at cluster start
            offset = ((offset + index_frame_hits[0]) // index_length) * index_length
            found_index = getIndex(offset)
            first_index = offset
            index_group_count = 0
            # Continue to read indexes because they can consist of groups.
            while found_index:
                index_group_count += 1
                current_index += getFrameInfoFromIndex(found_index)

                # Increase offset to check the next part.
                offset += index_length
                found_index = getIndex(offset)

                # If the next part is not index, check if it's a frame.
                if not found_index and isIndexSameAsFrame(current_index[0], offset):
                    # Calculate start of file based on first frame after index.
                    file_start = offset - current_index[0][1]
                    if current_file_start != file_start:
                        # There is a new file start. Write out the previous file.
                        if current_file_count > 0:
                            saveToFile(current_file_start, current_file_end, current_file_count,
                                       current_file_start_date, current_file_end_date)
                            current_file_count = 0
                        current_file_start = file_start
                        current_file_start_date = None

            # Check index-pointers to frames. If they are equal, move the current file end.
            for index in current_index:
                if isIndexSameAsFrame(index, current_file_start + index[1]):
                    offset = current_file_start + index[1]
                    frame_header = readFromImage(offset, frame_header_length)
                    frame_date = extractDatetimeStringFromFrameHeader(frame_header)
                    if not current_file_start_date:
                        current_file_start_date = frame_date
                    current_file_end_date = frame_date

                    offset = offset + index[2]
                    current_file_end = offset
                    current_file_count += 1
                else:
                    print("Didn't find frame: " + str(index[0]) + " Found " + str(current_file_count) + " frames")
                    # There is no frame at expected offset. Write out the file.
                    if current_file_count > 0:
                        saveToFile(current_file_start, current_file_end, current_file_count, current_file_start_date,
                                   current_file_end_date)
                        current_file_count = 0
                    current_file_start_date = None
                    current_file_start = 0
                    current_file_end = 0
                    break
            current_index = []
        else:
            # Else, if there were no hits in indexes, search for 'orphan' frames.
            hits = searchBytes(offset, full_haystack_length, frame_carve_string)
            if len(hits) > 0:
                for hit in hits:
                    hit_offset = offset + hit
                    header = readFromImage(hit_offset, frame_header_length)
                    frame_date = extractDatetimeStringFromFrameHeader(header)

                    if hit_offset > current_file_end:
                        if current_file_count > 0:
                            saveToFile(current_file_start, current_file_end, current_file_count,
                                       current_file_start_date, current_file_end_date)
                            current_file_count = 0
                        current_file_start = hit_offset
                        current_file_start_date = frame_date
                    current_blk_size = extractSize(header)
                    current_file_end = hit_offset + frame_header_length + current_blk_size + footer_length
                    current_file_end_date = frame_date
                    current_file_count += 1

        offset = offset + offset_skip
    if current_file_count > 0:
        saveToFile(current_file_start, current_file_end, current_file_count, current_file_start_date,
                   current_file_end_date)


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
