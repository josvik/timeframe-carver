#!/usr/bin/python3
# Script: detec_carve.py
# Author: Jostein Magnussen-Vik
# Created: 27.03.2023
# Modified: 19.04.2023
# Purpose: Scans image-files (RAW or EWF) for video files within a timeframe.
#          Video files from Detec video surveillance system.
#          Searches for frames within timeframe and tries recover as much as possible of video data.
# Dependencies: pyewf (If file is in E01 / EWF format)
# Version: 0.1

import argparse
import os
import re
import struct
from datetime import datetime

# Global variables
haystack_length = 1024

frame_signature = "\xFF\xFF\xFF\xFF"
frame_signature_offset = 8
frame_carve_string = b"<TIMEFRAME>\xFF\xFF\xFF\xFF"

frame_header_length = 28
frame_header_date = 0
frame_header_size = 24
frame_footer_length = 20

filehandle = None
total_size = 0
output_writer = None

resume_offset = 0


class OutputWriter:
    def __init__(self, path, prefix, suffix):
        self.out_path = path
        self.out_prefix = prefix
        self.out_suffix = suffix
        self.file_start = 0
        self.file_end = 0
        self.from_date = ""
        self.to_date = ""
        self.frame_count = 0

        if not os.path.exists(self.out_path):
            os.makedirs(self.out_path)

        self.log_file = os.path.join(self.out_path, "currentOffset.log")

    def saveToFile(self):
        if self.frame_count > 0 and self.file_end > self.file_start:
            filename = f'{self.out_prefix}{self.from_date}-{self.to_date[11:17]}_{self.frame_count}_{self.file_start}_{self.file_end}{self.out_suffix}'
            output_file = os.path.join(self.out_path, filename)
            print(output_file)
            with open(output_file, 'wb') as f:
                f.write(readFromImage(self.file_start, (self.file_end - self.file_start)))

        self.frame_count = 0
        self.from_date = None
        self.to_date = None

    def writeLog(self, logline):
        with open(self.log_file, 'w') as f:
            f.write(logline)

    def setFileStartEnd(self, start, end):
        if start <= self.file_start:
            # If the start is before current start, move to new offset.
            self.file_start = start
        elif start <= self.file_end:
            # the start is before or at the end, file continues. Expand file to new end
            if end > self.file_end:
                self.file_end = end
        else:
            #if self.file_start != start:
            self.saveToFile()

            self.file_start = start
            self.file_end = end

    def increaseFrameCount(self):
        self.frame_count += 1

    def setDate(self, date):
        if not self.from_date:
            self.from_date = date
        self.to_date = date


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


# 01.01.1970 in Microsoft Ticks (LE) : 0080B5F7F57F9F08 = 621355968000000000
EPOCH_AS_TICKS_TIME = 621355968000000000  # January 1, 1970 as ticks
HUNDREDS_OF_NS = 10000000


def getTicksTime(value):
    if value is None:
        return None
    date_long_value = getLongLongFromBytes(value)

    # Code from https://github.com/jleclanche/winfiletime Because pip winfiletime contains an error.
    # Get seconds and remainder in terms of Unix epoch
    s, ns100 = divmod(date_long_value - EPOCH_AS_TICKS_TIME, HUNDREDS_OF_NS)
    # Convert to datetime object, with remainder as microseconds.
    date_value = datetime.utcfromtimestamp(s).replace(microsecond=(ns100 // 10))

    return date_value


def getLongLongFromBytes(value):
    if value is None:
        return 0
    return struct.unpack('<Q', value)[0]


def getIntFromBytes(value):
    if value is None:
        return 0
    return struct.unpack('<I', value)[0]


def getDateTimeString(value):
    return datetime.strftime(value, '%Y-%m-%d_%H%M%S')


def searchChunksOfData():
    offset = resume_offset

    progress_report = total_size / 100
    next_progress_report = offset
    next_offset_to_file = offset
    log_offset_to_file = 200000

    while offset < total_size:
        # Write offset to file, makes it easier to resume
        if offset >= log_offset_to_file:
            output_writer.writeLog(str(offset))
            next_offset_to_file += log_offset_to_file

        # Write progress report to console
        if offset >= next_progress_report:
            print("Searching... " + str(100 * offset // total_size) + "% Current offset: " + str(offset) + " / " + str(total_size))
            next_progress_report += progress_report

        # Search for frames.
        hits = carveInImage(offset, haystack_length, frame_carve_string)
        if len(hits) > 0:
            for hit in hits:
                # Frame found, get info from header.
                frame_start = offset + hit
                frame_header = readFromImage(frame_start, frame_header_length)
                date_from_ticks = getTicksTime(frame_header[frame_header_date: frame_header_date + 8])
                frame_date = getDateTimeString(date_from_ticks)
                frame_size = getIntFromBytes(frame_header[frame_header_size: frame_header_size + 4])
                frame_end = frame_start + frame_header_length + frame_size + frame_footer_length
                # Update info to output writer. setFileStartEnd() writes to file if there is no contiguous file.
                output_writer.setFileStartEnd(frame_start, frame_end)
                output_writer.setDate(frame_date)
                output_writer.increaseFrameCount()

        offset = offset + haystack_length

    # Write out the last frame.
    output_writer.saveToFile()


def parseArguments():
    global frame_carve_string
    parser = argparse.ArgumentParser(description='Scans image-files (RAW or EWF) for video files within a timeframe. '
                                                 'Video files from Detec video surveillance system. '
                                                 'Searches for frames within timeframe and tries recover as much as possible of video data.')

    parser.add_argument('filename', help='Image-file to scan. RAW or EFW-format')
    parser.add_argument('timeframe', help='Regex-string for timeframe search.')
    parser.add_argument('-o', '--output', help='Path to output result, default is image folder + "/output/"')
    parser.add_argument('-r', '--resume', type=int, help='Resume from offset.')
    arguments = parser.parse_args()

    date_regex = getBytesFromString(arguments.timeframe)
    frame_carve_string = frame_carve_string.replace(b'<TIMEFRAME>', date_regex)

    return arguments


def openImageFile(filename):
    global filehandle, total_size

    if not os.path.isfile(filename):
        print("File not found: " + filename)
        exit(1)

    image_folder_path, image_file = os.path.split(os.path.realpath(filename))

    # Open file
    print("Opening {} ...".format(image_file))
    if image_file[-4:].upper() == ".E01":
        import pyewf

        filenames = pyewf.glob(filename)
        filehandle = pyewf.handle()
        filehandle.open(filenames, 'rb')
        total_size = filehandle.get_media_size()
    else:
        filehandle = open(filename, 'rb')
        total_size = os.fstat(filehandle.fileno()).st_size


def createOutputWriter(output, filename):
    global output_writer
    if output:
        output_path = output
    else:
        image_folder_path, image_file = os.path.split(os.path.realpath(filename))
        output_path = os.path.join(image_folder_path, "output")

    output_writer = OutputWriter(output_path, "", ".detec")


if __name__ == "__main__":
    args = parseArguments()
    openImageFile(args.filename)
    createOutputWriter(args.output, args.filename)

    if args.resume:
        resume_offset = args.resume

    searchChunksOfData()
