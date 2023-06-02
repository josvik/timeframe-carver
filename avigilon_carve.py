#!/usr/bin/python3
# Script: avigilon_carve.py
# Author: Jostein Magnussen-Vik
# Created: 15.02.2023
# Modified: 17.03.2023
# Purpose: Scans image-files (RAW or EWF) for video files within a timeframe.
#          Video files from Avigilon video surveillance system.
#          Searches for indexes within timeframe and tries recover as much as possible of video data.
# Dependencies: pyewf (If file is in E01 / EWF format)
# Version: 0.1


import argparse
import os
import re
import struct
from datetime import datetime


# Global variables
haystack_length = 1024
haystack_length_extra = 32
file_signature = b'avfs'
file_signature_offset = 4

index_signature = b'rcfc'
index_signature_offset = 4
index_carve_string = b'.{4}rcfc.*tkfh.{6}<TIMEFRAME>'
index_at_modulo_bytes = 512
index_date_signature = b'tkfh'
index_date_offset = 10

index_frame_signature = b'\x12'
index_frame_signature_offset = 0
index_frame_footer_length = 2

index_frame_carve_string = b'\x12.\x08.\x10.{1,8}\x18.{1,8}\x30\x65\x38\x00\x40\x00.*tkfc.{4}tkfh.{6}<TIMEFRAME>'
index_frame_size_offset = 5
index_frame_offset_signature = b'\x18'

frame_signature = b'datp'
frame_signature_offset = 4
frame_header_length = 32

filehandle = None
total_size = 0
output_writer = None


class OutputWriter:
    def __init__(self, path):
        self.out_path = path
        self.file_start = 0
        self.file_end = 0
        self.from_date = None
        self.to_date = None
        self.frame_count = 0

        if not os.path.exists(self.out_path):
            os.makedirs(self.out_path)

        self.log_file = os.path.join(self.out_path, "currentOffset.log")

    def saveToFile(self):
        if self.frame_count > 0 and self.file_end > self.file_start:
            filename = f'{self.from_date}-{self.to_date}_{self.frame_count}_{self.file_start}_{self.file_end}.avd'
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
            self.saveToFile()

            self.file_start = start
            self.file_end = end

    def increaseFrameCount(self):
        self.frame_count += 1

    def setDate(self, date):
        if not self.from_date:
            self.from_date = date
        self.to_date = date[11:17]


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


def regexFindInBytes(data, carve_string):
    if carve_string:
        carve_list = [match.start() for match in re.finditer(carve_string, data, flags=re.DOTALL)]
        return carve_list
    return []


def getLongLongFromBytes(value):
    if value is None:
        return 0
    return struct.unpack('>Q', value)[0]


def getIntFromBytes(value):
    if value is None:
        return 0
    return struct.unpack('>I', value)[0]


def getByteFromBytes(value):
    if value is None:
        return None
    return struct.unpack('>B', value)[0]


def getLeb128FromBytes(byte_array):
    uint = 0
    if byte_array:
        i = 0
        for byte in byte_array:
            sign_bit = byte >> 7
            byte = byte & 0x7f
            byte = byte << 7 * i
            uint |= byte
            if sign_bit != 0x01:
                break
            i += 1
    return uint


NANOSECONDS = 1000000000


def getApfsTime(value):
    if value is None:
        return None
    date_long_value = getLongLongFromBytes(value)

    s, ns = divmod(date_long_value, NANOSECONDS)
    # Convert to datetime object, with remainder as microseconds.
    date_value = datetime.utcfromtimestamp(s).replace(microsecond=(ns // 1000))

    return date_value


def getDateTimeString(value):
    return datetime.strftime(value, '%Y-%m-%d_%H%M%S')


def extractSizeFromFrameHeader(frame_header):
    size = getIntFromBytes(frame_header[0:4])
    return size


def checkSignature(bytes_value, signature, signature_offset):
    if not bytes_value:
        return False
    if signature:
        return bytes_value[signature_offset: signature_offset + len(signature)] == signature
    return True


def getIndex(offset):
    index_length = getIntFromBytes(readFromImage(offset, 4))
    index_bytes = readFromImage(offset, index_length)
    if checkSignature(index_bytes, index_signature, index_signature_offset):
        # Bytes start with a valid signature.
        return index_bytes
    # Not a valid index, return None
    return None


def getDateFromIndex(found_index):
    date_value = None
    offsets = regexFindInBytes(found_index, index_date_signature)
    if offsets:
        offset = offsets[0] + index_date_offset
        date_bytes = found_index[offset: offset+8]
        date_value = getApfsTime(date_bytes)
    return date_value


def getFrameInfoFromIndex(found_index):
    result = []
    offsets = regexFindInBytes(found_index, index_frame_carve_string)
    if len(offsets) > 0:
        offset = offsets[0]
        while offset < len(found_index):
            frame_bytes = found_index[offset:]
            index_frame_field_length = getByteFromBytes(frame_bytes[1:2])
            frame_bytes = frame_bytes[0: index_frame_field_length + index_frame_footer_length]

            if checkSignature(frame_bytes, index_frame_signature, index_frame_signature_offset):
                index_frame_size = getLeb128FromBytes(frame_bytes[index_frame_size_offset:])
                index_frame_offset_hit = regexFindInBytes(frame_bytes, index_frame_offset_signature)
                if index_frame_offset_hit:
                    index_frame_offset = getLeb128FromBytes(frame_bytes[index_frame_offset_hit[0]+1:])

                result.append({"offset": index_frame_offset, "size": index_frame_size})
                offset += len(frame_bytes)
            else:
                # Reached end of index. Pattern doesn't start with index_frame_signature
                break
    return result


def isIndexSameAsFrame(index_frame_size, frame_header):
    if checkSignature(frame_header, frame_signature, frame_signature_offset):
        frame_size = extractSizeFromFrameHeader(frame_header)
        # Compare index to frame header, if size is same: we have a hit
        return index_frame_size == frame_size
    return False


def searchChunksOfData(resume):

    offset = resume

    progress_report = total_size / 100
    next_progress_report = offset
    log_offset_counter = 0
    log_offset_to_file = 200000

    current_index = []

    while offset < total_size:
        log_offset_counter += 1
        if log_offset_counter > log_offset_to_file:
            log_offset_counter = 0
            output_writer.writeLog(str(offset))

        if offset >= next_progress_report:
            print("Searching... " + str(100 * offset // total_size) + "% Current offset: " + str(
                offset) + " / " + str(total_size))
            next_progress_report = next_progress_report + progress_report

        haystack = readFromImage(offset, haystack_length + haystack_length_extra)
        index_hits = regexFindInBytes(haystack, index_carve_string)
        if len(index_hits) == 0:
            index_hits = regexFindInBytes(haystack, index_frame_carve_string)
        if len(index_hits) > 0:
            offset += index_hits[0]

            # Index starts at start of cluster or sector
            offset = (offset // index_at_modulo_bytes) * index_at_modulo_bytes

            found_index = getIndex(offset)
            index_start = offset
            index_date = getDateFromIndex(found_index)
            index_date_string = getDateTimeString(index_date)
            current_index += getFrameInfoFromIndex(found_index)
            offset += len(found_index)

            # Actual start of file. Set to currently non-overwritten part.
            file_start = index_start
            file_end = index_start
            # Reference value for frames offset.
            # If file start is not overwritten this will be equal to current_file_start
            logical_file_start = None
            if current_index:
                # Reverse the list to read the frames closest to the index first.
                current_index.reverse()

                # Calculate file start from the offset to the frame closest to the index.
                for index in current_index:
                    potential_file_start = index_start - index["offset"] - index["size"]

                    # If logical_file_start is not set, set it to potential_file_start.
                    logical_file_start = logical_file_start or potential_file_start

                    if potential_file_start >= 0:
                        file_start_bytes = readFromImage(potential_file_start, file_signature_offset + len(file_signature))
                        if checkSignature(file_start_bytes, file_signature, file_signature_offset):
                            logical_file_start = potential_file_start
                            break

                # Verify the frames the index is pointing to.
                for index in current_index:
                    # Test offset from logical_file_st art, since the start of file might be overwritten.
                    frame_offset = logical_file_start + index["offset"]
                    frame_header = readFromImage(frame_offset, frame_header_length)
                    if isIndexSameAsFrame(index["size"], frame_header):
                        if frame_offset < file_start:
                            # Move the file_start to the earliest point of carved bytes.
                            file_start = frame_offset

                        file_end = offset
                        output_writer.setDate(index_date_string)
                        output_writer.increaseFrameCount()
                    else:
                        print("Couldn't find frame @" + str(frame_offset) + ": " + str(index["offset"]))
                        break
            current_index = []
            output_writer.setFileStartEnd(file_start, file_end)

        else:

            offset = offset + haystack_length

    output_writer.saveToFile()


def parseArguments():
    parser = argparse.ArgumentParser(description='Scans image-files (RAW or EWF) for video files within a timeframe. '
                                                 'Video files from Avigilon video surveillance system. '
                                                 'Searches for indexes within timeframe and tries recover as much as possible of video data.')
    parser.add_argument('filename', help='Image-file to scan. RAW or EFW-format')
    parser.add_argument('timeframe', help='Regex-string for timeframe search.')
    parser.add_argument('-o', '--output', help='Path to output result, default is image folder + "/output/"')
    parser.add_argument('-r', '--resume', type=int, help='Resume from offset.')
    arguments = parser.parse_args()

    return arguments


def readTimeframe(timeframe):
    global index_carve_string, index_frame_carve_string

    date_regex = getBytesFromString(timeframe)
    index_carve_string = index_carve_string.replace(b'<TIMEFRAME>', date_regex)
    index_frame_carve_string = index_frame_carve_string.replace(b'<TIMEFRAME>', date_regex)


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

    output_writer = OutputWriter(output_path)


if __name__ == "__main__":
    args = parseArguments()
    readTimeframe(args.timeframe)
    openImageFile(args.filename)
    createOutputWriter(args.output, args.filename)

    resume_offset = 0
    if args.resume:
        resume_offset = args.resume

    searchChunksOfData(resume_offset)
