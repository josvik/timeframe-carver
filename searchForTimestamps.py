#!/usr/bin/python3
# Script: searchForTimestamps.py
# Author: Jostein Magnussen-Vik
# Created: 14.12.2022
# Modified: 30.01.2023
# Purpose: Search for multiple different timestamps in a file.
# Version: 0.3

# Check list of timestamps: https://github.com/kaitai-io/kaitai_struct_webide/issues/51

# Changelog:
# v0.1: Initial file with Microsoft ticks and Windows filetime
# v0.2: Added Unix seconds and milliseconds
# v0.3: Added endianness and big-endian

import argparse
import os
import struct
from datetime import datetime, timezone
import re

parser = argparse.ArgumentParser(description='Search for timestamps in a file')
parser.add_argument('datetime', help='Datetime to search for timestamps ("DD.MM.YYYY hh:mm[:ss] [+0100]")')
parser.add_argument('filename', help='File to search in')
parser.add_argument('-o', '--outfile', help='File to output result, default is input file + "_010-bookmark.csv"')
parser.add_argument('-a', '--accuracy', choices=['h', 'm', 'l', 'high', 'medium', 'low'], default='medium',
                    help='Timeframe accuracy: high=within an hour, medium=couple of hours, low=day. Default=medium')
parser.add_argument('-e', '--endian', choices=['l', 'b', 'little', 'big'], default='little',
                    help='Endianness: little-endian or big-endian. Default=little')
parser.add_argument('-t', '--types', default="all",
                    help='Types of timestamps to search for. "ticks,filetime,unixsec,unixmicrosec,apfs" default:"all')
args = parser.parse_args()

filename = args.filename
search_datetime = ""

try:
    datetime_format = '%d.%m.%Y %H:%M'
    if len(args.datetime) > 16:
        datetime_format += ':%S'
    if len(args.datetime) < 20:
        args.datetime += ' +0000'
    datetime_format += ' %z'

    search_datetime = datetime.strptime(args.datetime, datetime_format)
except ValueError:
    print('Error in datetime format. ("DD.MM.YYYY hh:mm")')
    exit(1)

output_filename = filename + "_010-bookmark.csv"
if args.outfile:
    output_filename = args.outfile

if args.endian[0] == 'l':
    endian_f = "<"
else:
    endian_f = ">"


def createRegexRange(regex_prefix, regex_range, regex_range_step, regex_postfix):
    if args.endian[0] == 'l':
        regex_string = regex_prefix
    else:
        regex_string = ""
        for i in range(len(regex_postfix), 0, -2):
            regex_string += "\\x" + regex_postfix[i-2:i]

    if regex_range:
        midpoint = int(regex_range, 16)
        range_from = midpoint - regex_range_step
        if range_from < 0:
            range_from = 0
            range_to = regex_range_step + regex_range_step
        else:
            range_to = midpoint + regex_range_step
            if range_to > 0xff:
                range_from = 0xff - regex_range_step - regex_range_step
                range_to = 0xff
        regex_string += f"[\x5cx{range_from:02x}-\x5cx{range_to:02x}]"

    if args.endian[0] == 'l':
        for i in range(0, len(regex_postfix), 2):
            regex_string += "\\x" + regex_postfix[i:i+2]
    else:
        regex_string += regex_prefix

    regex_string = regex_string.replace("0x", "\\x")
    return bytes(regex_string, 'UTF-8')


def createRegexFor100NanoSeconds(dt, epoch):
    total_ticks = int((dt - epoch).total_seconds() * 10000000)
    hex_string = struct.pack('<Q', total_ticks).hex()
    regex_prefix = ""
    regex_range = None
    regex_range_step = None
    regex_postfix = ""
    if args.accuracy[0] == 'h':
        # High accuracy range about a second around the given datetime.
        # This is done by ranging all values for the first three bytes.
        regex_prefix = ".{3}"
        regex_postfix = hex_string[6:16]
    elif args.accuracy[0] == 'm':
        # Medium accuracy range about four hours around the given datetime.
        # This is done by ranging all values for the first four bytes and the fifth byte 0x10 up and down.
        regex_prefix = ".{4}"
        regex_range = hex_string[8:10]
        regex_range_step = 0x10
        regex_postfix = hex_string[10:16]
    elif args.accuracy[0] == 'l':
        # Low accuracy range over one month around the given datetime.
        # This is done by ranging all values for the first five bytes and the sixth byte 0x10 up and down.
        regex_prefix = ".{5}"
        regex_range = hex_string[10:12]
        regex_range_step = 0xB
        regex_postfix = hex_string[12:16]

    return createRegexRange(regex_prefix, regex_range, regex_range_step, regex_postfix)


def createRegexForMicrosoftTicks(dt):
    epoch = datetime(1, 1, 1, tzinfo=timezone.utc)
    return createRegexFor100NanoSeconds(dt, epoch)


def createRegexForWinFiletime(dt):
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    return createRegexFor100NanoSeconds(dt, epoch)


def createRegexForUnixsecond(dt):
    seconds = int(dt.timestamp())
    hex_string = struct.pack('<I', seconds).hex()
    regex_prefix = ""
    regex_range = None
    regex_postfix = ""
    if args.accuracy[0] == 'h':
        # High accuracy range two seconds around the given datetime.
        # This is done by ranging the first byte 0x02 values for the first three bytes.
        regex_range = hex_string[0:2]
        regex_range_step = 0x01
        regex_postfix = hex_string[2:8]
    elif args.accuracy[0] == 'm':
        # Medium accuracy range about four hours around the given datetime.
        # This is done by ranging all values for the first byte and the second byte 0x20 up and down.
        regex_prefix = "."
        regex_range = hex_string[2:4]
        regex_range_step = 0x20
        regex_postfix = hex_string[4:8]
    elif args.accuracy[0] == 'l':
        # Low accuracy range over one month around the given datetime.
        # This is done by ranging all values for the first five bytes and the sixth byte 0x10 up and down.
        regex_prefix = ".{2}"
        regex_range = hex_string[4:6]
        regex_range_step = 0x14
        regex_postfix = hex_string[6:8]

    return createRegexRange(regex_prefix, regex_range, regex_range_step, regex_postfix)


def createRegexForUnixmicrosecond(dt):
    microseconds = int(dt.timestamp() * 1000000)
    hex_string = struct.pack('<Q', microseconds).hex()
    regex_prefix = ""
    regex_range = None
    regex_range_step = None
    regex_postfix = ""
    if args.accuracy[0] == 'h':
        # High accuracy range two seconds around the given datetime.
        # This is done by ranging all values for the first two bytes and the third byte 0x10 up and down.
        regex_prefix = ".{2}"
        regex_range = hex_string[4:6]
        regex_range_step = 0x10
        regex_postfix = hex_string[6:16]
    elif args.accuracy[0] == 'm':
        # Medium accuracy range about four hours around the given datetime.
        # This is done by ranging all values for the first four byte and the second byte 0x20 up and down.
        regex_prefix = ".{4}"
        regex_range = hex_string[8:10]
        regex_range_step = 0x01
        regex_postfix = hex_string[10:16]
    elif args.accuracy[0] == 'l':
        # Low accuracy range over one month around the given datetime.
        # This is done by ranging all values for the first five bytes and the sixth byte 0x01 up and down.
        regex_prefix = ".{5}"
        regex_range = hex_string[10:12]
        regex_range_step = 0x01
        regex_postfix = hex_string[12:16]

    return createRegexRange(regex_prefix, regex_range, regex_range_step, regex_postfix)


def createRegexForApfsFiletime(dt):
    # 1 sec=
    # 1 000 milisec=
    # 1 000 000 microsec=
    # 1 000 000 000 nanosec
    nanoseconds = int(dt.timestamp() * 1000000000)
    hex_string = struct.pack('<Q', nanoseconds).hex()
    regex_prefix = ""
    regex_range = None
    regex_postfix = ""
    if args.accuracy[0] == 'h':
        # High accuracy range two seconds around the given datetime.
        # This is done by ranging all values for the first three bytes and the third byte 0x40 up and down.
        regex_prefix = ".{3}"
        regex_range = hex_string[6:8]
        regex_range_step = 0x40
        regex_postfix = hex_string[8:16]
    elif args.accuracy[0] == 'm':
        # Medium accuracy range about four hours around the given datetime.
        # This is done by ranging all values for the first four byte and the second byte 0x20 up and down.
        regex_prefix = ".{5}"
        regex_range = hex_string[10:12]
        regex_range_step = 0x06
        regex_postfix = hex_string[12:16]
    elif args.accuracy[0] == 'l':
        # Low accuracy range over o265ne month around the given datetime.
        # This is done by ranging all values for the first five bytes and the sixth byte 0x01 up and down.
        regex_prefix = ".{6}"
        regex_range = hex_string[12:14]
        regex_range_step = 0x04
        regex_postfix = hex_string[14:16]

    return createRegexRange(regex_prefix, regex_range, regex_range_step, regex_postfix)


EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as filetime
HUNDREDS_OF_NS = 10000000
# 01.01.1970 in Microsoft Ticks (LE) : 0080B5F7F57F9F08 = 621355968000000000
# 01.01.1970 in Windows Filetime (LE): 00803ED5DEB19D01 = 116444736000000000
EPOCH_DIFF = 504911232000000000


def getFiletimeFromLong(date_long_value):
    # Code from https://github.com/jleclanche/winfiletime Because pip winfiletime contains an error.
    # Get seconds and remainder in terms of Unix epoch
    s, ns100 = divmod(date_long_value - EPOCH_AS_FILETIME, HUNDREDS_OF_NS)
    # Convert to datetime object, with remainder as microseconds.
    date_value = datetime.utcfromtimestamp(s).replace(microsecond=(ns100 // 10))
    return date_value

def getTicksTime(value):
    date_long_value = struct.unpack(endian_f + "Q", value)[0]
    date_long_value -= EPOCH_DIFF
    return getFiletimeFromLong(date_long_value)


def getFiletime(value):
    date_long_value = struct.unpack(endian_f + "Q", value)[0]
    return getFiletimeFromLong(date_long_value)

def getUnixseconds(value):
    uintval = struct.unpack(endian_f + "I", value)[0]
    return datetime.fromtimestamp(uintval)


def getUnixmicroseconds(value):
    uintval = struct.unpack(endian_f + "Q", value)[0]
    return datetime.fromtimestamp(uintval / 1000000)

def getApfs(value):
    uintval = struct.unpack(endian_f + "Q", value)[0]
    return datetime.fromtimestamp(uintval / 1000000000)


def getRegexHits(regex, offset, timetype, name, getTimeMethod, color):
    result = ""
    if regex:
        ticks_hits = re.finditer(regex, byte_array, flags=re.DOTALL)
        for hit in ticks_hits:
            date_value = getTimeMethod(hit.group(0))
            start = hex(hit.start() + offset)[2:]
            size = hit.end() - hit.start()
            result += timetype + " " + name + "," + datetime.strftime(date_value, '%Y-%m-%d %H:%M:%S') + \
                      "," + start + "h," + str(size) + "h,Fg: Bg:0x" + color + os.linesep
    return result


if __name__ == "__main__":
    ticks_regex = None
    filetime_regex = None
    unixsec_regex = None
    unixmicrosec_regex = None
    apfs_regex = None
    if args.types == "all" or "ticks" in args.types:
        ticks_regex = createRegexForMicrosoftTicks(search_datetime)
    if args.types == "all" or "filetime" in args.types:
        filetime_regex = createRegexForWinFiletime(search_datetime)
    if args.types == "all" or "unixsec" in args.types:
        unixsec_regex = createRegexForUnixsecond(search_datetime)
    if args.types == "all" or "unixmicrosec" in args.types:
        unixmicrosec_regex = createRegexForUnixmicrosecond(search_datetime)
    if args.types == "all" or "apfs" in args.types:
        apfs_regex = createRegexForApfsFiletime(search_datetime)
    print(ticks_regex)
    print(filetime_regex)
    print(unixsec_regex)
    print(unixmicrosec_regex)
    print(apfs_regex)
    result = ""
    with open(filename, 'rb') as f:
        offset = 0
        jump = 512
        byte_array = f.read(512)
        while byte_array:
            result += getRegexHits(ticks_regex, offset, "FILETIME", "Micosoft Tics", getTicksTime, "FF3399")
            result += getRegexHits(filetime_regex, offset, "FILETIME", "Windows Filetime", getFiletime, "2525B9")
            result += getRegexHits(unixsec_regex, offset, "time_t", "Unix Seconds", getUnixseconds, "B92525")
            result += getRegexHits(unixmicrosec_regex, offset, "time_t", "Unix Microseconds", getUnixmicroseconds, "2C85DE")
            result += getRegexHits(apfs_regex, offset, "time64_t", "APFS ", getApfs, "B366FF")

            byte_array = f.read(jump)
            offset += jump
    if len(result) > 0:
        print("Result written to: " + output_filename)
        with open(output_filename, 'w') as outfile:
            outfile.write("Name,Value,Start,Size,Color" + os.linesep)
            outfile.write(result)
    else:
        print("No result in search...")
