# Example for using the iex_parser to parse all pcap.gz files in a given input directory.
#
# Usage:
#    python3 batch_parse.py <input_dir> <output_dir>
#
# Parses all files *_DEEP1.0.pcap.gz in the input_dir into folders named by the date:
#    <output_dir>/DEEP1.0/YYYYMMDD/output-X.csv
#
# Benedikt Otto - b.otto.code@protonmail.com - https://github.com/mafuba8
#
import iex_parser
import re
import time
import sys
import os
from pathlib import Path
from multiprocessing import Pool


# Set number of processes to run in parallel.
NUM_OF_PROCESSES = 4

def parse_file(file_tuple):
    input_file, output_dir, feed_type = file_tuple
    time_start = time.time()

    # Create the parser object and parse the files.
    decoder = iex_parser.Decoder(feed_type)
    parser = iex_parser.IEXFileParser(input_file, output_dir, decoder)
    parser.parse()

    print(f'Parsed {os.path.basename(input_file)} in {time.time() - time_start:.0f}'
          f' seconds ({parser.num_packets:,} packets).')


if __name__ == '__main__':
    # Get input from CLI arguments.
    if len(sys.argv) < 3:
        print(f'Usage: {sys.argv[0]} input_directory output_directory')
        exit()

    DIR_INPUT = Path(sys.argv[1])
    DIR_OUTPUT = Path(sys.argv[2])

    # Build list of files to be parsed.
    input_file_list = []
    regex_deep_10 = re.compile(r'^data_feeds_(\d{8})_(\d{8})_IEXTP1_DEEP1\.0\.pcap\.gz$')
    regex_tops_16 = re.compile(r'^data_feeds_(\d{8})_(\d{8})_IEXTP1_TOPS1\.6\.pcap\.gz$')
    for file in DIR_INPUT.iterdir():
        os.path.basename(file)
        s_deep_10 = regex_deep_10.search(file.name)
        s_tops_16 = regex_tops_16.search(file.name)

        if s_deep_10:
            date_stamp = s_deep_10.group(1)
            out_dir = (DIR_OUTPUT / 'DEEP1.0' / date_stamp)
            out_dir.mkdir(parents=True, exist_ok=True)
            arg_tuple = (file, out_dir, 'DEEP_1_0')
            input_file_list.append(arg_tuple)
        elif s_tops_16:
            date_stamp = s_tops_16.group(1)
            out_dir = (DIR_OUTPUT / 'TOPS1.6' / date_stamp)
            out_dir.mkdir(parents=True, exist_ok=True)
            arg_tuple = (file, out_dir, 'TOPS_1_6')
            input_file_list.append(arg_tuple)

    # Parse the files in parallel.
    with Pool(processes=NUM_OF_PROCESSES) as pool:
        pool.map(func=parse_file, iterable=input_file_list)
