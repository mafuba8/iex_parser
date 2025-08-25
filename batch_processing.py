import os
import re
import subprocess

INPUT_DIR = 'example'
#INPUT_DIR = 'data'
OUTPUT_DIR = 'output'

IEX_PARSER = 'python3 iex_parser.py'

regex = re.compile(r'^data_feeds_(\d{8})_.*.pcap\.gz$')

for pcap_file in os.listdir(INPUT_DIR):
    s = regex.search(pcap_file)
    if s:
        output = os.path.join(OUTPUT_DIR, s.group(1))
        print(f'Parsing {pcap_file} ...')

        command = f"gunzip -d -c {pcap_file} | tcpdump -r - -s 0 -w - | {IEX_PARSER} /dev/stdin {output}"
        print(command)
        # subprocess.run(command, shell=True)

