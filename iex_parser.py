# This program parses IEX exchange market data, given via a pcap file of packets in IEX-TP format.
#
# Benedikt Otto - b.otto.code@protonmail.com - https://github.com/mafuba8
#
import struct
import time
import sys
import gzip
import decoders.deep_1_0


class IEXFileParser:
    """
    Class for parsing PCAP files of IEX-TP packets with messages from the DEEP feed.
    """
    _MESSAGE_TYPES = decoders.deep_1_0.MESSAGE_TYPES
    _MESSAGE_TYPE_NAMES = decoders.deep_1_0.MESSAGE_TYPE_NAMES
    _CSV_HEADER_DICT = decoders.deep_1_0.CSV_HEADERS

    def __init__(self, input_file: str,
                 output_dir: str):
        self.input_file = input_file
        self.output_file_dict = {t: f'{output_dir}/output-{t}.csv' for t in self._MESSAGE_TYPES}
        self.num_packets = 0
        self._message_type_counter = {t: 0 for t in self._MESSAGE_TYPES}
        self._output_buffers = {t: [] for t in self._MESSAGE_TYPES}

    def parse(self):
        """Reads the input_file and parses the message contents. The output data will be
         written into their respective files within the output_dir directory.
         Also updates the message type counter.
        """
        print(f'Parsing file {self.input_file} ...')
        # Write CSV headers (and ensure that the files are new).
        for message_type in self._MESSAGE_TYPES:
            with open(self.output_file_dict[message_type], 'w+') as f:
                csv_header = "Packet Capture Time,Send Time Offset,Raw Time Offset,"
                csv_header += self._CSV_HEADER_DICT[message_type] + '\n'
                f.write(csv_header)

        # Open and parse the input file.
        with gzip.open(self.input_file, 'rb') as stream:
            # Parse the PcapNG header (Section Header Block).
            file_magic_number = stream.read(4)
            shb_size_raw = stream.read(4)
            byte_order_magic = stream.read(4)
            major_version = stream.read(2)
            minor_version = stream.read(2)

            # Ensure that the file has the right encoding.
            assert file_magic_number == b'\x0a\x0d\x0d\x0a', 'File must be in PcapNG format.'
            assert byte_order_magic == b'\x4d\x3c\x2b\x1a', 'File must be encoded in little endian.'
            assert major_version == b'\x01\x00' and minor_version == b'\x00\00', 'PCapNG version must be 1.0.'

            # Skip the remaining Section Header Block bytes.
            shb_size = struct.unpack('<I', shb_size_raw)[0]
            stream.read(shb_size - (4 + 4 + 4 + 2 + 2))

            # Main loop to read and process packets.
            while True:
                self.num_packets += 1

                # Read type of the next packet block.
                block_type = stream.read(4)

                # Check if the EoF is reached.
                if len(block_type) == 0:
                    print(f'End of file reached...terminating!')
                    print()
                    break

                block_size = struct.unpack('<I', stream.read(4))[0]

                # We will only parse the Enhanced Packet Blocks (EPB).
                if block_type != b'\x06\x00\x00\x00':
                    # Skip remaining bytes to get to the next block.
                    remaining_length = block_size - (4 + 4)
                    stream.read(remaining_length)
                    continue

                # Read EPB header.
                stream.read(4)  # Skip Interface ID.
                ts_upper = stream.read(4)
                ts_lower = stream.read(4)
                captured_packet_length = struct.unpack('<I', stream.read(4))[0]
                original_packet_length = struct.unpack('<I', stream.read(4))[0]

                assert captured_packet_length == original_packet_length, "We assume a smap length value of 0."

                # Timestamps are split in two 32bit blocks and in little endian.
                timestamp = struct.unpack('<Q', ts_lower + ts_upper)[0]
                # We assume that the timestamp are in microseconds (default).
                packet_capture_time_in_nanoseconds = timestamp * 1000

                # Ensure that the packet length is more than 42 bytes.
                assert captured_packet_length >= 42, f"Invalid packet length: {block_size}"

                # Skip Ethernet, IP and UDP headers to get to the IEX payload.
                offset_into_iex_payload = 14 + 20 + 8
                stream.read(offset_into_iex_payload)

                # Extract and parse IEX payload.
                iex_payload_length = captured_packet_length - offset_into_iex_payload
                iex_packet = stream.read(iex_payload_length)
                self._parse_iex_payload(iex_packet, packet_capture_time_in_nanoseconds)

                # Skip the remaining fields of the current EPB.
                rest_length = block_size - (4 + 4 + 4 + 4 + 4 + 4 + 4 + captured_packet_length)
                stream.read(rest_length)

                # Every 10 million packets, write buffer to their respective files and print a status message.
                if self.num_packets % 10_000_000 == 0:
                    for t in self._MESSAGE_TYPES:
                        with open(self.output_file_dict[t], 'a+') as f:
                            f.writelines(self._output_buffers[t])
                        self._output_buffers[t] = []

                    print(f'Parsed {self.num_packets:,} packets.')

            # Write remaining buffer to output.
            for t in self._MESSAGE_TYPES:
                with open(self.output_file_dict[t], 'a+') as f:
                    f.writelines(self._output_buffers[t])

    def print_counter(self):
        """Prints how many of each message type was processed.
        """
        print(f'Parsed {self.num_packets:,} packets:')
        for message_type in self._MESSAGE_TYPES:
            print(f'  {self._message_type_counter[message_type]:,}'
                  f' {self._MESSAGE_TYPE_NAMES[message_type]} ({message_type})')

    def _parse_iex_payload(self, iex_payload: bytes,
                           packet_capture_time: int):
        """Parses the byte payload according to the IEX-TP specification. Each IEX packet
        consists of a 40-byte header, followed by one or more messages as binary:
        [message_length][message_bytes].
        """
        # Extract the first 40 bytes of the payload.
        iex_header = iex_payload[0:40]
        message_protocol_id = struct.unpack('<H', iex_header[2:4])[0]
        channel_id = struct.unpack('<I', iex_header[4:8])[0]
        payload_len = struct.unpack('<H', iex_header[12:14])[0]
        message_count = struct.unpack('<H', iex_header[14:16])[0]
        send_time = struct.unpack('<q', iex_header[32:40])[0]

        # Ensure that the size of the payload matches the reported length in the header.
        if len(iex_payload) != payload_len + 40:
            raise Exception("Invalid parser state; the length of the IEX payload does not match the header.")

        # Ensure that the messages are in DEEP format.
        assert message_protocol_id == 0x8004 and channel_id == 1, "Input must be in DEEP1.0 format."

        # The remaining bytes are a sequence of messages.
        message_bytes = iex_payload[40:]

        # Iterate through each message in the payload.
        cur_offset = 0
        for i in range(message_count):
            # Extract the length and the bytes of the current message.
            message_len = struct.unpack('<H', message_bytes[cur_offset : cur_offset + 2])[0]
            cur_message_bytes = message_bytes[cur_offset + 2 : cur_offset + 2 + message_len]

            # Parse the current message.
            self._parse_iex_message(cur_message_bytes, packet_capture_time, send_time)

            # Move the offset to the next message.
            cur_offset += 2 + message_len

        # Ensure that the offset matches the payload length.
        if cur_offset != payload_len:
            raise Exception("Invalid parser state: cur_offset after parsing all messages does not match the header.")

    def _parse_iex_message(self, message_payload: bytes,
                           packet_capture_time: int,
                           send_time: int):
        """Parses the given message payload according to the DEEP1.0 specification and writes the
        decoded CSV line to buffer. Each DEEP message starts with a message byte indicating the
        type of message and the layout of the following bytes.
        """
        # Decode the message payload.
        raw_timestamp, message_string, message_type = decoders.deep_1_0.decode(message_payload)

        # Calculate offsets to packet capture time.
        packet_send_offset = packet_capture_time - send_time
        packet_raw_offset = packet_capture_time - raw_timestamp

        # Prepend timestamps and add full line to buffer.
        output_string = f'{packet_capture_time},{packet_send_offset},{packet_raw_offset},'
        output_string += message_string + '\n'
        self._output_buffers[message_type].append(output_string)

        # Count the message type.
        self._message_type_counter[message_type] += 1


if __name__ == "__main__":
    # Get input from CLI arguments.
    if len(sys.argv) < 3:
        print(f'Usage: {sys.argv[0]} input_file.pcap.gz output_directory')
        exit()

    INPUT_FILE = sys.argv[1]
    OUTPUT_DIR = sys.argv[2]

    # We measure the total time needed for the parse.
    time_start = time.time()

    # Create the parser object and parse the files.
    iex_parser = IEXFileParser(INPUT_FILE, OUTPUT_DIR)
    iex_parser.parse()

    # Get some statistics.
    iex_parser.print_counter()
    time_end = time.time()
    print(f'Process took {time_end - time_start:.0f} seconds.')
