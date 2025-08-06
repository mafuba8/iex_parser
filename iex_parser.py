# This program parses IEX exchange market data, given via a pcap file of packets in IEX-TP format.
#
# Benedikt Otto - b.otto.code@protonmail.com
#
import struct
import time
import sys
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
        self._message_decoder = {t: decoders.deep_1_0.get_decoder(t) for t in self._MESSAGE_TYPES}


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
        with open(self.input_file, 'rb') as stream:
            # Skip the PCAP file header (24 bytes).
            stream.read(24)

            # Main loop to read and process packets.
            while True:
                self.num_packets += 1

                # Read packet
                packet_header_len = 4 + 4 + 4 + 4
                packet_header = stream.read(packet_header_len)

                # Check if the EoF is reached or the packet header is incomplete.
                if len(packet_header) == 0:
                    print(f'End of file reached...terminating!')
                    print()
                    break

                # Unpack the pcap packet header.
                ts_sec = struct.unpack('<I', packet_header[0:4])[0]  # Timestamp (seconds)
                ts_usec = struct.unpack('<I', packet_header[4:8])[0]  # Timestamp (microseconds)
                incl_len = struct.unpack('<I', packet_header[8:12])[0]  # Captured Packet length
                orig_len = struct.unpack('<I', packet_header[12:16])[0]  # Original Packet length

                # Calculate packet timestamp in nanoseconds.
                packet_capture_time_in_nanoseconds = int((ts_sec * 1e9) + (ts_usec * 1e3))

                # Skip Ethernet, IP and UDP headers to get to the IEX payload (42 bytes).
                offset_into_iex_payload = 14 + 20 + 8
                stream.read(offset_into_iex_payload)

                # Ensure that the packet length is less than 42 bytes.
                if incl_len < 42:
                    raise Exception(f"Invalid packet length: {incl_len}.")

                # Extract and parse IEX payload.
                iex_payload_length = incl_len - offset_into_iex_payload
                iex_packet = stream.read(iex_payload_length)
                self._parse_iex_payload(iex_packet, packet_capture_time_in_nanoseconds)

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
            message_len = struct.unpack('<H', message_bytes[cur_offset:cur_offset + 2])[0]
            cur_message_bytes = message_bytes[cur_offset + 2:cur_offset + 2 + message_len]

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
        """Parses the given message payload according to the DEEP specification and writes the
        decoded CSV line to buffer. Each DEEP message starts with a message byte indicating the
        type of message and the layout of the following bytes.
        """
        # Extract the message type byte.
        message_type = chr(message_payload[0])

        # Decode message and write the output strings to buffer.
        if message_type in self._MESSAGE_TYPES:
            self._message_type_counter[message_type] += 1

            # Decode the message payload.
            decoder = self._message_decoder[message_type]
            raw_timestamp, message_string = decoder(message_payload)

            # Calculate offsets to packet capture time.
            packet_send_offset = packet_capture_time - send_time
            packet_raw_offset = packet_capture_time - raw_timestamp

            # Prepend timestamps and add full line to buffer.
            output_string = f'{packet_capture_time},{packet_send_offset},{packet_raw_offset},'
            output_string += message_string + '\n'
            self._output_buffers[message_type].append(output_string)


if __name__ == "__main__":
    # Get input from CLI arguments.
    if len(sys.argv) < 3:
        print(f'Usage: {sys.argv[0]} input_file.raw output_directory')
        print(f'For example:')
        print(f'   gunzip -d -c FILE.pcap.gz | tcpdump -r - -w - -s 0 | '
              f'python3 {sys.argv[0]} /dev/stdin output_folder')
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
