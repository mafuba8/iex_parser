# This file contains classes that represent decoders for the IEX data feeds.
#
# Benedikt Otto - b.otto.code@protonmail.com - https://github.com/mafuba8
#
import iex_messages

#############################
### Defining IEX Messages included in each feed.
#############################
decoder_message_classes = {
    'DEEP_1_0': {
        # Administrative Messages
        'S': iex_messages.SystemEvent,
        'D': iex_messages.SecurityDirectory,
        'H': iex_messages.TradingStatus,
        'I': iex_messages.RetailLiquidityIndictor,
        'O': iex_messages.OperationalHaltStatus,
        'P': iex_messages.ShortSalePriceTestStatus,
        'E': iex_messages.SecurityEvent,
        # Trading Messages
        '8': iex_messages.PriceLevelUpdate,
        '5': iex_messages.PriceLevelUpdate,
        'T': iex_messages.TradeReport,
        'X': iex_messages.OfficialPrice,
        'B': iex_messages.TradeBreak,
        # Auction Messages
        'A': iex_messages.AuctionInformation
    },

    'TOPS_1_6': {
        # Administrative Messages
        'S': iex_messages.SystemEvent,
        'D': iex_messages.SecurityDirectory,
        'H': iex_messages.TradingStatus,
        'I': iex_messages.RetailLiquidityIndictor,
        'O': iex_messages.OperationalHaltStatus,
        'P': iex_messages.ShortSalePriceTestStatus,
        # Trading Messages
        'Q': iex_messages.QuoteUpdate,
        'T': iex_messages.TradeReport,
        'X': iex_messages.OfficialPrice,
        'B': iex_messages.TradeBreak,
        # Auction Messages
        'A': iex_messages.AuctionInformation
    }
}


#############################
### IEX Messages for each feed.
#############################
class Decoder:
    """Class representing a decoder for different given feed types."""
    def __init__(self, feed: str):
        match feed:
            case 'DEEP_1_0':
                self.feed_name = 'DEEP 1.0'
                self.message_protocol_id = 0x8004
                self.channel_id = 1
                self.message_classes = decoder_message_classes['DEEP_1_0']
            case 'TOPS_1_6':
                self.feed_name = 'TOPS 1.6'
                self.message_protocol_id = 0x8003
                self.channel_id = 1
                self.message_classes = decoder_message_classes['TOPS_1_6']
            case _:
                raise Exception(f'Unknown feed type: "{feed}".')

        # List of message type for messages in the given feed format.
        self.message_types = [message_type for message_type in self.message_classes]
        self.message_type_names = {message_type: self.message_classes[message_type].message_type_name
                                   for message_type in self.message_types}
        self.csv_header_dict = {message_type: self.message_classes[message_type].csv_header
                                for message_type in self.message_types}

    def decode(self, message_payload: bytes) -> iex_messages.Message:
        """Decodes and parses the message payload.

        Returns an object of the corresponding message class.
        """
        # Read the message type byte.
        message_type = chr(message_payload[0])
        if message_type in self.message_classes:
            # Return an instance of the message class.
            return self.message_classes[message_type](message_payload)
        else:
            raise Exception(f'Unknown {self.feed_name} message type: "{message_type}".')
