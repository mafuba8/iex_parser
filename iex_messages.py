# This file contains classes that represent the different types
# of IEX messages.
#
# Benedikt Otto - b.otto.code@protonmail.com - https://github.com/mafuba8
#
import struct
from datetime import datetime
from typing import Union

type Message = Union[SystemEvent, SecurityDirectory, TradingStatus, RetailLiquidityIndictor,
                     OperationalHaltStatus, ShortSalePriceTestStatus, SecurityEvent, QuoteUpdate,
                     PriceLevelUpdate, TradeReport, OfficialPrice, TradeBreak, AuctionInformation]

#############################
### Helper functions
#############################
def unix_to_date(t: int) -> tuple[str, str]:
    """Helper function that converts the given unix timestamp (in nanoseconds)
    into iso formats of their date and time parts."""
    dt = datetime.fromtimestamp(t / 1_000_000_000)
    return dt.date().isoformat(), dt.time().isoformat()


#############################
### Message Classes: Administrative Message Formats
#############################
class SystemEvent:
    """Class representing a System Event Message (message type 'S')."""
    message_type = 'S'
    message_type_name = 'System Event'
    csv_header = 'Tick Type,System Event'

    def __init__(self, message_payload: bytes):
        assert len(message_payload) == 10, "System Event Message payload size should be 10 bytes."
        assert chr(message_payload[0]) == 'S', "Wrong message type bit."

        # Extract data from the payload.
        self.system_event_type = chr(message_payload[1])
        timestamp_raw = struct.unpack('<q', message_payload[2:10])[0]

        self.timestamp = timestamp_raw

    def to_string(self):
        system_event_string = ''
        match self.system_event_type:
            case 'O':  # Start of Messages.
                system_event_string = 'MESSAGES_START'
            case 'S':  # Start of System Hours
                system_event_string = 'SYSTEM_HOURS_START'
            case 'R':  # Start of Regular Market Hours
                system_event_string = 'REGULAR_MARKET_START'
            case 'M':  # End of Regular Market Hours
                system_event_string = 'REGULAR_MARKET_END'
            case 'E':  # End of System Hours
                system_event_string = 'SYSTEM_HOURS_END'
            case 'C':  # End of Messages
                system_event_string = 'MESSAGES_END'
            case _:
                raise Exception('Invalid System Event Message flag')

        # Create message string.
        message_string = f'S,{system_event_string}'
        return message_string

    def to_dict(self):
        message_dict = {}

        # Time and date from timestamp.
        date, time = unix_to_date(self.timestamp)
        message_dict['date'] = date
        message_dict['time'] = time

        message_dict['system_event_type'] = self.system_event_type
        return message_dict


class SecurityDirectory:
    """Class representing a Security Directory Message (message type 'D')."""
    message_type = 'D'
    message_type_name = 'Security Directory'
    csv_header = 'Tick Type,Symbol,Round Lot Size,Adjusted POC Price,LULD Tier,Security Directory Flags'

    def __init__(self, message_payload: bytes):
        assert len(message_payload) == 31, "Security Directory Message payload size should be 31 bytes."
        assert chr(message_payload[0]) == 'D', "Wrong message type bit."

        # Extract data from the payload.
        sd_flag_byte = message_payload[1]
        timestamp_raw = struct.unpack('<q', message_payload[2:10])[0]
        symbol_raw = struct.unpack('<8s', message_payload[10:18])[0]
        round_lot_size = struct.unpack('<I', message_payload[18:22])[0]
        adjusted_poc_price_raw = struct.unpack('<q', message_payload[22:30])[0]
        luld_tier_int = message_payload[30]

        self.is_test_sec = sd_flag_byte & 0x80
        self.is_issued_sec = sd_flag_byte & 0x40
        self.is_etp = sd_flag_byte & 0x20
        self.timestamp = timestamp_raw
        self.symbol = symbol_raw.decode().strip()
        self.round_lot_size = round_lot_size
        self.adjusted_poc_price = round(adjusted_poc_price_raw * 1e-4, 2)
        self.luld_tier = luld_tier_int

    def to_string(self):
        # Determine security directory flags.
        sd_flags = []
        if self.is_test_sec:  # Symbol is a test security
            sd_flags.append('TEST_SECURITY')
        if self.is_issued_sec:  # Symbol is a when issued security
            sd_flags.append('WHEN_ISSUED')
        if self.is_etp:  # Symbol is an ETP
            sd_flags.append('ETP')
        sd_flag_string = '|'.join(sd_flags)

        # Determine LULD tier.
        luld_tier_string = ''
        match self.luld_tier:
            case 0:  # Not applicable
                luld_tier_string = 'NOT_APPLICABLE'
            case 1:  # Tier 1 NMS Stock
                luld_tier_string = 'TIER1_NMS_STOCK'
            case 2:  # Tier 2 NMS Stock
                luld_tier_string = 'TIER2_NMS_STOCK'
            case _:
                raise Exception('Invlaid Security Direcrity Message LULD Tier flag.')

        # Create message string.
        message_string = (f'D,{self.symbol},{self.round_lot_size},{self.adjusted_poc_price},'
                          f'{luld_tier_string},{sd_flag_string}')
        return message_string

    def to_dict(self):
        message_dict = {}

        # Time and date from timestamp.
        date, time = unix_to_date(self.timestamp)
        message_dict['date'] = date
        message_dict['time'] = time

        message_dict['test_security'] = self.is_test_sec
        message_dict['issued_security'] = self.is_issued_sec
        message_dict['etp'] = self.is_etp

        message_dict['symbol'] = self.symbol
        message_dict['round_lot_size'] = self.round_lot_size
        message_dict['adjusted_poc_price'] = self.adjusted_poc_price
        message_dict['luld_tier'] = self.luld_tier

        return message_dict


class TradingStatus:
    """Class representing a Trading Status Message (message type 'H')."""
    message_type = 'H'
    message_type_name = 'Trading Status'
    csv_header = 'Tick Type,Symbol,Trading Status,Reason'

    def __init__(self, message_payload: bytes):
        assert len(message_payload) == 22, "Trading Status Message payload size should be 22 bytes."
        assert chr(message_payload[0]) == 'H', "Wrong message type bit."

        # Extract data from the payload.
        trading_status_int = message_payload[1]
        timestamp_raw = struct.unpack('<q', message_payload[2:10])[0]
        symbol_raw = struct.unpack('<8s', message_payload[10:18])[0]
        reason_raw = struct.unpack('<4s', message_payload[18:22])[0]

        self.trading_status = chr(trading_status_int)
        self.timestamp = timestamp_raw
        self.symbol = symbol_raw.decode().strip()
        self.reason = reason_raw.decode().strip()

    def to_string(self):
        # Determine trading status.
        trading_status_string = ''
        match self.trading_status:
            case 'H':  # Trading halted across all US equity markets
                trading_status_string = 'HALTED'
            case 'O':  # Trading halt released into an Order Acceptance Period in IEX
                trading_status_string = 'HALT_RELEASED_INTO_OAP'
            case 'P':  # Trading paused and Order Acceptance Period on IEX
                trading_status_string = 'PAUSED'
            case 'T':  # Trading on IEX
                trading_status_string = 'TRADING'

        # Create message string.
        message_string = f'H,{self.symbol},{trading_status_string},{self.reason}'
        return message_string

    def to_dict(self):
        message_dict = {}

        # Time and date from timestamp.
        date, time = unix_to_date(self.timestamp)
        message_dict['date'] = date
        message_dict['time'] = time

        message_dict['trading_status'] = self.trading_status
        message_dict['symbol'] = self.symbol
        message_dict['reason'] = self.reason

        return message_dict


class RetailLiquidityIndictor:
    """Class representing a Retail Liquidity Indicator Message (message type 'I')."""
    message_type = 'I'
    message_type_name = 'Retail Liquidity Indicator'
    csv_header = 'Tick Type,Symbol,Retail Liquidity Indicator'

    def __init__(self, message_payload: bytes):
        assert len(message_payload) == 18, "Retail Liquidity Indicator Message payload size should be 18 bytes."
        assert chr(message_payload[0]) == 'I', "Wrong message type bit."

        # Extract data from the payload.
        retail_liquidity_indicator_int = message_payload[1]
        timestamp_raw = struct.unpack('<q', message_payload[2:10])[0]
        symbol_raw = struct.unpack('<8s', message_payload[10:18])[0]

        self.retail_liquidity_indicator = chr(retail_liquidity_indicator_int)
        self.timestamp = timestamp_raw
        self.symbol = symbol_raw.decode().strip()

    def to_string(self):
        # Determine retail liquidity indicator.
        retail_liquidity_indicator_string = ''
        match self.retail_liquidity_indicator:
            case ' ':  # Retail indicator not applicable
                retail_liquidity_indicator_string = 'NOT_APPLICABLE'
            case 'A':  # Buy interest for Retail
                retail_liquidity_indicator_string = 'BUY_INTEREST'
            case 'B':  # Sell interest for Retail
                retail_liquidity_indicator_string = 'SELL_INTEREST'
            case 'C':  # Buy and sell interest for Retail
                retail_liquidity_indicator_string = 'BUY_INTEREST|SELL_INTEREST'
            case _:
                raise Exception('Invalid Retail Liquidity Indicator flag')

        # Create message string.
        message_string = f'I,{self.symbol},{retail_liquidity_indicator_string}'
        return message_string

    def to_dict(self):
        message_dict = {}

        # Time and date from timestamp.
        date, time = unix_to_date(self.timestamp)
        message_dict['date'] = date
        message_dict['time'] = time

        message_dict['retail_liquidity_indicator'] = self.retail_liquidity_indicator
        message_dict['symbol'] = self.symbol

        return message_dict


class OperationalHaltStatus:
    """Class representing an Operational Halt Message (message type 'O')."""
    message_type = 'O'
    message_type_name = 'Operational Halt Status'
    csv_header = 'Tick Type,Symbol,Operational Halt Status'

    def __init__(self, message_payload: bytes):
        assert len(message_payload) == 18, "Operational Halt Status Message payload size should be 18 bytes."
        assert chr(message_payload[0]) == 'O', "Wrong message type bit."

        # Extract data from the payload.
        operational_halt_status_int = message_payload[1]
        timestamp_raw = struct.unpack('<q', message_payload[2:10])[0]
        symbol_raw = struct.unpack('<8s', message_payload[10:18])[0]

        self.timestamp = timestamp_raw
        self.operational_halt_status = chr(operational_halt_status_int)
        self.symbol = symbol_raw.decode().strip()

    def to_string(self):
        # Determine operational halt status.
        operational_halt_status_string = ''
        match self.operational_halt_status:
            case 'O':  # IEX specific operational trading halt
                operational_halt_status_string = 'HALTED'
            case 'N':  # Not operationally halted on IEX
                operational_halt_status_string = 'NOT_HALTED'
            case _:
                raise Exception('Invalid Operational Halt Status Message flag')

        # Create message string.
        message_string = f'O,{self.symbol},{operational_halt_status_string}'
        return message_string

    def to_dict(self):
        message_dict = {}

        # Time and date from timestamp.
        date, time = unix_to_date(self.timestamp)
        message_dict['date'] = date
        message_dict['time'] = time

        message_dict['operational_halt_status'] = self.operational_halt_status
        message_dict['symbol'] = self.symbol

        return message_dict


class ShortSalePriceTestStatus:
    """Class representing a Short Sale Price Test Statzs Message (message type 'P')."""
    message_type = 'P'
    message_type_name = 'Short Sale Price Test Status'
    csv_header = 'Tick Type,Symbol,Short Sale Price Test Status,Detail'

    def __init__(self, message_payload: bytes):
        assert len(message_payload) == 19, "Short Sale Price Test Status Message payload size should be 19 bytes."
        assert chr(message_payload[0]) == 'P', "Wrong message type bit."

        # Extract data from the payload.
        short_sale_price_test_status = message_payload[1]
        timestamp_raw = struct.unpack('<q', message_payload[2:10])[0]
        symbol_raw = struct.unpack('<8s', message_payload[10:18])[0]
        detail_int = message_payload[18]

        self.short_sale_price_test_status = short_sale_price_test_status
        self.timestamp = timestamp_raw
        self.symbol = symbol_raw.decode().strip()
        self.price_test_detail = chr(detail_int)

    def to_string(self):
        # Determine short sale price test status.
        status_string = ''
        match self.short_sale_price_test_status:
            case 0:  # Short Sale Price Test Not in Effect
                status_string = 'NOT_IN_EFFECT'
            case 1:  # Short Sale Price Test in Effect
                status_string = 'IN_EFFECT'
            case _:
                raise Exception('Invalid Short Sale Price Test Status flag')

        # Determine short sale price test detail.
        detail_string = ''
        match self.price_test_detail:
            case ' ':  # No price test in place
                detail_string = 'NO_PRICE_TEST'
            case 'A':  # Restrictions in effect due to an intraday price drop in the security
                detail_string = 'RES_ACTIVATED'
            case 'C':  # Restriction remains in effect from prior day
                detail_string = 'RES_CONTINUED'
            case 'D':  # Restriction deactivated
                detail_string = 'RES_DEACTIVATED'
            case 'N':  # Detail not available
                detail_string = 'NOT_AVAILABLE'
            case _:
                raise Exception('Invalid Short Sale Price Test Detail flag')

        # Create message string.
        message_string = f'P,{self.symbol},{status_string},{detail_string}'
        return message_string

    def to_dict(self):
        message_dict = {}

        # Time and date from timestamp.
        date, time = unix_to_date(self.timestamp)
        message_dict['date'] = date
        message_dict['time'] = time

        message_dict['in_effect'] = False
        if self.short_sale_price_test_status == 1:
            message_dict['in_effect'] = True

        message_dict['symbol'] = self.symbol
        message_dict['price_test_detail'] = self.price_test_detail

        return message_dict


class SecurityEvent:
    """Class representing a Security Event Message (message type 'E')."""
    message_type = 'E'
    message_type_name = 'Security Event'
    csv_header = 'Tick Type,Symbol,Security Event'

    def __init__(self, message_payload: bytes):
        assert len(message_payload) == 18, "Security Event Message payload size should be 18 bytes."
        assert chr(message_payload[0]) == 'E', "Wrong message type bit."

        # Extract data from the payload.
        security_event_int = message_payload[1]
        timestamp_raw = struct.unpack('<q', message_payload[2:10])[0]
        symbol_raw = struct.unpack('<8s', message_payload[10:18])[0]

        self.security_event = chr(security_event_int)
        self.timestamp = timestamp_raw
        self.symbol = symbol_raw.decode().strip()

    def to_string(self):
        # Determine security event.
        security_event_string = ''
        match self.security_event:
            case 'O':  # Opening Process Complete
                security_event_string = 'OPENING'
            case 'C':  # Closing Process Complete
                security_event_string = 'CLOSING'

        # Create message string.
        message_string = f'E,{self.symbol},{security_event_string}'
        return message_string

    def to_dict(self):
        message_dict = {}

        # Time and date from timestamp.
        date, time = unix_to_date(self.timestamp)
        message_dict['date'] = date
        message_dict['time'] = time

        message_dict['security_event'] = self.security_event
        message_dict['symbol'] = self.symbol

        return message_dict


#############################
### Message Classes: Trading Message Formats
#############################
class QuoteUpdate:
    """Class representing a Quote Update Message (message type 'Q')."""
    message_type = 'Q'
    message_type_name = 'Quote Update'
    csv_header = 'Tick Type,Symbol,Bid Size,Bid Price,Ask Size,Ask Price,Quote Flags'

    def __init__(self, message_payload: bytes):
        assert len(message_payload) == 42, "Quote Update Message payload size should be 42 bytes."
        assert chr(message_payload[0]) == 'Q', "Wrong message type bit."

        # Extract data from the payload.
        quote_update_flags = message_payload[1]
        timestamp_raw = struct.unpack('<q', message_payload[2:10])[0]
        symbol_raw = struct.unpack('<8s', message_payload[10:18])[0]
        bid_size = struct.unpack('<I', message_payload[18:22])[0]
        bid_price_raw = struct.unpack('<Q', message_payload[22:30])[0]
        ask_price_raw = struct.unpack('<Q', message_payload[30:38])[0]
        ask_size = struct.unpack('<I', message_payload[38:42])[0]

        # Symbol is halted, paused or otherwise not available for trading on IEX.
        self.is_halted = quote_update_flags & 0x80
        # Symbol is active, available for trading.
        self.is_active = not self.is_halted

        # Pre-/Post-Market Session.
        self.is_pre_post_market = quote_update_flags & 0x40
        # Regular Market Session.
        self.is_regular_market = not self.is_pre_post_market

        self.timestamp = timestamp_raw
        self.symbol = symbol_raw.decode().strip()
        self.bid_size = bid_size
        self.bid_price = round(bid_price_raw * 1e-4, 2)
        self.ask_price = round(ask_price_raw * 1e-4, 2)
        self.ask_size = ask_size

    def to_string(self):
        # Determine the Quote Update flags.
        q_flags = []
        if self.is_halted:  # Symbol is halte, paused or otherwise not available for trading on IEX
            q_flags.append('HALTED')
        if self.is_active:  # Symbol is active, available for trading
            q_flags.append('ACTIVE')
        if self.is_regular_market:   # Regular Market Session
            q_flags.append('REGULAR')
        if self.is_pre_post_market:  # Pre-/Post-Market Session
            q_flags.append('PRE/POST')
        q_flags_string = '|'.join(q_flags)

        # Create message string.
        message_string = (f'Q,{self.symbol},{self.bid_size},{self.bid_price},{self.ask_size},'
                          f'{self.ask_price},{q_flags_string}')
        return message_string

    def to_dict(self):
        message_dict = {}

        # Time and date from timestamp.
        date, time = unix_to_date(self.timestamp)
        message_dict['date'] = date
        message_dict['time'] = time

        message_dict['halted'] = self.is_halted
        message_dict['active'] = self.is_active
        message_dict['pre_post_market'] = self.is_pre_post_market
        message_dict['regular_market'] = self.is_regular_market
        message_dict['symbol'] = self.symbol
        message_dict['bid_size'] = self.bid_size
        message_dict['bid_price'] = self.bid_price
        message_dict['ask_price'] = self.ask_price
        message_dict['ask_size'] = self.ask_size

        return message_dict


class PriceLevelUpdate:
    """Class representing a Price Level Update Message (message type '8' or '5')."""
    message_type = '8'  # '8' or '5'
    message_type_name = 'Price Level Update'
    csv_header = 'Tick Type,Symbol,Price,Size,Record Type,Flag'

    def __init__(self, message_payload: bytes):
        assert len(message_payload) == 30, "Price Level Update payload size should be 30 bytes."
        assert chr(message_payload[0]) in ('8', '5'), "Wrong message type bit."
        if chr(message_payload[0]) == '8':
            self.message_type = '8'
            self.message_type_name = 'Price Level Update - Buy'
        else:
            self.message_type = '5'
            self.message_type_name = 'Price Level Update - Sell'

        # Extract data from the payload.
        event_flags = message_payload[1]
        timestamp_raw = struct.unpack('<q', message_payload[2:10])[0]
        symbol_raw = struct.unpack('<8s', message_payload[10:18])[0]
        size = struct.unpack('<I', message_payload[18:22])[0]
        price_raw = struct.unpack('<Q', message_payload[22:30])[0]

        self.event_flag = event_flags
        self.timestamp = timestamp_raw
        self.symbol = symbol_raw.decode().strip()
        self.size = size
        if size == 0:
            self.record_type = 'Z'
        else:
            self.record_type = 'R'
        self.price = round(price_raw * 1e-4, 2)

    def to_string(self):
        # Check event flags.
        flag = 'Tick Type,Symbol,Price,Size,Record Type,Flag,ASK'
        match self.event_flag:
            case 1:  # Order Book is processing an event
                flag = 'IN_TRANSITION'
            case 0:  # Event processing complete
                flag = 'TRANS_COMPLETE'
            case _:
                raise Exception('Invalid event flag encountered in price level update message')

        # Create message string.
        message_string = (f'{self.message_type},{self.symbol},{self.price},{self.size},'
                          f'{self.record_type},{flag}')
        return message_string

    def to_dict(self):
        message_dict = {}

        # Time and date from timestamp.
        date, time = unix_to_date(self.timestamp)
        message_dict['date'] = date
        message_dict['time'] = time

        if self.event_flag == 0:
            message_dict['in_transition'] = True
        else:
            message_dict['in_transition'] = False

        message_dict['type'] = ''
        if self.message_type == '8':
            message_dict['type'] = 'SELL'
        elif self.message_type == '5':
            message_dict['type'] = 'BUY'

        message_dict['symbol'] = self.symbol
        message_dict['size'] = self.size
        message_dict['price'] = self.price

        return message_dict


class TradeReport:
    """Class representing a Trade Report Message (message type 'T')."""
    message_type = 'T'
    message_type_name = 'Trade Report'
    csv_header = 'Tick Type,Symbol,Size,Price,Trade ID,Sale Condition'

    def __init__(self, message_payload: bytes):
        assert len(message_payload) == 38, "Trade Report Message payload size should be 38 bytes."
        assert chr(message_payload[0]) == 'T', "Wrong message type bit."

        # Extract data from the payload.
        sale_condition_flags = message_payload[1]
        timestamp_raw = struct.unpack('<q', message_payload[2:10])[0]
        symbol_raw = struct.unpack('<8s', message_payload[10:18])[0]
        size = struct.unpack('<I', message_payload[18:22])[0]
        price_raw = struct.unpack('<Q', message_payload[22:30])[0]
        trade_id = struct.unpack('<q', message_payload[30:38])[0]

        self.is_intermarket_sweep = sale_condition_flags & 0x80
        self.is_extended_hours = sale_condition_flags & 0x40
        self.is_odd_lot = sale_condition_flags & 0x20
        self.is_trade_through_exempt = sale_condition_flags & 0x10
        self.is_single_price_cross = sale_condition_flags & 0x08

        self.timestamp = timestamp_raw
        self.symbol = symbol_raw.decode().strip()
        self.size = size
        self.price = round(price_raw * 1e-4, 2)
        self.trade_id = trade_id

    def to_string(self):
        # Parse the sale condition flags.
        sale_conditions = []
        if self.is_intermarket_sweep:  # Intermarket Sweep Order (ISO)
            sale_conditions.append('INTERMARKET_SWEEP')
        if self.is_extended_hours:  # Extended Hours Trade
            sale_conditions.append('EXTENDED_HOURS')
        else:                       # Regular Market Session Trade
            sale_conditions.append('REGULAR_HOURS')
        if self.is_odd_lot:  # Odd Lot Trade
            sale_conditions.append('ODD_LOT')
        if self.is_trade_through_exempt:  # Trade is not subject to Rule 611 (Trade Through)
            sale_conditions.append('TRADE_THROUGH_EXEMPT')
        if self.is_single_price_cross:  # Trade resulting from a single-price cross
            sale_conditions.append('SINGLE_PRICE_CROSS')
        sale_conditions_string = '|'.join(sale_conditions)

        # Create the message string.
        message_string = f'T,{self.symbol},{self.size},{self.price},{self.trade_id},{sale_conditions_string}'
        return message_string

    def to_dict(self):
        message_dict = {}

        # Time and date from timestamp.
        date, time = unix_to_date(self.timestamp)
        message_dict['date'] = date
        message_dict['time'] = time

        message_dict['intermarket_sweep'] = self.is_intermarket_sweep
        message_dict['extended_hours'] = self.is_extended_hours
        message_dict['odd_lot'] = self.is_odd_lot
        message_dict['trade_through_exempt'] = self.is_trade_through_exempt
        message_dict['single_price_cross'] = self.is_single_price_cross
        message_dict['symbol'] = self.symbol
        message_dict['size'] = self.size
        message_dict['price'] = self.price
        message_dict['trade_id'] = self.trade_id

        return message_dict


class OfficialPrice:
    """Class representing an Official Price Message (message type 'X')."""
    message_type = 'X'
    message_type_name = 'Official Price'
    csv_header = 'Tick Type,Symbol,Official Price,Price Type'

    def __init__(self, message_payload: bytes):
        assert len(message_payload) == 26, "Official Price Message payload size should be 26 bytes."
        assert chr(message_payload[0]) == 'X', "Wrong message type bit."

        # Extract data from the payload.
        price_type_int = message_payload[1]
        timestamp_raw = struct.unpack('<q', message_payload[2:10])[0]
        symbol_raw = struct.unpack('<8s', message_payload[10:18])[0]
        official_price_raw = struct.unpack('<Q', message_payload[18:26])[0]

        self.price_type = chr(price_type_int)
        self.timestamp = timestamp_raw
        self.symbol = symbol_raw.decode().strip()
        self.official_price = round(official_price_raw * 1e-4, 2)

    def to_string(self):
        # Determine Price Type.
        price_type_string = ''
        match self.price_type:
            case 'Q':  # Official opening price
                price_type_string = 'OPENING'
            case 'M':  # Official closing price
                price_type_string = 'CLOSING'
            case _:
                raise Exception('Invalid price type flag encountered in official price message')

        # Create the message string.
        message_string = f'X,{self.symbol},{self.official_price},{price_type_string}'
        return message_string

    def to_dict(self):
        message_dict = {}

        # Time and date from timestamp.
        date, time = unix_to_date(self.timestamp)
        message_dict['date'] = date
        message_dict['time'] = time

        message_dict['price_type'] = self.price_type
        message_dict['symbol'] = self.symbol
        message_dict['official_price'] = self.official_price

        return message_dict


class TradeBreak:
    """Class representing a Trade Break Message (message type 'B')."""
    message_type = 'B'
    message_type_name = 'Trade Break'
    csv_header = 'Tick Type,Symbol,Size,Price,Trade ID,Sale Condition'

    def __init__(self, message_payload: bytes):
        assert len(message_payload) == 38, "Trade Break Message payload size should be 38 bytes."
        assert chr(message_payload[0]) == 'B', "Wrong message type bit."

        # Extract data from the payload.
        sale_condition_flags = message_payload[1]
        timestamp_raw = struct.unpack('<q', message_payload[2:10])[0]
        symbol_raw = struct.unpack('<8s', message_payload[10:18])[0]
        size = struct.unpack('<I', message_payload[18:22])[0]
        price_raw = struct.unpack('<Q', message_payload[22:30])[0]
        trade_id = struct.unpack('<q', message_payload[30:38])[0]

        self.is_intermarket_sweep = sale_condition_flags & 0x80
        self.is_extended_hours = sale_condition_flags & 0x40
        self.is_odd_lot = sale_condition_flags & 0x20
        self.is_trade_through_exempt = sale_condition_flags & 0x10
        self.is_single_price_cross = sale_condition_flags & 0x08

        self.timestamp = timestamp_raw
        self.symbol = symbol_raw.decode().strip()
        self.size = size
        self.price = round(price_raw * 1e-4, 2)
        self.trade_id = trade_id

    def to_string(self):
        # Parse the sale condition flags.
        sale_conditions = []
        if self.is_intermarket_sweep:  # Intermarket Sweep Order (ISO)
            sale_conditions.append('INTERMARKET_SWEEP')
        if self.is_extended_hours:  # Extended Hours Trade
            sale_conditions.append('EXTENDED_HOURS')
        else:                       # Regular Market Session Trade
            sale_conditions.append('REGULAR_HOURS')
        if self.is_odd_lot:  # Odd Lot Trade
            sale_conditions.append('ODD_LOT')
        if self.is_trade_through_exempt:  # Trade is not subject to Rule 611 (Trade Through)
            sale_conditions.append('TRADE_THROUGH_EXEMPT')
        if self.is_single_price_cross:  # Trade resulting from a single-price cross
            sale_conditions.append('SINGLE_PRICE_CROSS')
        sale_conditions_string = '|'.join(sale_conditions)

        # Create the message string.
        message_string = f'T,{self.symbol},{self.size},{self.price},{self.trade_id},{sale_conditions_string}'
        return message_string

    def to_dict(self):
        message_dict = {}

        # Time and date from timestamp.
        date, time = unix_to_date(self.timestamp)
        message_dict['date'] = date
        message_dict['time'] = time

        message_dict['intermarket_sweep'] = self.is_intermarket_sweep
        message_dict['extended_hours'] = self.is_extended_hours
        message_dict['odd_lot'] = self.is_odd_lot
        message_dict['trade_through_exempt'] = self.is_trade_through_exempt
        message_dict['single_price_cross'] = self.is_single_price_cross
        message_dict['symbol'] = self.symbol
        message_dict['size'] = self.size
        message_dict['price'] = self.price
        message_dict['trade_id'] = self.trade_id

        message_dict['system_event_type'] = self.system_event_type
        return message_dict


#############################
### Message Classes: Auction Message Formats
#############################
class AuctionInformation:
    """Class representing an Auction Information Message (message type 'A')."""
    message_type = 'A'
    message_type_name = 'Auction Information'
    csv_header = ('Tick Type,Auction Type,Symbol,Paired Shares,Reference Price,'
                  'Indicative Clearing Price,Imbalance Shares,Imbalance Side,'
                  'Extension Number,Scheduled Auction Time,Auction Book Clearing Price,'
                  'Collar Reference Price,Lower Auction Collar,Upper Auction Collar')

    def __init__(self, message_payload: bytes):
        assert len(message_payload) == 80, "Auction Information Message payload size should be 80 bytes."
        assert chr(message_payload[0]) == 'A', "Wrong message type bit."

        # Extract data from the payload.
        auction_type_int = message_payload[1]
        timestamp_raw = struct.unpack('<q', message_payload[2:10])[0]
        symbol_raw = struct.unpack('<8s', message_payload[10:18])[0]
        paired_shares = struct.unpack('<I', message_payload[18:22])[0]
        reference_price_raw = struct.unpack('<Q', message_payload[22:30])[0]
        ind_cl_price_raw = struct.unpack('<Q', message_payload[30:38])[0]
        imbalance_shares = struct.unpack('<I', message_payload[38:42])[0]
        imbalance_side_int = message_payload[42]
        extension_number = message_payload[43]
        scheduled_auction_time = struct.unpack('<I', message_payload[44:48])[0]
        auction_book_clearing_price_raw = struct.unpack('<Q', message_payload[48:56])[0]
        collar_reference_price_raw = struct.unpack('<Q', message_payload[56:64])[0]
        lower_auction_collar_raw = struct.unpack('<Q', message_payload[64:72])[0]
        upper_auction_collar_raw = struct.unpack('<Q', message_payload[72:80])[0]

        self.auction_type = chr(auction_type_int)
        self.timestamp = timestamp_raw
        self.symbol = symbol_raw.decode().strip()
        self.paired_shares = paired_shares
        self.reference_price = round(reference_price_raw * 1e-4, 2)
        self.ind_cl_price = round(ind_cl_price_raw * 1e-4, 2)
        self.imbalance_shares = imbalance_shares
        self.imbalance_side = chr(imbalance_side_int)
        self.extension_number = extension_number
        self.scheduled_auction_time = scheduled_auction_time
        self.auction_book_clearing_price = round(auction_book_clearing_price_raw * 1e-4, 2)
        self.collar_reference_price = round(collar_reference_price_raw * 1e-4, 2)
        self.lower_auction_collar = round(lower_auction_collar_raw * 1e-4, 2)
        self.upper_auction_collar = round(upper_auction_collar_raw * 1e-4, 2)

    def to_string(self):
        # Determine auction type.
        auction_type_string = ''
        match self.auction_type:
            case 'O':  # Opening Auction
                auction_type_string = 'OPENING'
            case 'C':  # Closing Auction
                auction_type_string = 'CLOSING'
            case 'I':  # IPO Auction
                auction_type_string = 'IPO'
            case 'H':  # Halt Auction
                auction_type_string = 'HALT'
            case 'V':  # Volatility Auction
                auction_type_string = 'VOLATILITY'
            case _:
                raise Exception('Invalid auction type flag encountered in auction information message')

        # Determine imbalance side.
        imbalance_side_string = ''
        match self.imbalance_side:
            case 'B':  # buy-side imbalance
                imbalance_side_string = 'BUY'
            case 'S':  # sell-side imbalance
                imbalance_side_string = 'SELL'
            case 'N':  # no imbalance
                imbalance_side_string = 'NONE'
            case _:
                raise Exception('Invalid imbalance side flag encountered in official price message')

        # Create the message string.
        message_string = (f'A,{auction_type_string},{self.symbol},{self.paired_shares},{self.reference_price},'
                          f'{self.ind_cl_price},{self.imbalance_shares},{imbalance_side_string},'
                          f'{self.extension_number},{self.scheduled_auction_time},{self.auction_book_clearing_price},'
                          f'{self.collar_reference_price},{self.lower_auction_collar},{self.upper_auction_collar}')
        return message_string

    def to_dict(self):
        message_dict = {}

        # Time and date from timestamp.
        date, time = unix_to_date(self.timestamp)
        message_dict['date'] = date
        message_dict['time'] = time

        message_dict['auction_type'] = self.auction_type
        message_dict['symbol'] = self.symbol
        message_dict['paired_shares'] = self.paired_shares
        message_dict['reference_price'] = self.reference_price
        message_dict['indicative_clearing_price'] = self.ind_cl_price
        message_dict['imbalance_shares'] = self.imbalance_shares
        message_dict['imbalance_side'] = self.imbalance_side
        message_dict['extension_number'] = self.extension_number
        message_dict['scheduled_auction_time'] = self.scheduled_auction_time
        message_dict['auction_book_clearing_price'] = self.auction_book_clearing_price
        message_dict['collar_reference_price'] = self.collar_reference_price
        message_dict['lower_auction_collar'] = self.lower_auction_collar
        message_dict['upper_auction_collar'] = self.upper_auction_collar

        return message_dict

