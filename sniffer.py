#!/usr/bin/env python

"""
Python  modbus sniffer implementation with FTP upload
---------------------------------------------------------------------------

The following is an modbus RTU sniffer program,
made without the use of modbus specific library.
Ignores Function Codes 5, 6, 15, 16.
Includes verbose logging option (-v).
Fixed logging formatter error.
Adjusted timestamp format for console output.
Updated CSV header and format (v2).
Improved graceful shutdown handling.
Added buffer clearing on failed timeout processing.
RTU issues (CRC errors, ignored data) logged only in verbose mode.
Added inter-frame gap logging (DEBUG level).
Added state tracking for request/response matching and timeout detection.
"""
# --------------------------------------------------------------------------- #
# import the various needed libraries
# --------------------------------------------------------------------------- #
import signal
import sys
import getopt
import logging
import serial
import csv
from datetime import datetime, timedelta
# ftplib depends on socket
import socket
from ftplib import FTP
import time
import os

# --------------------------------------------------------------------------- #
# configure the logging system
# --------------------------------------------------------------------------- #
class myFormatter(logging.Formatter):
    # Use format with comma for milliseconds for console output
    date_fmt_console = '%Y-%m-%d %H:%M:%S,%f'
    # Use format with period for CSV/internal if needed (or stick to one)
    date_fmt_iso = '%Y-%m-%d %H:%M:%S.%f'


    def format(self, record):
         # Base format string - we will handle time separately
        base_log_fmt = " %(levelname)-8s: %(message)s" # Default simple format
        # Color codes
        grey = "\x1b[38;20m"
        yellow = "\x1b[33;20m"
        red = "\x1b[31;20m"
        bold_red = "\x1b[31;1m"
        blue = "\x1b[36m"
        cyan = "\x1b[36m" # Color for unmatched slave
        reset = "\x1b[0m"

        level_color = {
            logging.DEBUG: blue,
            logging.INFO: grey, # Keep INFO subtle
            logging.WARNING: yellow,
            logging.ERROR: red,
            logging.CRITICAL: bold_red
        }.get(record.levelno, grey) # Default to grey

        # Format based on level
        if record.levelno == logging.DEBUG:
            log_fmt = level_color + "%(levelname)-8s" + reset + ": %(message)s"
        elif record.levelno == logging.WARNING:
             # Special handling for unmatched slave warnings if desired
             if "Unmatched Slave" in record.getMessage() or "Request Timeout" in record.getMessage():
                  log_fmt = cyan + "%(levelname)-8s" + reset + ": %(message)s" # Use cyan for unmatched/timeouts
             else:
                  log_fmt = level_color + "%(levelname)-8s" + reset + ": %(message)s"
        elif record.levelno >= logging.ERROR: # Error, Critical
             log_fmt = level_color + "%(levelname)-8s" + reset + ": [%(module)s:%(lineno)d] %(message)s"
        else: # INFO
             # Keep INFO level concise on console
             log_fmt = "%(message)s" # No levelname needed for INFO

        # Create a formatter *without* date for the main message part
        msg_formatter = logging.Formatter(log_fmt)
        formatted_msg_part = msg_formatter.format(record)

        # Format the time separately using datetime and the console format
        now = datetime.fromtimestamp(record.created)
        # Format with ms (comma) and slice to 3 decimal places
        formatted_time = now.strftime(self.date_fmt_console)[:-3]

        # Combine time and message part
        return f"{formatted_time} {formatted_msg_part}"


log = logging.getLogger() # Get root logger
handler = logging.StreamHandler()
handler.setFormatter(myFormatter())
# Remove default handlers if any to avoid duplicates
if log.hasHandlers():
    log.handlers.clear()
log.addHandler(handler)
# Set default level to INFO, will be changed later if -v is specified
log.setLevel(logging.INFO)

# --------------------------------------------------------------------------- #
# declare the sniffer
# --------------------------------------------------------------------------- #
class SerialSnooper:
    # Timeout for considering a pending request as stale (e.g., 5 seconds)
    REQUEST_TIMEOUT_SECONDS = 5.0

    def __init__(self, port, baud=9600, timeout=0, ftp_host=None, ftp_user=None, ftp_password=None, ftp_dir=None):
        self.port = port
        self.baud = baud
        self.timeout = timeout if timeout is not None else 0 # Ensure timeout is not None
        self.shutdown_flag = False # Flag for graceful shutdown
        log_message = f"Opening serial interface: port={port}, baudrate={baud}, bytesize=8, parity=none, stopbits=1, timeout={self.timeout:.6f}"
        log.info(log_message) # Log setup to console

        try:
            self.connection = serial.Serial(port=port, baudrate=baud, bytesize=serial.EIGHTBITS, parity=serial.PARITY_NONE, stopbits=serial.STOPBITS_ONE, timeout=self.timeout)
            log.debug(f"Serial connection object: {self.connection}")
        except serial.SerialException as e:
            log.error(f"Failed to open serial port {port}: {e}") # Keep as ERROR
            sys.exit(f"Error: Could not open serial port {port}.")
        except ValueError as e:
             log.error(f"Invalid serial parameter for port {port}: {e}") # Keep as ERROR
             sys.exit(f"Error: Invalid serial parameter.")


        # Internal state variables
        self.data_buffer = bytearray(0)
        self.collecting_ignored_data = False
        self.ignored_data_log = bytearray(0)
        self.last_frame_end_time_float = None # For inter-frame gap calculation
        # State tracking for requests: {slave_id: {'timestamp': float_time, 'fc': int, 'start_ts_str': str}, ...}
        self.pending_requests = {}


        # FTP Server Details (SECURITY WARNING: Hardcoded credentials)
        self.ftp_host = ftp_host if ftp_host else "ftpcandisolar.qosenergy.com"
        self.ftp_user = ftp_user if ftp_user else "candisolar"
        self.ftp_password = ftp_password if ftp_password else "sho4Lo5to3aveGi4" # Example password - VERY INSECURE
        self.ftp_dir = ftp_dir if ftp_dir else "/modbus/"
        if not (ftp_host or ftp_user or ftp_password): # Log warning only if using defaults
             log.warning("Using hardcoded FTP credentials (SECURITY RISK). Consider using command line arguments.") # Keep as WARNING

        self.ftp_last_upload = time.time()
        self.ftp_interval = 5 * 60  # 5 minutes in seconds

        # CSV File Handling
        self.csv_filename = "modbus_log.csv"
        self.csv_file = None
        self.csv_writer = None
        try:
            # Open in write mode 'w' (overwrites each run). Use 'a' to append.
            self.csv_file = open(self.csv_filename, "w", newline="", encoding='utf-8')
            self.csv_writer = csv.writer(self.csv_file)
            # Write the NEW header as requested by the user (v2)
            self.csv_writer.writerow([
                "Timestamp", "Level", "Source", "ID", "Function", "Address",
                "Quantity", "Data", "CRC status ", "Exception Code" , "Details" # Note trailing spaces kept as requested
            ])
            # Do NOT log the initial setup message to CSV as it doesn't fit the format
        except IOError as e:
            log.error(f"Failed to open or write header to CSV file {self.csv_filename}: {e}") # Keep as ERROR
            # Allow script to continue without CSV logging
            self.csv_file = None
            self.csv_writer = None

    def _write_csv_log(self, level="", source="", unit_id="", function="", addr="", qty="", data=None, crc_status="", err_code="", message=""):
        """Helper function to write a standardized row to the CSV according to the new header (v2)."""
        if not self.csv_writer: return
        try:
            timestamp = self.get_timestamp() # Use current time for the log entry (ISO format with .)
            # Ensure data is a string (hex representation or empty)
            data_str = data if isinstance(data, str) else (data.hex(' ') if data else "")
            self.csv_writer.writerow([
                timestamp, level, source, unit_id, function,
                addr if addr is not None else "",
                qty if qty is not None else "",
                data_str, # Data payload (hex string)
                crc_status, # CRC status ("OK" or "Error")
                err_code if err_code is not None else "",
                message # Details column
            ])
            # self.csv_file.flush() # Optional: Flush after each write
        except Exception as e:
            log.error(f"Error writing row to CSV: {e}") # Keep as ERROR


    def get_timestamp(self):
            """Returns the current timestamp in ISO 8601 format with milliseconds (using period)."""
            # Keep period for internal use / CSV consistency if desired
            return datetime.now().strftime(myFormatter.date_fmt_iso)[:-3]

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
         # Log only unexpected exceptions during exit
         if exc_type and exc_type not in (SystemExit, KeyboardInterrupt):
             # Use default logging formatter for exceptions during exit to avoid recursion
             try:
                 # Keep logging actual script errors as ERROR
                 log.error(f"Exiting due to unhandled exception: {exc_val}", exc_info=(exc_type, exc_val, exc_tb))
             except Exception: # Fallback if even error logging fails
                 print(f"ERROR: Exiting due to unhandled exception: {exc_val}", file=sys.stderr)
                 import traceback
                 traceback.print_exception(exc_type, exc_val, exc_tb, file=sys.stderr)
         self.close() # Ensure close is always called

    def open(self):
        """Opens the serial connection if closed."""
        if self.connection and not self.connection.is_open:
             try:
                  self.connection.open()
                  log.info(f"Serial port {self.port} opened.")
             except serial.SerialException as e:
                  log.error(f"Failed to re-open serial port {self.port}: {e}") # Keep as ERROR
                  sys.exit(f"Error: Could not re-open serial port {self.port}.")

    def close(self):
        """Closes serial port and CSV file, attempts final FTP upload."""
        log.info("Close requested. Shutting down resources...")
        if self.connection and self.connection.is_open:
            try:
                self.connection.close()
                log.info(f"Serial port {self.port} closed.")
            except Exception as e:
                 log.error(f"Error closing serial port {self.port}: {e}") # Keep as ERROR

        if self.csv_file and not self.csv_file.closed:
            try:
                self.csv_file.flush()
                self.csv_file.close()
                log.info(f"CSV file {self.csv_filename} closed.")
                log.info("Performing final FTP upload...")
                self.ftp_upload() # Upload the closed file
            except Exception as e:
                 log.error(f"Error closing CSV or during final FTP upload: {e}") # Keep as ERROR
        elif os.path.exists(self.csv_filename): # Attempt upload if file exists but wasn't open
             log.info("CSV file wasn't open, attempting final FTP upload of existing file...")
             self.ftp_upload()
        else:
             log.info("No CSV file found for final upload.")

    def read_raw(self, n=1):
        """Reads raw data from serial with basic error handling."""
        try:
            read_data = self.connection.read(n)
            # Log raw bytes read at DEBUG level
            if read_data and log.isEnabledFor(logging.DEBUG):
               log.debug(f"Read {len(read_data)} bytes: {read_data.hex(' ')}")
            return read_data
        except serial.SerialException as e:
            # Keep logging serial read errors as ERROR as it indicates a port problem
            log.error(f"SerialException during read from {self.port}: {e}")
            return b'' # Return empty on error
        except Exception as e:
            log.error(f"Unexpected error during serial read: {e}") # Keep as ERROR
            return b''

    def ftp_upload(self):
        """Uploads the CSV file to the FTP server."""
        if not (self.ftp_host and self.ftp_user and self.ftp_password):
             log.warning("FTP details missing, skipping upload.") # Keep as WARNING
             return
        if not self.csv_filename or not os.path.exists(self.csv_filename):
             log.warning(f"CSV file '{self.csv_filename}' not found, skipping FTP upload.") # Keep as WARNING
             return
        try:
            if os.path.getsize(self.csv_filename) == 0:
                 log.info(f"CSV file '{self.csv_filename}' is empty, skipping FTP upload.")
                 return
        except OSError as e:
             log.error(f"Error checking CSV file size: {e}") # Keep as ERROR
             return # Don't attempt upload if we can't check size

        # Use a unique filename for upload based on timestamp
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        remote_filename = f"{os.path.splitext(self.csv_filename)[0]}_{timestamp_str}.csv"

        try:
            log.info(f"Attempting FTP connection to {self.ftp_host}...")
            with FTP(self.ftp_host, timeout=30) as ftp:
                ftp.login(self.ftp_user, self.ftp_password)
                log.info(f"FTP login successful for user {self.ftp_user}.")
                if self.ftp_dir:
                    try:
                        ftp.cwd(self.ftp_dir)
                        log.info(f"Changed FTP directory to {self.ftp_dir}")
                    except Exception as e:
                        # Keep FTP directory issues as WARNING
                        log.warning(f"Failed to change FTP directory to {self.ftp_dir}: {e}. Uploading to root.")

                log.info(f"Uploading '{self.csv_filename}' to FTP as '{remote_filename}'...")
                with open(self.csv_filename, "rb") as file:
                    ftp.storbinary(f"STOR {remote_filename}", file)
                log.info(f"File successfully uploaded to FTP as {remote_filename}.")
                # Optional: Delete or rename local file after successful upload

        # Keep FTP errors as ERROR as they indicate failure of a core function
       
        except ConnectionRefusedError: log.error(f"FTP connection refused by {self.ftp_host}.")
        except Exception as e: log.error(f"FTP upload failed: {e}")


    # --------------------------------------------------------------------------- #
    # Bufferise the data and call the decoder if the interframe timeout occur.
    # --------------------------------------------------------------------------- #
    def process_data(self, incoming_data):
        """Processes incoming serial data, buffers it, and triggers decoding."""
        if not incoming_data: # Timeout occurred on serial read
            log.debug(f"Serial read timeout occurred at {self.get_timestamp()}") # DEBUG log for timeout
            if len(self.data_buffer) > 0: # Process buffer only if timeout happened and buffer has data
                original_len = len(self.data_buffer) # Remember original length
                log.debug(f"Timeout: Processing buffer ({original_len} bytes): {self.data_buffer.hex(' ')}") # DEBUG
                self.data_buffer = self.decodeModbus(self.data_buffer)
                # Check if decodeModbus consumed *any* data after timeout
                if len(self.data_buffer) == original_len and original_len > 0:
                    # If buffer is unchanged after timeout processing, clear it
                    log.debug(f"Clearing {original_len} unparsable byte(s) from buffer after timeout: {self.data_buffer.hex(' ')}") # DEBUG
                    if not self.collecting_ignored_data: # Start collecting if not already
                        self.collecting_ignored_data = True
                        self.ignored_data_log = bytearray() # Ensure it's empty
                    self.ignored_data_log.extend(self.data_buffer) # Add all remaining bytes
                    self._flush_ignored_data_log() # Log and clear the ignored data log

                    self.data_buffer.clear() # Clear the main buffer
            # else: Buffer empty on timeout, nothing to do
            self._check_ftp_upload() # Check FTP periodically
            self._cleanup_stale_requests() # Check for timed out requests
            return

        # Append new data
        self.data_buffer.extend(incoming_data)
        log.debug(f"Appended data. Buffer now ({len(self.data_buffer)} bytes): {self.data_buffer.hex(' ')}") # DEBUG

        # Attempt to decode frames from the buffer
        self.data_buffer = self.decodeModbus(self.data_buffer)

        # Check FTP upload interval and stale requests
        self._check_ftp_upload()
        self._cleanup_stale_requests()


    def _check_ftp_upload(self):
         """Checks if the FTP upload interval has been reached."""
         current_time = time.time()
         if current_time - self.ftp_last_upload >= self.ftp_interval:
            log.info("FTP upload interval reached.")
            self.ftp_upload()
            self.ftp_last_upload = current_time

    def _cleanup_stale_requests(self):
        """Removes pending requests that have exceeded the timeout and logs them."""
        now = time.time()
        stale_ids = [
            slave_id for slave_id, req_info in self.pending_requests.items()
            if now - req_info['timestamp'] > self.REQUEST_TIMEOUT_SECONDS
        ]
        for slave_id in stale_ids:
            req_info = self.pending_requests.pop(slave_id)
            details_msg = f"Request Timeout (> {self.REQUEST_TIMEOUT_SECONDS}s)"
            # Log timeout as WARNING (visible by default)
            log.warning(f"Master       -> ID: {slave_id:<3}, Request FC 0x{req_info.get('fc', 0):02X} timed out (sent ~{req_info.get('start_ts_str', 'N/A')})")
            # Log timeout to CSV
            self._write_csv_log(
                level="WARN", source="System", unit_id=slave_id, function=f"0x{req_info.get('fc', 0):02X}",
                message=details_msg, crc_status="N/A" # CRC not applicable for timeout event
            )


    # --------------------------------------------------------------------------- #
    # Debuffer and decode the modbus frames (Request, Responce, Exception)
    # --------------------------------------------------------------------------- #
    def decodeModbus(self, current_buffer):
        """Decodes Modbus RTU frames from the buffered data."""
        bufferIndex = 0 # Start scanning from the beginning
        log.debug(f"decodeModbus called with buffer ({len(current_buffer)} bytes): {current_buffer.hex(' ')}") # DEBUG

        # Loop while there's potentially enough data for a minimal frame
        while len(current_buffer) >= (bufferIndex + 4): # Min: ID(1)+FC(1)+CRC(2)
            frameStartIndex = bufferIndex
            frame_scan_start_time_float = time.time() # Record time when scan starts for this potential frame
            frame_scan_start_ts_str = self.get_timestamp() # String version for logging
            log_source = "?" # Placeholder for Master/Slave
            log_details = "" # Placeholder for specific data

            # --- Peek at Frame Start ---
            unitIdentifier = current_buffer[frameStartIndex]
            functionCode = current_buffer[frameStartIndex + 1]
            log.debug(f"Scanning buffer at index {frameStartIndex}: Potential ID={unitIdentifier}, FC={functionCode:02x}") # DEBUG

            # --- Initialize frame components ---
            readAddress = readQuantity = writeAddress = writeQuantity = 0
            readByteCount = writeByteCount = exceptionCode = 0
            readData = writeData = bytearray()
            frame_processed = False # Flag to indicate if a frame was fully processed (valid or CRC error)
            crc_error_occurred = False # Flag for CRC specific error
            is_request_heuristic = False # Reset heuristic flag for each attempt
            calculated_crc_on_error = 0 # Store CRC details if error occurs
            received_crc_on_error = 0
            frame_data_on_error = bytearray()
            frame_end_time_float = None # Timestamp when frame processing ends (valid or CRC error)

            # --- Function Code Specific Parsing ---
            try:
                # FC01/02: Read Coils / Read Discrete Inputs
                if functionCode in (1, 2):
                    func_name = 'Read Coils' if functionCode == 1 else 'Read Discrete Inputs'
                    # Try Request: ID(1)+FC(1)+Addr(2)+Qty(2)+CRC(2) = 8 bytes
                    if len(current_buffer) >= (frameStartIndex + 8):
                        payload = current_buffer[frameStartIndex : frameStartIndex + 6]
                        received_crc = (current_buffer[frameStartIndex + 6] << 8) + current_buffer[frameStartIndex + 7]
                        calculated_crc = self.calcCRC16(payload)
                        frame_end_time_float = time.time() # Time after check
                        if received_crc == calculated_crc:
                            is_request_heuristic = True # Looks like a request
                            readAddress = (payload[2] << 8) + payload[3]
                            readQuantity = (payload[4] << 8) + payload[5]
                            log_details = f"{func_name} (0x{functionCode:02X}), Addr: {readAddress}, Qty: {readQuantity}"
                            self._log_frame(unitIdentifier, functionCode, log_details, is_request_heuristic, addr=readAddress, qty=readQuantity, crc_ok=True, start_ts_float=frame_scan_start_time_float, start_ts_str=frame_scan_start_ts_str, end_ts_float=frame_end_time_float)
                            bufferIndex = frameStartIndex + 8
                            frame_processed = True
                        else:
                             log.debug(f"CRC Mismatch for potential FC{functionCode} Request. Calc: {calculated_crc:04X}, Recv: {received_crc:04X}") # DEBUG
                             crc_error_occurred = True
                             calculated_crc_on_error = calculated_crc
                             received_crc_on_error = received_crc
                             frame_data_on_error = current_buffer[frameStartIndex : frameStartIndex + 8]

                    # Try Response: ID(1)+FC(1)+ByteCount(1)+Data(n)+CRC(2) = 5+n bytes
                    if not frame_processed and len(current_buffer) >= (frameStartIndex + 5): # Min response size
                        readByteCount = current_buffer[frameStartIndex + 2]
                        expected_len = 5 + readByteCount
                        if len(current_buffer) >= (frameStartIndex + expected_len):
                            payload = current_buffer[frameStartIndex : frameStartIndex + 3 + readByteCount]
                            received_crc = (current_buffer[frameStartIndex + expected_len - 2] << 8) + current_buffer[frameStartIndex + expected_len - 1]
                            calculated_crc = self.calcCRC16(payload)
                            frame_end_time_float = time.time() # Time after check
                            if received_crc == calculated_crc:
                                is_request_heuristic = False # Looks like a response
                                readData = payload[3:]
                                data_str = readData.hex(' ')
                                log_details = f"{func_name} (0x{functionCode:02X}), ByteCount: {readByteCount}, Data: [{data_str}]"
                                self._log_frame(unitIdentifier, functionCode, log_details, is_request_heuristic, data=readData, crc_ok=True, start_ts_float=frame_scan_start_time_float, start_ts_str=frame_scan_start_ts_str, end_ts_float=frame_end_time_float) # Pass bytearray
                                bufferIndex = frameStartIndex + expected_len
                                frame_processed = True
                            else:
                                log.debug(f"CRC Mismatch for potential FC{functionCode} Response. Calc: {calculated_crc:04X}, Recv: {received_crc:04X}") # DEBUG
                                crc_error_occurred = True
                                calculated_crc_on_error = calculated_crc
                                received_crc_on_error = received_crc
                                frame_data_on_error = current_buffer[frameStartIndex : frameStartIndex + expected_len]


                # FC03/04: Read Holding Registers / Read Input Registers
                elif functionCode in (3, 4):
                    func_name = 'Read Holding Registers' if functionCode == 3 else 'Read Input Registers'
                    # Try Request: ID(1)+FC(1)+Addr(2)+Qty(2)+CRC(2) = 8 bytes
                    if len(current_buffer) >= (frameStartIndex + 8):
                        payload = current_buffer[frameStartIndex : frameStartIndex + 6]
                        received_crc = (current_buffer[frameStartIndex + 6] << 8) + current_buffer[frameStartIndex + 7]
                        calculated_crc = self.calcCRC16(payload)
                        frame_end_time_float = time.time() # Time after check
                        if received_crc == calculated_crc:
                            is_request_heuristic = True
                            readAddress = (payload[2] << 8) + payload[3]
                            readQuantity = (payload[4] << 8) + payload[5]
                            log_details = f"{func_name} (0x{functionCode:02X}), Addr: {readAddress}, Qty: {readQuantity}"
                            self._log_frame(unitIdentifier, functionCode, log_details, is_request_heuristic, addr=readAddress, qty=readQuantity, crc_ok=True, start_ts_float=frame_scan_start_time_float, start_ts_str=frame_scan_start_ts_str, end_ts_float=frame_end_time_float)
                            bufferIndex = frameStartIndex + 8
                            frame_processed = True
                        else:
                             log.debug(f"CRC Mismatch for potential FC{functionCode} Request. Calc: {calculated_crc:04X}, Recv: {received_crc:04X}") # DEBUG
                             crc_error_occurred = True
                             calculated_crc_on_error = calculated_crc
                             received_crc_on_error = received_crc
                             frame_data_on_error = current_buffer[frameStartIndex : frameStartIndex + 8]

                    # Try Response: ID(1)+FC(1)+ByteCount(1)+Data(n)+CRC(2) = 5+n bytes
                    if not frame_processed and len(current_buffer) >= (frameStartIndex + 5):
                        readByteCount = current_buffer[frameStartIndex + 2]
                        expected_len = 5 + readByteCount
                        # Sanity check: byte count should be even for registers
                        if readByteCount % 2 == 0 and len(current_buffer) >= (frameStartIndex + expected_len):
                            payload = current_buffer[frameStartIndex : frameStartIndex + 3 + readByteCount]
                            received_crc = (current_buffer[frameStartIndex + expected_len - 2] << 8) + current_buffer[frameStartIndex + expected_len - 1]
                            calculated_crc = self.calcCRC16(payload)
                            frame_end_time_float = time.time() # Time after check
                            if received_crc == calculated_crc:
                                is_request_heuristic = False
                                readData = payload[3:]
                                data_str = readData.hex(' ')
                                log_details = f"{func_name} (0x{functionCode:02X}), ByteCount: {readByteCount}, Data: [{data_str}]"
                                self._log_frame(unitIdentifier, functionCode, log_details, is_request_heuristic, data=readData, crc_ok=True, start_ts_float=frame_scan_start_time_float, start_ts_str=frame_scan_start_ts_str, end_ts_float=frame_end_time_float) # Pass bytearray
                                bufferIndex = frameStartIndex + expected_len
                                frame_processed = True
                            else:
                                log.debug(f"CRC Mismatch for potential FC{functionCode} Response. Calc: {calculated_crc:04X}, Recv: {received_crc:04X}") # DEBUG
                                crc_error_occurred = True
                                calculated_crc_on_error = calculated_crc
                                received_crc_on_error = received_crc
                                frame_data_on_error = current_buffer[frameStartIndex : frameStartIndex + expected_len]

                # FC05, FC06, FC15, FC16 are intentionally ignored now

                # Exception Response (FC >= 0x80)
                elif functionCode >= 0x80:
                    # Error size: ID(1)+FC(1)+ExceptionCode(1)+CRC(2) = 5 bytes
                    if len(current_buffer) >= (frameStartIndex + 5):
                        payload = current_buffer[frameStartIndex : frameStartIndex + 3]
                        received_crc = (current_buffer[frameStartIndex + 3] << 8) + current_buffer[frameStartIndex + 4]
                        calculated_crc = self.calcCRC16(payload)
                        frame_end_time_float = time.time() # Time after check
                        if received_crc == calculated_crc:
                            is_request_heuristic = False # Exception is a response
                            exceptionCode = payload[2]
                            log_details = f"Exception Response (FC 0x{functionCode:02X}), Exception Code: {exceptionCode}"
                            self._log_frame(unitIdentifier, functionCode, log_details, is_request_heuristic, err_code=exceptionCode, crc_ok=True, start_ts_float=frame_scan_start_time_float, start_ts_str=frame_scan_start_ts_str, end_ts_float=frame_end_time_float)
                            bufferIndex = frameStartIndex + 5
                            frame_processed = True
                        else:
                            log.debug(f"CRC Mismatch for potential Exception Response FC{functionCode:02X}. Calc: {calculated_crc:04X}, Recv: {received_crc:04X}") # DEBUG
                            crc_error_occurred = True
                            calculated_crc_on_error = calculated_crc
                            received_crc_on_error = received_crc
                            frame_data_on_error = current_buffer[frameStartIndex : frameStartIndex + 5]

                # --- End of FC Specific Logic ---

            except IndexError:
                 log.debug(f"IndexError during parsing at index {frameStartIndex}.") # DEBUG
                 frame_processed = False
                 break # Break inner loop, wait for more data
            except Exception as e:
                 # Change unexpected parsing errors to DEBUG level
                 log.debug(f"Unexpected error during frame parsing: {e}", exc_info=True)
                 frame_processed = False
                 bufferIndex = frameStartIndex + 1 # Skip problematic byte
                 continue # Continue while loop


            # --- Post-processing Check ---
            if frame_processed:
                self._flush_ignored_data_log()
                continue # Continue while loop from the new bufferIndex
            else:
                # Frame not processed. Check if buffer is too short for *any* frame.
                if len(current_buffer) < (frameStartIndex + 4):
                     log.debug(f"Buffer too short ({len(current_buffer)-frameStartIndex} bytes) for any frame. Waiting.") # DEBUG
                     break # Break outer loop, need more data

                # If CRC error was detected for a potential frame, log it now
                if crc_error_occurred:
                    frame_data_hex = frame_data_on_error.hex(' ')
                    details_msg = f"CRC Error. Calc: {calculated_crc_on_error:04X}, Recv: {received_crc_on_error:04X}"
                    # Change CRC error console log to DEBUG level
                    log.debug(f"CRC Error detected for potential frame starting at index {frameStartIndex}. FC: {functionCode:02X}, Data: {frame_data_hex}...")
                    # Log CRC error to CSV with WARN level
                    self._write_csv_log(level="WARN", source="?", unit_id=unitIdentifier, function=f"0x{functionCode:02X}",
                                        data=frame_data_on_error, crc_status="Error", message=details_msg)


                # If we had enough data but still didn't process, assume the byte at frameStartIndex is garbage
                log.debug(f"No valid frame found starting at index {frameStartIndex}. Ignoring byte {current_buffer[frameStartIndex]:02X}.") # DEBUG
                self._log_ignored_byte(current_buffer[frameStartIndex])
                bufferIndex = frameStartIndex + 1 # Advance scan index by one
                # Continue the while loop to try parsing from the next byte

        # End of while loop
        log.debug(f"decodeModbus finished. Remaining buffer ({len(current_buffer) - bufferIndex} bytes): {current_buffer[bufferIndex:].hex(' ')}") # DEBUG
        return current_buffer[bufferIndex:] # Return the remaining unprocessed part


    def _log_frame(self, unit_id, fc, details, is_request, addr=None, qty=None, data=None, err_code=None, crc_ok=True, start_ts_float=None, start_ts_str=None, end_ts_float=None):
        """Logs a successfully decoded frame to console and CSV, handling state tracking."""
        source = "?"
        log_level = logging.INFO # Default log level for valid frames

        # --- Determine Source using State Tracking ---
        pending_req_info = self.pending_requests.get(unit_id)

        if is_request:
            source = "Master"
            # Store request info for state tracking
            # Overwrite previous pending request for this ID if any
            self.pending_requests[unit_id] = {
                'timestamp': end_ts_float, # Store float time when request *ended*
                'fc': fc,
                'start_ts_str': start_ts_str # Store string ts for logging if needed
            }
            log.debug(f"Stored pending request for Slave ID {unit_id} (FC {fc:02X})")
        elif pending_req_info:
            # Frame looks like a response/exception AND there was a pending request for this ID
            source = "Slave"
            # Check if function code matches (optional, but good practice)
            # Note: Exception FC = Request FC + 0x80
            expected_resp_fc = pending_req_info['fc']
            if fc == expected_resp_fc or fc == (expected_resp_fc | 0x80):
                 response_time_ms = (end_ts_float - pending_req_info['timestamp']) * 1000
                 log.debug(f"Matched response for Slave ID {unit_id} (FC {fc:02X}). Response time: {response_time_ms:.1f} ms")
                 # Remove the pending request now that we have the response
                 del self.pending_requests[unit_id]
            else:
                 log.warning(f"Slave ID {unit_id} responded with FC {fc:02X}, but pending request was for FC {expected_resp_fc:02X}. Treating as matched response anyway.")
                 # Still remove pending request as *something* came back
                 del self.pending_requests[unit_id]
        else:
            # Looks like a response/exception, but no pending request found
            source = "Slave (?)" # Unmatched Slave
            log_level = logging.WARNING # Log unmatched slaves as WARNING
            log.warning(f"Unmatched Slave response/exception from ID {unit_id} (FC {fc:02X}). No pending request found.")

        # --- Log Frame details ---
        # Log inter-frame gap if applicable (only for valid, matched frames)
        if crc_ok and start_ts_float is not None and self.last_frame_end_time_float is not None and source == "Master": # Log gap before Master requests
             inter_frame_gap_ms = (start_ts_float - self.last_frame_end_time_float) * 1000
             log.debug(f"Inter-frame gap before Master req: {inter_frame_gap_ms:.1f} ms")
        elif crc_ok and start_ts_float is not None and self.last_frame_end_time_float is not None and source == "Slave": # Log gap before Slave responses
             inter_frame_gap_ms = (start_ts_float - self.last_frame_end_time_float) * 1000
             log.debug(f"Inter-frame gap before Slave resp: {inter_frame_gap_ms:.1f} ms")


        # Ensure data is hex string for logging if it's bytes/bytearray
        data_str = data.hex(' ') if isinstance(data, (bytes, bytearray)) else data
        # Use f-string formatting similar to the user's example for console log
        log.log(log_level, f"{source:<12} -> ID: {unit_id:<3}, {details}")

        # Log to CSV
        self._write_csv_log(
            level=logging.getLevelName(log_level),
            source=source, unit_id=unit_id,
            function=f"0x{fc:02X}", # Log FC as hex
            addr=addr, qty=qty, data=data_str, err_code=err_code,
            crc_status="OK" if crc_ok else "Error", # Add CRC status
            message=details # Use details string for Details column in CSV
        )
        # Update last frame end time only if CRC was OK
        if crc_ok and end_ts_float is not None:
             self.last_frame_end_time_float = end_ts_float


    def _log_ignored_byte(self, byte_val):
        """Collects bytes that are being ignored due to parsing/CRC errors."""
        if not self.collecting_ignored_data:
            self.collecting_ignored_data = True
            self.ignored_data_log = bytearray(f"[{byte_val:02X}".encode('ascii'))
        else:
            self.ignored_data_log.extend(f" {byte_val:02X}".encode('ascii'))

    def _flush_ignored_data_log(self):
        """If ignored data was collected, log it."""
        if self.collecting_ignored_data:
            self.ignored_data_log.extend(b']')
            ignored_str = self.ignored_data_log.decode('ascii', errors='replace')
            # Change ignored data console log to DEBUG level
            log.debug(f"Ignored data segment flushed: {ignored_str}")
            # Log ignored data to CSV with WARN level
            self._write_csv_log(level="WARN", message=f"Ignored data: {ignored_str}", crc_status="N/A")
            self.collecting_ignored_data = False
            self.ignored_data_log.clear()


    # --------------------------------------------------------------------------- #
    # Calculate the modbus CRC
    # --------------------------------------------------------------------------- #
    def calcCRC16(self, data):
        """Calculates the Modbus RTU CRC16 for the given data (bytes or bytearray)."""
        # Use the standard table-based CRC calculation for efficiency
        crc = 0xFFFF
        for char in data:
            crc = (crc >> 8) ^ self._crc16_table[(crc ^ char) & 0xFF]
        return crc

    _crc16_table = (
        0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
        0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
        0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
        0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
        0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
        0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
        0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
        0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
        0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
        0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
        0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
        0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
        0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
        0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
        0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
        0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
        0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
        0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
        0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
        0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
        0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
        0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
        0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
        0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
        0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
        0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
        0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
        0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
        0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
        0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
        0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
        0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040 )


# --------------------------------------------------------------------------- #
# Print the usage help
# --------------------------------------------------------------------------- #
def printHelp(baud, timeout_override):
    """Prints the command-line usage instructions."""
    calculated_timeout = calcTimeout(baud) if baud > 0 else 0
    timeout_str = f"{timeout_override:.6f}s (provided)" if timeout_override is not None else f"{calculated_timeout:.6f}s (calculated)"
    print("\nUsage:")
    print("  python modbus_sniffer.py -p <serial_port> [options]")
    print("\nArguments:")
    print("  -p, --port PORT       Specify the serial port (e.g., /dev/ttyUSB0, COM3) (Required)")
    print("\nOptions:")
    print(f"  -b, --baudrate BAUD   Set the communication baud rate (default: {baud})")
    print(f"  -t, --timeout SECS    Override the calculated inter-frame timeout (default: {timeout_str})")
    print("  -v, --verbose         Enable verbose debug logging to console") # Added verbose help
    print("      --ftp_host HOST   FTP server hostname or IP address")
    print("      --ftp_user USER   FTP username")
    print("      --ftp_pass PASS   FTP password (use quotes if needed)")
    print("      --ftp_dir DIR     Remote directory on FTP server")
    print("  -h, --help            Print this help message and exit")
    print("")

# --------------------------------------------------------------------------- #
# Calculate the timeout with the baudrate
# --------------------------------------------------------------------------- #
def calcTimeout(baud):
    """Calculates the Modbus RTU inter-frame delay (timeout)."""
    if baud <= 0:
        log.warning("Invalid baud rate <= 0 for timeout calc, using 0.01s")
        return 0.01
    # Modbus standard: 3.5 character times. Assume 11 bits/char (8N1).
    bits_per_char = 11.0
    char_time = bits_per_char / baud
    timeout = 3.5 * char_time
    # Apply minimums
    min_timeout = 0.005 # 5ms general minimum
    if baud > 19200:
        min_timeout = max(min_timeout, 0.00175) # 1.75ms for > 19200 baud
    calculated_timeout = max(timeout, min_timeout)
    log.debug(f"Calculated timeout for {baud} baud: {calculated_timeout:.6f}s") # DEBUG
    return calculated_timeout

# --------------------------------------------------------------------------- #
# configure a clean exit
# --------------------------------------------------------------------------- #
snooper_instance = None # Global reference for signal handler

def signal_handler(sig, frame):
    """Handles termination signals for graceful shutdown by setting a flag."""
    global snooper_instance
    signal_name = signal.Signals(sig).name
    print(f'\nSignal {signal_name} received, requesting shutdown...')
    log.info(f"Shutdown signal ({signal_name}) received.")
    if snooper_instance:
        snooper_instance.shutdown_flag = True # Set flag to stop main loop
    else:
        # If instance not created yet (e.g., error during init), exit directly
        sys.exit(0)
    # Do NOT call sys.exit here; let the main loop exit naturally

# --------------------------------------------------------------------------- #
# main routine
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    print("Modbus RTU Sniffer Initializing...")
    # Setup signal handlers early
    signal.signal(signal.SIGINT, signal_handler)  # Ctrl+C
    signal.signal(signal.SIGTERM, signal_handler) # kill command

    # --- Default values ---
    port = None
    baud = 9600
    timeout_override = None
    verbose = False # Default verbose to False
    ftp_host = None
    ftp_user = None
    ftp_password = None
    ftp_dir = None

    # --- Argument Parsing ---
    short_opts = "hp:b:t:v" # Added 'v' for verbose
    long_opts = ["help", "port=", "baudrate=", "timeout=", "verbose", # Added 'verbose'
                 "ftp_host=", "ftp_user=", "ftp_pass=", "ftp_dir="]

    try:
        opts, args = getopt.getopt(sys.argv[1:], short_opts, long_opts)
    except getopt.GetoptError as e:
        print(f"Argument error: {e}")
        printHelp(baud, timeout_override)
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            printHelp(baud, timeout_override)
            sys.exit()
        elif opt in ("-p", "--port"):
            port = arg
        elif opt in ("-b", "--baudrate"):
            try:
                baud = int(arg)
                if baud <= 0: raise ValueError("Baud rate must be positive")
            except ValueError as e: print(f"Invalid baud rate: {arg}. {e}"); sys.exit(2)
        elif opt in ("-t", "--timeout"):
             try:
                timeout_override = float(arg)
                if timeout_override < 0: raise ValueError("Timeout cannot be negative")
             except ValueError as e: print(f"Invalid timeout value: {arg}. {e}"); sys.exit(2)
        elif opt in ("-v", "--verbose"): # Check for verbose flag
             verbose = True
        elif opt == "--ftp_host": ftp_host = arg
        elif opt == "--ftp_user": ftp_user = arg
        elif opt == "--ftp_pass": ftp_password = arg
        elif opt == "--ftp_dir": ftp_dir = arg

    # --- Post-parsing Setup ---
    if port is None:
        print("Error: Serial Port (-p or --port) is required."); printHelp(baud, timeout_override); sys.exit(2)

    # Set logging level based on verbose flag
    if verbose:
        log.setLevel(logging.DEBUG)
        log.info("Verbose logging enabled (DEBUG level).")
    else:
        log.setLevel(logging.INFO)
        # Optionally log that standard logging is enabled
        # log.info("Standard logging enabled (INFO level). Use -v for verbose.")


    # Calculate final timeout value
    timeout = timeout_override if timeout_override is not None else calcTimeout(baud)

    # --- Initialize and Run ---
    main_instance = None # Keep track for final message
    try:
        # Use 'with' statement for automatic cleanup via __enter__/__exit__
        with SerialSnooper(port, baud, timeout, ftp_host, ftp_user, ftp_password, ftp_dir) as sniffer:
            main_instance = sniffer # Assign to local var
            snooper_instance = sniffer # Assign global ref for signal handler
            log.info("Starting Modbus sniffing loop... Press Ctrl+C to exit.")
            # Loop until shutdown flag is set by signal handler
            while not sniffer.shutdown_flag:
                # Read available data or block until timeout
                # Check flag before potentially blocking read
                if sniffer.shutdown_flag: break
                read_data = sniffer.read_raw(sniffer.connection.in_waiting or 1)
                # Check flag again after read returns (might have been set during block)
                if sniffer.shutdown_flag: break
                sniffer.process_data(read_data) # Process data/timeout

            log.info("Shutdown flag detected, exiting main loop.")

    except KeyboardInterrupt:
        # This should ideally not be reached if signal handler works
        log.info("Keyboard interrupt detected directly by main loop.")
        print("\nExiting via KeyboardInterrupt.")
    except SystemExit as e:
         # Catch SystemExit if it occurs unexpectedly (e.g., from other parts of code)
         log.info(f"SystemExit called ({e.code}). Sniffer shutting down.")
    except Exception as e:
        # Catch unexpected errors during initialization or runtime loop
        # Use default logger config for critical errors to avoid formatter issues during exceptions
        logging.basicConfig() # Reset to basic config for safety
        logging.critical(f"An critical unexpected error occurred in the main execution block: {e}", exc_info=True) # Log traceback
        print(f"A critical error occurred: {e}")
    finally:
        # Cleanup is handled by the __exit__ method of the 'with' statement
        log.info("Sniffer main execution finished.")
        print("Sniffer finished.")
