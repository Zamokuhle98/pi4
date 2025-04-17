#!/usr/bin/env python

"""
Python modbus sniffer implementation with FTP upload - Error Focused Logging
---------------------------------------------------------------------------

Listens to Modbus RTU traffic, logs detected Modbus exceptions,
CRC errors, and framing issues to console and CSV, and uploads the CSV via FTP.
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
from datetime import datetime
from ftplib import FTP
import time
import os

# --------------------------------------------------------------------------- #
# configure the logging system
# --------------------------------------------------------------------------- #
class myFormatter(logging.Formatter):
    def format(self, record):
        if record.levelno == logging.INFO:
            # Keep INFO for startup, FTP, etc., but make successful Modbus quiet later
            self._style._fmt = "%(asctime)-15s %(message)s"
        elif record.levelno == logging.DEBUG:
            self._style._fmt = f"%(asctime)-15s \033[36m%(levelname)-8s\033[0m: %(message)s"
        # Highlight Warnings and Errors
        elif record.levelno == logging.WARNING:
             self._style._fmt = f"%(asctime)-15s \033[33m%(levelname)-8s\033[0m: %(message)s"
        elif record.levelno >= logging.ERROR:
             color = 31 # Red for ERROR and FATAL
             self._style._fmt = f"%(asctime)-15s \033[{color}m%(levelname)-8s\033[0m: %(message)s" # Simplified error format
        else: # Other levels (e.g., CRITICAL)
             self._style._fmt = super().format(record) # Default formatting
        # Apply formatting changes
        # This needs to be done before super().format() for custom levels
        original_fmt = self._style._fmt
        # Format the message using the selected format string
        formatted_message = super().format(record)
        # Reset format string for next record if it was changed dynamically
        self._style._fmt = original_fmt
        return formatted_message


log = logging.getLogger()
handler = logging.StreamHandler()
handler.setFormatter(myFormatter())
# Set base level - INFO shows startup, WARNING/ERROR for Modbus issues
log.setLevel(logging.INFO)
# For even quieter console, set to WARNING:
# log.setLevel(logging.WARNING)
log.addHandler(handler)

# --------------------------------------------------------------------------- #
# declare the sniffer
# --------------------------------------------------------------------------- #
class SerialSnooper:

    def __init__(self, port, baud=9600, timeout=0, ftp_host=None, ftp_user=None, ftp_password=None, ftp_dir=None):
        self.port = port
        self.baud = baud
        self.timeout = timeout
        log_message = f"Opening serial interface: port={port}, baudrate={baud}, bytesize=8, parity=none, stopbits=1, timeout={timeout}"
        log.info(log_message)
        self.connection = serial.Serial(port=port, baudrate=baud, bytesize=serial.EIGHTBITS, parity=serial.PARITY_NONE, stopbits=serial.STOPBITS_ONE, timeout=timeout)
        log.debug(self.connection)

        # Global variables
        self.data = bytearray(0)
        # Removed self.trashdata and self.trashdataf - will log trash directly

        # FTP Server details from arguments
        self.ftp_host = ftp_host
        self.ftp_user = ftp_user
        self.ftp_password = ftp_password
        self.ftp_dir = ftp_dir if ftp_dir else "/"
        self.ftp_last_upload = time.time()
        self.ftp_interval = 5 * 60

        if self.ftp_host:
             log.info(f"FTP Upload Enabled: Host={self.ftp_host}, User={self.ftp_user}, Dir={self.ftp_dir}")
        else:
             log.info("FTP Upload Disabled (no host specified).")

        # CSV File - Naming convention implies errors/issues
        self.csv_filename = "modbus_issues_log.csv" # Changed filename
        self.csv_file = open(self.csv_filename, "w", newline="")
        self.csv_writer = csv.writer(self.csv_file)
        # MODIFICATION: Updated CSV Header
        self.csv_writer.writerow(["Timestamp", "Error Type", "Details", "Raw Data"])
        log.info(f"Logging Modbus issues to {self.csv_filename}")


    def get_timestamp(self):
        """Returns the current timestamp in a suitable format for logging."""
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def open(self):
        self.connection.open()

    def close(self):
        if self.connection and self.connection.is_open:
            self.connection.close()
            log.info("Serial connection closed.")
        if self.csv_file and not self.csv_file.closed:
            self.csv_file.close()
            log.info(f"CSV issue log '{self.csv_filename}' closed.")

    def read_raw(self, n=1):
        try:
            return self.connection.read(n)
        except serial.SerialException as e:
            log.error(f"Serial read error: {e}")
            # Log serial error to CSV as well
            if self.csv_writer and self.csv_file and not self.csv_file.closed:
                 try:
                     self.csv_writer.writerow([self.get_timestamp(), "Serial Error", f"Read failed: {e}", ""])
                     self.csv_file.flush()
                 except Exception as csv_e:
                     log.error(f"Failed to write serial error to CSV: {csv_e}")
            sys.exit(f"Serial communication failed: {e}")

    def ftp_upload(self):
        """Uploads the CSV issue log file to the FTP server."""
        if self.ftp_host and self.ftp_user and self.ftp_password and self.ftp_dir:
            log.info(f"Attempting FTP upload of {self.csv_filename} to {self.ftp_host}...")
            self.csv_file.flush()
            os.fsync(self.csv_file.fileno())

            try:
                with FTP(self.ftp_host, timeout=30) as ftp:
                    ftp.login(self.ftp_user, self.ftp_password)
                    try:
                        ftp.cwd(self.ftp_dir)
                    except Exception as e:
                        log.warning(f"FTP CWD failed ({e}), attempting to create directory: {self.ftp_dir}")
                        try:
                           ftp.mkd(self.ftp_dir)
                           ftp.cwd(self.ftp_dir)
                        except Exception as mkd_e:
                           log.error(f"FTP could not CWD or MKD directory {self.ftp_dir}: {mkd_e}")
                           # Also log FTP error to CSV
                           if self.csv_writer and self.csv_file and not self.csv_file.closed:
                               self.csv_writer.writerow([self.get_timestamp(), "FTP Error", f"Cannot access remote directory {self.ftp_dir}: {mkd_e}", ""])
                               self.csv_file.flush()
                           return

                    remote_filename = f"modbus_issues_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
                    with open(self.csv_filename, "rb") as file:
                        ftp.storbinary(f"STOR {remote_filename}", file)
                    log.info(f"CSV issue log uploaded successfully to FTP as {remote_filename}.")
                    # Optional: Clear local CSV after upload
                    # ... (implementation as before if needed) ...
            except Exception as e:
                log.error(f"FTP upload failed: {e}")
                 # Log FTP error to CSV
                if self.csv_writer and self.csv_file and not self.csv_file.closed:
                    self.csv_writer.writerow([self.get_timestamp(), "FTP Error", f"Upload failed: {e}", ""])
                    self.csv_file.flush()
        else:
             log.debug("FTP upload skipped: Missing FTP credentials or host.")

    # --------------------------------------------------------------------------- #
    # Bufferise the data and call the decoder if the interframe timeout occur.
    # --------------------------------------------------------------------------- #
    def process_data(self, data):
        if len(data) > 0:
            for dat in data:
                self.data.append(dat)
        else: # Timeout occurred
            if len(self.data) > 2:
                log.debug(f"Timeout detected, processing buffer: [{' '.join(f'{x:02x}' for x in self.data)}]")
                remaining_data = self.decodeModbus(bytearray(self.data)) # Process a copy
                if len(remaining_data) == len(self.data):
                    # No frame was decoded, log buffer as potentially incomplete/noise after timeout
                    log.warning(f"Timeout occurred, but buffer contains unrecognized data: [{' '.join(f'{x:02x}' for x in self.data)}]")
                    self.csv_writer.writerow([self.get_timestamp(), "Framing/Timeout Issue", "Timeout occurred, buffer content unrecognized", f"{' '.join(f'{x:02x}' for x in self.data)}"])
                    self.csv_file.flush()
                elif len(remaining_data) > 0:
                     log.warning(f"Partial data remaining after decode: [{' '.join(f'{x:02x}' for x in remaining_data)}]")
                     # Optionally log this remaining part too
                     self.csv_writer.writerow([self.get_timestamp(), "Framing Issue", "Partial data remaining after decoding frame(s)", f"{' '.join(f'{x:02x}' for x in remaining_data)}"])
                     self.csv_file.flush()
                self.data.clear() # Clear buffer after processing attempt
            elif len(self.data) > 0:
                 # Timeout occurred, but buffer too small for a valid frame, clear it and log maybe?
                 log.debug(f"Timeout occurred with small buffer: [{' '.join(f'{x:02x}' for x in self.data)}]")
                 # Log small buffer on timeout? Might be too noisy.
                 # self.csv_writer.writerow([self.get_timestamp(), "Framing/Timeout Issue", "Timeout occurred, buffer too small", f"{' '.join(f'{x:02x}' for x in self.data)}"])
                 # self.csv_file.flush()
                 self.data.clear()

        # Check if it's time to upload via FTP
        if self.ftp_host and (time.time() - self.ftp_last_upload >= self.ftp_interval):
            self.ftp_upload()
            self.ftp_last_upload = time.time()

    # --------------------------------------------------------------------------- #
    # Debuffer and decode the modbus frames, logging only errors/issues
    # --------------------------------------------------------------------------- #
    def decodeModbus(self, modbusdata):
        bufferIndex = 0

        while True:
            start_buffer_len = len(modbusdata) # Track if we consume data

            if len(modbusdata) < (bufferIndex + 4): # Need min 4 bytes (Addr+FC+CRC)
                break # Not enough data left for any frame

            frameStartIndex = bufferIndex
            unitIdentifier = modbusdata[frameStartIndex]
            functionCode = modbusdata[frameStartIndex + 1]
            log.debug(f"Attempting decode at index {frameStartIndex}: Unit={unitIdentifier}, FC={functionCode}")

            frame_processed = False
            expectedLenght = -1

            # --- Function Code Handling ---

            # FC 1, 2, 3, 4 (Reads)
            if functionCode in (1, 2, 3, 4):
                # Check Request (8 bytes)
                expectedLenght = 8
                if len(modbusdata) >= (frameStartIndex + expectedLenght):
                    crc16_index = frameStartIndex + expectedLenght - 2
                    crc16_from_frame = (modbusdata[crc16_index + 1] << 8) | modbusdata[crc16_index] # High byte first << WRONG, CRC is Low then High
                    crc16_from_frame = (modbusdata[crc16_index + 1] << 8) | modbusdata[crc16_index] # CRC: Low byte then High byte

                    # Read CRC from buffer: Low byte at crc16_index, High byte at crc16_index + 1
                    crc_low = modbusdata[crc16_index]
                    crc_high = modbusdata[crc16_index + 1]
                    crc16_from_frame = (crc_high << 8) | crc_low # Combine Low and High bytes correctly

                    calculated_crc = self.calcCRC16(modbusdata[frameStartIndex : crc16_index]) # Calculate CRC on data before CRC bytes

                    if crc16_from_frame == calculated_crc:
                        # VALID REQUEST - DO NOT LOG TO CSV/CONSOLE INFO
                        log.debug(f"Valid Master request FC={functionCode} found.")
                        bufferIndex += expectedLenght
                        frame_processed = True
                    else:
                        # REQUEST CRC FAILED - Log Error
                        log.warning(f"Potential Master request FC={functionCode} found with CRC ERROR. Expected={calculated_crc:04x}, Got={crc16_from_frame:04x}")
                        frame_data_hex = ' '.join(f'{x:02x}' for x in modbusdata[frameStartIndex : frameStartIndex + expectedLenght])
                        self.csv_writer.writerow([self.get_timestamp(), "CRC Error", f"Master Request FC={functionCode}, Expected={calculated_crc:04x}, Got={crc16_from_frame:04x}", frame_data_hex])
                        self.csv_file.flush()
                        bufferIndex += expectedLenght # Consume the bad frame
                        frame_processed = True # Treat as processed (even though bad)
                # else: Not enough data for request

                # Check Response (Variable length: 5 + n bytes) only if not processed as request
                if not frame_processed and len(modbusdata) >= (frameStartIndex + 5): # Min response length
                    byteCount_index = frameStartIndex + 2
                    readByteCount = modbusdata[byteCount_index]
                    expectedLenght = 5 + readByteCount

                    if len(modbusdata) >= (frameStartIndex + expectedLenght):
                        crc16_index = frameStartIndex + expectedLenght - 2
                        crc_low = modbusdata[crc16_index]
                        crc_high = modbusdata[crc16_index + 1]
                        crc16_from_frame = (crc_high << 8) | crc_low
                        calculated_crc = self.calcCRC16(modbusdata[frameStartIndex : crc16_index])

                        if crc16_from_frame == calculated_crc:
                            # VALID RESPONSE - DO NOT LOG TO CSV/CONSOLE INFO
                            log.debug(f"Valid Slave response FC={functionCode} found.")
                            bufferIndex += expectedLenght
                            frame_processed = True
                        else:
                            # RESPONSE CRC FAILED - Log Error
                            log.warning(f"Potential Slave response FC={functionCode} found with CRC ERROR. Expected={calculated_crc:04x}, Got={crc16_from_frame:04x}")
                            frame_data_hex = ' '.join(f'{x:02x}' for x in modbusdata[frameStartIndex : frameStartIndex + expectedLenght])
                            self.csv_writer.writerow([self.get_timestamp(), "CRC Error", f"Slave Response FC={functionCode}, Expected={calculated_crc:04x}, Got={crc16_from_frame:04x}", frame_data_hex])
                            self.csv_file.flush()
                            bufferIndex += expectedLenght # Consume the bad frame
                            frame_processed = True
                    # else: Not enough data for response of this length

            # FC80+ (Exception)
            elif (functionCode >= 0x80):
                expectedLenght = 5 # Exception frame length
                if len(modbusdata) >= (frameStartIndex + expectedLenght):
                    crc16_index = frameStartIndex + expectedLenght - 2
                    crc_low = modbusdata[crc16_index]
                    crc_high = modbusdata[crc16_index + 1]
                    crc16_from_frame = (crc_high << 8) | crc_low
                    calculated_crc = self.calcCRC16(modbusdata[frameStartIndex : crc16_index])

                    if crc16_from_frame == calculated_crc:
                        # VALID EXCEPTION - LOG THIS
                        exceptionCode = modbusdata[frameStartIndex + 2]
                        log.warning(f"Slave  -> ID: {unitIdentifier}, Exception: 0x{functionCode:02x}, Code: {exceptionCode}") # Use warning level
                        frame_data_hex = ' '.join(f'{x:02x}' for x in modbusdata[frameStartIndex : frameStartIndex + expectedLenght])
                        self.csv_writer.writerow([self.get_timestamp(), "Modbus Exception", f"Slave ID={unitIdentifier}, FC=0x{functionCode:02x}, Exception Code={exceptionCode}", frame_data_hex])
                        self.csv_file.flush()
                        bufferIndex += expectedLenght
                        frame_processed = True
                    else:
                        # EXCEPTION FRAME CRC FAILED - Log Error
                        log.warning(f"Potential Exception frame FC={functionCode} found with CRC ERROR. Expected={calculated_crc:04x}, Got={crc16_from_frame:04x}")
                        frame_data_hex = ' '.join(f'{x:02x}' for x in modbusdata[frameStartIndex : frameStartIndex + expectedLenght])
                        self.csv_writer.writerow([self.get_timestamp(), "CRC Error", f"Exception Frame FC=0x{functionCode}, Expected={calculated_crc:04x}, Got={crc16_from_frame:04x}", frame_data_hex])
                        self.csv_file.flush()
                        bufferIndex += expectedLenght # Consume the bad frame
                        frame_processed = True
                # else: Not enough data for exception frame

            # --- Unknown Function Code or Framing Error ---
            if not frame_processed:
                # Data starting at frameStartIndex didn't match any known pattern or failed checks
                # Treat the first byte as unrecognized/trash and advance
                trash_byte = modbusdata[frameStartIndex]
                log.warning(f"Unrecognized data / Framing Error starting with byte 0x{trash_byte:02x} at index {frameStartIndex}.")
                # Log the single byte or maybe more context? Log just the byte for now.
                self.csv_writer.writerow([self.get_timestamp(), "Framing Error", f"Unrecognized byte 0x{trash_byte:02x}", f"{trash_byte:02x}"])
                self.csv_file.flush()
                bufferIndex += 1 # Advance past the single bad byte
                # Don't set frame_processed = True, let the loop continue from the next byte

            # Check if buffer was consumed or loop should exit
            if bufferIndex >= len(modbusdata):
                 log.debug("End of buffer reached in decode loop.")
                 break # Exit while loop

            if bufferIndex == frameStartIndex and not frame_processed:
                 # We didn't process a frame and didn't advance the index (e.g. unknown FC but not enough data yet)
                 # This case indicates we need more data for the current frame start
                 log.debug("Need more data for current frame start.")
                 break # Exit while loop, wait for more data

        # Return only the unprocessed part of the buffer
        return modbusdata[bufferIndex:]


    # --------------------------------------------------------------------------- #
    # Calculate the modbus CRC
    # --------------------------------------------------------------------------- #
    def calcCRC16(self, data): # Takes data buffer
        # (CRC calculation code remains the same as previous version)
        crcHi = 0xFF
        crcLo = 0xFF
        crcHiTable = [0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40]
        crcLoTable = [0x00, 0xC0, 0xC1, 0x01, 0xC3, 0x03, 0x02, 0xC2, 0xC6, 0x06, 0x07, 0xC7, 0x05, 0xC5, 0xC4, 0x04, 0xCC, 0x0C, 0x0D, 0xCD, 0x0F, 0xCF, 0xCE, 0x0E, 0x0A, 0xCA, 0xCB, 0x0B, 0xC9, 0x09, 0x08, 0xC8, 0xD8, 0x18, 0x19, 0xD9, 0x1B, 0xDB, 0xDA, 0x1A, 0x1E, 0xDE, 0xDF, 0x1F, 0xDD, 0x1D, 0x1C, 0xDC, 0x14, 0xD4, 0xD5, 0x15, 0xD7, 0x17, 0x16, 0xD6, 0xD2, 0x12, 0x13, 0xD3, 0x11, 0xD1, 0xD0, 0x10, 0xF0, 0x30, 0x31, 0xF1, 0x33, 0xF3, 0xF2, 0x32, 0x36, 0xF6, 0xF7, 0x37, 0xF5, 0x35, 0x34, 0xF4, 0x3C, 0xFC, 0xFD, 0x3D, 0xFF, 0x3F, 0x3E, 0xFE, 0xFA, 0x3A, 0x3B, 0xFB, 0x39, 0xF9, 0xF8, 0x38, 0x28, 0xE8, 0xE9, 0x29, 0xEB, 0x2B, 0x2A, 0xEA, 0xEE, 0x2E, 0x2F, 0xEF, 0x2D, 0xED, 0xEC, 0x2C, 0xE4, 0x24, 0x25, 0xE5, 0x27, 0xE7, 0xE6, 0x26, 0x22, 0xE2, 0xE3, 0x23, 0xE1, 0x21, 0x20, 0xE0, 0xA0, 0x60, 0x61, 0xA1, 0x63, 0xA3, 0xA2, 0x62, 0x66, 0xA6, 0xA7, 0x67, 0xA5, 0x65, 0x64, 0xA4, 0x6C, 0xAC, 0xAD, 0x6D, 0xAF, 0x6F, 0x6E, 0xAE, 0xAA, 0x6A, 0x6B, 0xAB, 0x69, 0xA9, 0xA8, 0x68, 0x78, 0xB8, 0xB9, 0x79, 0xBB, 0x7B, 0x7A, 0xBA, 0xBE, 0x7E, 0x7F, 0xBF, 0x7D, 0xBD, 0xBC, 0x7C, 0xB4, 0x74, 0x75, 0xB5, 0x77, 0xB7, 0xB6, 0x76, 0x72, 0xB2, 0xB3, 0x73, 0xB1, 0x71, 0x70, 0xB0, 0x50, 0x90, 0x91, 0x51, 0x93, 0x53, 0x52, 0x92, 0x96, 0x56, 0x57, 0x97, 0x55, 0x95, 0x94, 0x54, 0x9C, 0x5C, 0x5D, 0x9D, 0x5F, 0x9F, 0x9E, 0x5E, 0x5A, 0x9A, 0x9B, 0x5B, 0x99, 0x59, 0x58, 0x98, 0x88, 0x48, 0x49, 0x89, 0x4B, 0x8B, 0x8A, 0x4A, 0x4E, 0x8E, 0x8F, 0x4F, 0x8D, 0x4D, 0x4C, 0x8C, 0x44, 0x84, 0x85, 0x45, 0x87, 0x47, 0x46, 0x86, 0x82, 0x42, 0x43, 0x83, 0x41, 0x81, 0x80, 0x40]

        for byte in data:
            index = crcHi ^ byte
            crcHi = crcLo ^ crcHiTable[index]
            crcLo = crcLoTable[index]
        return (crcHi << 8) | crcLo

# --------------------------------------------------------------------------- #
# Print the usage help (remains the same)
# --------------------------------------------------------------------------- #
def printHelp(baud, timeout_val):
    # (Help text code remains the same as previous version)
    if timeout_val is None:
        timeout_val = calcTimeout(baud)
    print("\nUsage:")
    print("  python modbus_sniffer.py -p <serial_port> [options]")
    print("")
    print("Arguments:")
    print("  -p, --port       <port>    Serial port to use (e.g., /dev/ttyUSB0, COM3) (Required)")
    print("  -b, --baudrate   <baud>    Communication baud rate (default: 9600)")
    print(f"  -t, --timeout    <secs>    Inter-frame timeout in seconds (default: {timeout_val:.6f}s for {baud} baud)")
    print("  -h, --help                 Print this help message")
    print("\nFTP Upload Options (Optional):")
    print("  --ftp_host       <host>    FTP server hostname or IP address")
    print("  --ftp_user       <user>    FTP username")
    print("  --ftp_pass       <pass>    FTP password")
    print("  --ftp_dir        <dir>     Remote directory on FTP server (default: /)")
    print("")

# --------------------------------------------------------------------------- #
# Calculate the timeout (remains the same)
# --------------------------------------------------------------------------- #
def calcTimeout(baud):
    # (Timeout calculation code remains the same as previous version)
    if baud > 0:
         return 38.5 / baud # 3.5 char times
    else:
        return 0.005

# --------------------------------------------------------------------------- #
# configure a clean exit (remains the same)
# --------------------------------------------------------------------------- #
sniffer_instance = None
def signal_handler(sig, frame):
    # (Signal handler code remains the same as previous version)
    print('\nCtrl+C detected. Shutting down gracefully...')
    if sniffer_instance:
        sniffer_instance.close()
    print('CSV issue log saved.')
    print('Goodbye\n')
    sys.exit(0)

# --------------------------------------------------------------------------- #
# main routine (remains the same logic, args passed to modified class)
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    # (Main routine code remains the same as previous version)
    print("Modbus RTU Sniffer - Issue Logger with FTP Upload") # Updated title slightly
    print("Press Ctrl+C to exit.")

    signal.signal(signal.SIGINT, signal_handler)

    port = None
    baud = 9600
    timeout_arg = None
    ftp_host = None
    ftp_user = None
    ftp_password = None
    ftp_dir = None

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hp:b:t:", ["help", "port=", "baudrate=", "timeout=", "ftp_host=", "ftp_user=", "ftp_pass=", "ftp_dir="])
    except getopt.GetoptError as e:
        log.error(f"Argument error: {e}")
        printHelp(baud, timeout_arg)
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            printHelp(baud, timeout_arg)
            sys.exit()
        elif opt in ("-p", "--port"):
            port = arg
        elif opt in ("-b", "--baudrate"):
            try:
                baud = int(arg)
                if baud <= 0: raise ValueError("Baud rate must be positive.")
            except ValueError as e:
                log.error(f"Invalid baud rate '{arg}': {e}")
                sys.exit(2)
        elif opt in ("-t", "--timeout"):
             try:
                timeout_arg = float(arg)
                if timeout_arg <= 0: raise ValueError("Timeout must be positive.")
             except ValueError as e:
                 log.error(f"Invalid timeout value '{arg}': {e}")
                 sys.exit(2)
        elif opt == "--ftp_host":
            ftp_host = arg
        elif opt == "--ftp_user":
            ftp_user = arg
        elif opt == "--ftp_pass":
            ftp_password = arg
        elif opt == "--ftp_dir":
            ftp_dir = arg

    if port is None:
        log.error("Serial Port (-p or --port) is required.")
        printHelp(baud, timeout_arg)
        sys.exit(2)

    timeout_val = timeout_arg if timeout_arg is not None else calcTimeout(baud)

    try:
        sniffer_instance = SerialSnooper(port, baud, timeout_val, ftp_host, ftp_user, ftp_password, ftp_dir)
        log.info("Sniffer started. Logging Modbus issues. Press Ctrl+C to stop.")
        with sniffer_instance:
            while True:
                read_data = sniffer_instance.read_raw()
                sniffer_instance.process_data(read_data)

    except serial.SerialException as e:
         log.fatal(f"Failed to open serial port {port}: {e}")
         sys.exit(1)
    except Exception as e:
         log.fatal(f"An unexpected error occurred: {e}", exc_info=True)
         if sniffer_instance:
             sniffer_instance.close()
         sys.exit(1)
