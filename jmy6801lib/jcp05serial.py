#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""
Jinmuyu JCP05 serial protocol handler

Author: Tennessee Carmel-Veilleux <tcv@ro.boto.ca>
Created on: 12/19/2015

Copyright 2015, Tennessee Carmel-Veilleux
"""
import serial
import logging

class JCP05SerialDevice(object):
    def __init__(self, port, address=0, baudrate=19200, verbose=False):
        self.address = address
        self.port = port
        self.serial = serial.Serial(port=port, baudrate=baudrate)
        self.verbose = verbose
        self.logger = logging.getLogger('JCP05SerialDevice')
        self.logger.addHandler(logging.NullHandler())

    def _checksum(self, data):
        checksum = 0
        for b in data:
            checksum = (checksum ^ b) & 0xFF
        return checksum

    def sendrecv(self, command, data, timeout=None):
        # Discard previous data to prevent post-timeout results from blowing-up if possible
        self.serial.flushInput()

        # Prepare packet according to JCP05 header:
        # [len MSB] [len LSB] [address] [command] [...... data ........] [checksum]
        # len includes the header (4 bytes)
        len_hi = ((4 + len(data)) >> 8) & 0x01
        len_low = (4 + len(data)) & 0xFF
        packet = "".join([chr(c) for c in [len_hi, len_low, self.address & 0xFF, command & 0xFF]])
        if isinstance(data, str):
            packet += data
        else:
            packet += "".join([chr(c & 0xFF) for c in data])

        checksum = self._checksum([ord(c) for c in packet])
        packet += chr(checksum & 0xFF)

        if self.verbose:
            self.logger.info("--> %s", packet.encode("hex"))

        # Write packet to port
        self.serial.write(packet)

        # Wait for response (first of len)
        self.serial.timeout = timeout
        in_packet = self.serial.read(2)

        # Check for command timeout, returning None on timeout
        if len(in_packet) != 2:
            return False, None

        in_len = (ord(in_packet[0]) << 8) | ord(in_packet[1])
        # Read remaining bytes (in_len - 2 for len already read + 1 for checksum)
        in_packet += self.serial.read(in_len - 1)
        if self.verbose:
            self.logger.info("<-- %s", in_packet.encode("hex"))

        in_packet = map(ord, in_packet)

        # If packet too short, return None
        if len(in_packet) < 5:
            return False, None

        # Verify checksum, return empty, meaning checksum error
        if self._checksum(in_packet[:-1]) != in_packet[-1]:
            return False, None

        # Verify success, returning response data if any
        if in_packet[3] != command:
            return False, []
        else:
            return True, in_packet[4:-1]

    def close(self):
        self.serial.close()

if __name__ == "__main__":
    d = JCP05SerialDevice("COM13")
    d.sendrecv(0x11, [0x00])