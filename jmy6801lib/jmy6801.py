#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""
Jinmuyu JMY6801 NFC/ISO7816 module driver

Author: Tennessee Carmel-Veilleux <tcv@ro.boto.ca>
Created on: 12/19/2015

Copyright 2015, Tennessee Carmel-Veilleux
"""
from easy_secure_element import SecureElementChannel, SecureElementSession

class JMY6801SecureElementChannel(SecureElementChannel):
    def __init__(self, port, apdu_command, close_command, addr=None):
        super(JMY6801SecureElementChannel, self).__init__()
        self.port = port
        self.apdu_command = apdu_command
        self.close_command = close_command
        self.addr = addr

    def sendrecv_apdu_bytes(self, apdu_request_bytes, timeout=None):
        data = []
        if self.addr is not None:
            data.append(self.addr)

        data.extend(apdu_request_bytes)
        success, result = self.port.sendrecv(self.apdu_command, data, timeout=timeout)
        if success:
            if self.addr is not None:
                # SAM slot address case: address is returned with data, so discard first
                return result[1:]
            else:
                # ISO14443 case: no address returned, only APDU data
                return result[:]
        else:
            return None

    def close(self):
        if self.close_command is None:
            return

        data = []
        if self.addr is not None:
            data.append(self.addr)
        success, _ = self.port.sendrecv(self.close_command, data, timeout=1.0)
        return success


class JMY6801(object):
    RF_LEVEL_WEAKEST = 3
    RF_LEVEL_WEAK = 2
    RF_LEVEL_STRONG = 1
    RF_LEVEL_STRONGEST = 0

    def __init__(self, port):
        self.port = port
        self.default_timeout = 1.0

    def set_module_working_mode(self, rf_enable, auto_request_enable):
        """
        Set working mode (see JMY6801 manual section 5.2.4)
        :param rf_enable: True to enable RF field, False to disable
        :param auto_request_enable: True to enable auto-polling of cards, False to just have basic field
        :return: True on success, False on failure
        """
        data = 0x01 if rf_enable else 0x00
        data |= 0x02 if auto_request_enable else 0x00

        success, _ = self.port.sendrecv(0x11, [data], timeout=self.default_timeout)
        return success

    def set_module_idle(self):
        """
        Make module return to idle (see JMY6801 manual section 5.2.5)
        :return: True on success, False on failure
        """
        success, _ = self.port.sendrecv(0x12, [0x55], timeout=self.default_timeout)
        return success

    def set_buzzer(self, time_ms):
        """
        Turn buzzer on for given time in ms. (see JMY6801 manual section 5.2.7)
        :param time_ms: Time to turn buzzer on in ms
        :return: True on success, False on failure
        """
        if time_ms < 0 or time_ms > 2500:
            return False

        data = int(time_ms) // 10
        success, _ = self.port.sendrecv(0x14, [data], timeout=self.default_timeout)
        return success

    def set_led(self, green_enable, red_enable):
        """
        Enable/disable the red and green LEDs (see JMY6801 manual section 5.2.6)
        :param green_enable: True to turn green LED on, False to turn off
        :param red_enable: True to turn red LED on, False to turn off
        :return: True on success, False on failure
        """
        data = 0x01 if green_enable else 0x00
        data |= 0x02 if red_enable else 0x00

        success, _ = self.port.sendrecv(0x13, [data], timeout=self.default_timeout)
        return success

    def set_rf_output_level(self, level):
        """
        Set the RF output level. Only levels in self.RF_LEVEL* are available.
        (see JMY6801 manual section 5.2.20)

        :param level: one of RF_LEVEL_STRONGEST/STRONG/WEAK/WEAKEST
        :return: True on success, False on failure
        """
        if level < 0 or level > 3:
            return False

        success, _ = self.port.sendrecv(0x02, [level], timeout=self.default_timeout)
        return success

    def open_emv_cl_session(self):
        # Send a WUPA, which resets the card and makes it respond if in field.
        success, data = self.port.sendrecv(0x20, [0x00], timeout=0.5)
        if not success:
            return None, None
        #
        # sak_byte = data[-1]
        # atqa_bytes = data[-3:-1]
        # uid_bytes = data[:-3]
        # uid = long(0)
        # for uid_byte in uid_bytes:
        #     uid <<= 8
        #     uid |= (uid_byte & 0xFF)
        #
        # # TODO: Use sak/atqa/uid bytes

        success, data = self.port.sendrecv(0x32, [], timeout=self.default_timeout)
        if not success:
            return None, None

        # TODO: Split data out and determine A versus B
        channel = JMY6801SecureElementChannel(self.port, 0x31, None)
        session = SecureElementSession(channel)

        return session, data

    def open_iso7816_session(self, slot_number=1, init_baud=9600, main_baud=115200):
        baud_to_id = { 9600: 0, 19200: 1, 38400: 2, 55800: 3, 57600: 4, 115200: 5, 230400: 6 }

        if init_baud not in baud_to_id:
            raise ValueError("Invalid init_baud: %d" % init_baud)

        if main_baud not in baud_to_id:
            raise ValueError("Invalid main_baud: %d" % main_baud)

        if slot_number < 0 or slot_number > 2:
            raise ValueError("Wrong slot_number: %d (valid: [0..2])" % slot_number)

        init_baud_value = baud_to_id[init_baud]
        main_baud_value = baud_to_id[main_baud]

        # Do a ISO7816 card reset
        success, data = self.port.sendrecv(0x4D, [slot_number, init_baud_value], timeout=0.5)
        if not success:
            return None, None

        # TODO: Add baud rate switch

        atr_bytes = data[5:]

        channel = JMY6801SecureElementChannel(self.port, 0x4F, 0x4C, slot_number)
        session = SecureElementSession(channel)

        return session, atr_bytes
