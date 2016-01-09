#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""
Easy Secure Element abstractions for ISO7816/ISO14443 smartcard interfaces

Author: Tennessee Carmel-Veilleux <tcv@ro.boto.ca>
Created on: 12/23/2015

Copyright 2015, Tennessee Carmel-Veilleux
"""

class SecureElementException(Exception):
    def __init__(self, message, errors=None):
        super(SecureElementException, self).__init__(message)
        self.errors = errors


class SecureElementChannel(object):
    def sendrecv_adpu_bytes(self, apdu_command_bytes, timeout=None):
        pass

    def close(self):
        pass


class APDU(object):
    def __init__(self):
        self.is_command_apdu = True
        self.apdu_bytes = []

    def __len__(self):
        return len(self.apdu_bytes)

    def __getitem__(self, key):
        return self.apdu_bytes.__getitem__(key)

    def get_bytes(self):
        return self.apdu_bytes[:]


class CommandAPDU(APDU):
    @classmethod
    def from_bytes(cls, apdu_bytes):
        """
        Construct a command APDU from the given bytes

        :param apdu_bytes: Raw bytes making-up the APDU
        :return: a new CommandAPDU instance
        """
        if isinstance(apdu_bytes, str):
            apdu_bytes = map(ord, apdu_bytes.decode("hex"))
        else:
            apdu_bytes = apdu_bytes

        if len(apdu_bytes) < 4:
            raise SecureElementException("Not enough APDU bytes provided to build a command APDU!")
        return cls(apdu_bytes[0], apdu_bytes[1], apdu_bytes[2], apdu_bytes[3], apdu_bytes[4:])

    def __init__(self, ins, cla, p1, p2, payload=None):
        super(CommandAPDU, self).__init__()
        self.is_command_apdu = True
        self.apdu_bytes.extend([ins, cla, p1, p2])
        self.case = ""
        self.le = 0

        if isinstance(payload, str):
            payload = map(ord, payload.decode("hex"))
        else:
            payload = payload

        if payload is not None and len(payload) > 0:
            self.apdu_bytes.extend(payload)

        if payload is not None and len(payload) >= 1:
            total_len = 4 + len(payload)
            c_5 = payload[0]

            if total_len == (c_5 + 6) and c_5 != 0:
                self.case = "4S"
                self.le = payload[-1]
            elif total_len == (c_5 + 5) and c_5 != 0:
                self.case = "3S"
            elif total_len == 5:
                self.case = "2S"
                self.le = c_5
        else:
            self.case = "1S"

        # TODO: Support extended types 2E, 3E, 4E. See ISO7816-3:2006 section 12.1.3.

        if self.case == "":
            raise SecureElementException("APDU payload content does not map to an ISO type !")

    def get_cla(self):
        return self.apdu_bytes[0]

    def get_ins(self):
        return self.apdu_bytes[1]

    def get_p1(self):
        return self.apdu_bytes[2]

    def get_p2(self):
        return self.apdu_bytes[3]

    def get_lc(self):
        if self.case == "3S" or self.case == "4S":
            return self.apdu_bytes[4]
        else:
            return 0

    def get_le(self):
        return self.le

    def get_data_field(self):
        if self.case == "3S":
            return self.apdu_bytes[5:]
        elif self.case == "4S":
            return self.apdu_bytes[5:-1]
        else:
            return []

    def get_iso_case(self):
        return self.case

    @classmethod
    def gen_select_aid(cls, aid):
        if isinstance(aid, str):
            aid_bytes = map(ord, aid.decode("hex"))
        else:
            aid_bytes = list(aid[:])
        aid_len = len(aid_bytes)

        return cls(0x00, 0xA4, 0x04, 00, [aid_len] + aid_bytes)

    def __str__(self):
        ret_str = "[CommandAPDU case %s, CLA=0x%02X, INS=0x%02X, P1=0x%02X, P2=0x%02X, " % (
            self.get_iso_case(), self.get_cla(), self.get_ins(), self.get_p1(), self.get_p2()
        )

        if self.case == "3S" or self.case == "4S":
            ret_str += "Lc=0x%02X, Le=0x%02X Data=%s]" % (self.get_lc(), self.get_le(),
                ("".join([chr(c) for c in self.get_data_field()])).encode("hex")
            )
        else:
            ret_str += "Le=0x%02X]" % (self.get_le())

        return ret_str

class ResponseAPDU(APDU):
    @classmethod
    def from_bytes(cls, apdu_bytes):
        """
        Construct a response APDU from the given bytes

        :param apdu_bytes: Raw bytes making-up the APDU
        :return: a new ResponseAPDU instance
        """
        if isinstance(apdu_bytes, str):
            apdu_bytes = map(ord, apdu_bytes.decode("hex"))
        else:
            apdu_bytes = apdu_bytes

        if len(apdu_bytes) < 2:
            raise SecureElementException("Not enough APDU bytes provided to build a response APDU!")
        return cls(apdu_bytes[-2], apdu_bytes[-1], apdu_bytes[:-2])

    def __init__(self, sw1, sw2, payload=None):
        super(ResponseAPDU, self).__init__()
        self.is_command_apdu = False

        if payload is not None:
            self.apdu_bytes.extend(payload)

        self.apdu_bytes.append(sw1)
        self.apdu_bytes.append(sw2)

    def get_status(self):
        return ((self.apdu_bytes[-2] & 0xff) << 8) | (self.apdu_bytes[-1] & 0xff)

    def get_sw1(self):
        return self.apdu_bytes[-2] & 0xff

    def get_sw2(self):
        return self.apdu_bytes[-1] & 0xff

    def get_response_bytes(self):
        return self.apdu_bytes[:-2]

    def __str__(self):
        ret_str = "[ResponseAPDU SW=0x%02X%02X" % (self.get_sw1(), self.get_sw2())
        if len(self.get_response_bytes()) > 0:
            ret_str += " Data=%s" % ("".join([chr(c) for c in self.get_response_bytes()])).encode("hex")
        ret_str += "]"

        return ret_str

class SecureElementSession(object):
    def __init__(self, channel):
        self.channel = channel

    def sendrecv_apdu(self, apdu, timeout=None):
        if isinstance(apdu, APDU):
            apdu_bytes = apdu.get_bytes()
        elif isinstance(apdu, list) or isinstance(apdu, bytearray) or isinstance(apdu, bytes):
            apdu_bytes = apdu[:]
        elif isinstance(apdu, str):
            apdu_bytes = map(ord, apdu)
        else:
            raise TypeError("Cannot process APDU data of source type %s" % str(type(apdu)))

        response_apdu_bytes = self.channel.sendrecv_apdu_bytes(apdu_bytes, timeout=timeout)

        if response_apdu_bytes is None:
           raise SecureElementException("Communication error while trying to exchange APDU")

        if len(response_apdu_bytes) >= 2:
            return ResponseAPDU.from_bytes(response_apdu_bytes)
        else:
            raise SecureElementException("APDU response length too short !")

    def close(self):
        self.channel.close()
