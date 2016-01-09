#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""
Client for Tiny Access Control Applet (TACAPP)

Author: Tennessee Carmel-Veilleux <tcv@ro.boto.ca>
Created on: 12/23/2015

Copyright 2015, Tennessee Carmel-Veilleux
"""
from jmy6801lib.easy_secure_element import CommandAPDU
from datetime import datetime
import os
from Crypto.Cipher import DES3
import logging
import re


class TACAPPDriver(object):
    def __init__(self, session, shared_key_hex, applet_aid_hex="D0D1D2D3D4D5D2D0"):
        """
        Constructor for access controller driver.

        :param session: Secure element session (like easy_secure_element.SecureElementSession)
        :param shared_key_hex: Shared key as a hex string (24 bytes, 48 characters)
        :param applet_aid_hex: AID for the applet (differs per build)
        :return: an instance of the TACAPP driver
        """
        if not re.match("[0-9A-Fa-f]{48}", shared_key_hex):
            raise ValueError("Invalid hex shared key: '%s'" % shared_key_hex)
        if not re.match("[0-9A-Fa-f]{6,}", applet_aid_hex):
            raise ValueError("Invalid hex AID: '%s'" % applet_aid_hex)

        self.session = session
        self.shared_key = shared_key_hex
        self.applet_aid = applet_aid_hex
        self.logger = logging.getLogger('TACAPPDriver')
        self.logger.addHandler(logging.NullHandler())

    def _get_cplc(self):
        # Select ISD
        select_isd_apdu = CommandAPDU.gen_select_aid("A000000151000000")
        response = self.session.sendrecv_apdu(select_isd_apdu, 1.0)
        if response.get_status() != 0x9000:
            # LOG ERROR: Could not select ISD
            return None

        get_cplc_apdu = CommandAPDU.from_bytes("80CA9F7F00")
        response = self.session.sendrecv_apdu(get_cplc_apdu, 1.0)
        if response.get_status() != 0x9000:
            # LOG ERROR: Could not read CPLC
            return None

        resp_bytes = response.get_response_bytes()
        if resp_bytes[0:2] != [0x9F, 0x7F] or len(resp_bytes) < 4:
            # LOG ERROR: CPLC response invalid
            return None

        # Actual CPLC starts after echo of P1/P2 and size byte
        return resp_bytes[3:]

    def _serial_from_cplc(self, cplc):
        # Batch number + serial == serial
        return cplc[10:16]

    def authenticate(self, loc_id):
        # TODO: Check that loc_id is an 8 bytes hex string and/or allow for other representations

        # Challenge is 7 bytes data YYYYMMDDhhmmss + 4 bytes location ID + 24 random bytes
        challenge = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        challenge += loc_id
        challenge += os.urandom(24).encode("hex")
        challenge = map(ord, challenge.decode("hex"))

        challenge_apdu = CommandAPDU(0x84, 0x01, 0x00, 0x00, [len(challenge)] + challenge)
        response = self.session.sendrecv_apdu(challenge_apdu, 3.0)
        if response.get_status() != 0x9000:
            self.logger.error("Non-success response from applet, SW=0x%04X", response.get_status())
            return False

        shared_key_bytes = self.shared_key.decode("hex")

        cipher = DES3.new(shared_key_bytes, DES3.MODE_CBC, IV="0000000000000000".decode("hex"))
        decrypted = cipher.decrypt("".join([chr(c) for c in response.get_response_bytes()]))

        # Encrypted challenge is last 24 bytes of challenge
        if map(ord, decrypted) != challenge[-24:]:
            self.logger.error("Unsuccessful authentication!")
            return False
        else:
            return True

    def select_applet(self):
        # Select access control applet
        select_aid_apdu = CommandAPDU.gen_select_aid(self.applet_aid)
        response = self.session.sendrecv_apdu(select_aid_apdu, 1.0)
        self.logger.debug("SELECT AID response: %s", str(response))

        if response.get_status() == 0x6A82:
            self.logger.debug("Access control applet not installed !")
            return False, None
        elif response.get_status() != 0x9000:
            self.logger.warn("Error selecting access control applet: SW=0x%04X", response.get_status())
            return False, None
        else:
            return True, response.get_response_bytes()

    def personalize(self):
        self.logger.info("======= Starting personalization of access control applet ========")

        # Get CPLC
        cplc = self._get_cplc()

        if cplc is None or len(cplc) < 0x20:
            self.logger.error("Error getting CPLC!")
            return False

        serial_number = self._serial_from_cplc(cplc)

        # Personalize serial number from value extracted from CPLC
        set_serial_apdu = CommandAPDU(0x84, 0xA1, 0x00, 0x00, [len(serial_number)] + serial_number + [0x00])
        response = self.session.sendrecv_apdu(set_serial_apdu, 2.0)
        self.logger.debug("Personalize serial response: %s", str(response))

        if response.get_status() != 0x9000:
            self.logger.error("Error personalizing serial number: SW=0x%04X", response.get_status())
            return False

        shared_key_bytes = map(ord, self.shared_key.decode("hex"))
        set_key_apdu = CommandAPDU(0x84, 0xA0, 0x00, 0x00, [len(shared_key_bytes)] + shared_key_bytes)
        response = self.session.sendrecv_apdu(set_key_apdu, 2.0)
        self.logger.debug("Personalize key response: %s", str(response))

        if response.get_status() != 0x9000:
            self.logger.error("Error personalizing key: SW=0x%04X", response.get_status())
            return False

