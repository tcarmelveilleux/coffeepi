#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""
Simple access control application for NFC smartcards

Author: Tennessee Carmel-Veilleux <tcv@ro.boto.ca>
Created on: 12/30/2015

Copyright 2015, Tennessee Carmel-Veilleux
"""

from jmy6801lib import jcp05serial, jmy6801
import tacapp_driver
import loggly.handlers
import logging
import time
import sys
import os

from threading import Thread
import Queue
import multiprocessing

SHARED_KEY = "3812A419C63BE77100120019803BE771011201010103E771"
LOGGLY_TOKEN = "9d1bfad8-a04c-4607-97e9-8a0c89a4ee3e"
TRIGGER_DRIVER = "/bin/sh make_coffee.sh"

class AccessControlDaemon(object):
    STATE_WAIT_FOR_CARD = "wait_for_card"
    STATE_WAITING_FOR_REMOVAL = "wait_for_removal"

    EVENT_POLL = "poll"
    EVENT_DONE = "done"

    def __init__(self, port_name):
        self.port_name = port_name
        self.running = False
        self.thread = Thread(target=self._process)
        self.thread.daemon = False
        self.event_queue = multiprocessing.Queue()
        self.state = self.STATE_WAIT_FOR_CARD
        self.port = None
        self.device = None
        self.session = None
        self.poll_rate_seconds = 0.1
        self.logger = logging.getLogger('AccessControlDaemon')
        self.logger.addHandler(logging.NullHandler())
        self.location_id = "DEADBEEF"
        self.shared_key = SHARED_KEY

    def start(self):
        self.logger.info("Starting access control daemon on port %s", self.port_name)
        self.port = jcp05serial.JCP05SerialDevice(self.port_name, verbose=False)
        self.device = jmy6801.JMY6801(self.port)

        self._front_panel_idle()

        self.running = True
        self.thread.start()

    def finish(self):
        self.logger.info("Terminating access control session!")
        self.event_queue.put({"type": self.EVENT_DONE})

        if self.thread.is_alive():
            self.thread.join(5.0)
            if self.thread.is_alive():
                self.logger.error("Timed-out waiting for access control thread to terminate!")

    def _cleanup(self):
        # Cleanup
        if self.session is not None:
            self.session.close()
            self.session = None
        if self.device is not None:
            self.device.close()
            self.device = None
        if self.port is not None:
            self.port.close()
            self.port = None

    def _process(self):
        while self.running:
            try:
                event = self.event_queue.get(block=True, timeout=self.poll_rate_seconds)
                self._handle_event(event)
            except Queue.Empty:
                self.event_queue.put({"type": self.EVENT_POLL})

        self._cleanup()

    def _handle_event(self, event):
        event_type = event["type"]

        if event_type == self.EVENT_DONE:
            self.running = False
            return
        elif event_type == self.EVENT_POLL:
            if self.state == self.STATE_WAIT_FOR_CARD:
                self._detect_card()
            elif self.state == self.STATE_WAITING_FOR_REMOVAL:
                session, atr_data = self.device.open_emv_cl_session()
                if session is None:
                    # Card no longer detected, go back to waiting after dead time
                    self.logger.info("Card gone, resetting detection loop.")
                    self._front_panel_idle()
                    time.sleep(1.0)
                    self.state = self.STATE_WAIT_FOR_CARD
                    return
            else:
                self.logger.error("Unexpected state: %s", self.state)
                self.state = self.STATE_WAITING_FOR_REMOVAL
        else:
            self.logger.error("Unexpected event type %s during state %s", event_type, self.state)

    def _front_panel_idle(self):
        # Green LED on
        self.device.set_led(True, False)

    def _front_panel_warning(self, num_blinks):
        # Red blink with sound
        for i in range(num_blinks):
            self.device.set_buzzer(200)
            self.device.set_led(False, True)
            time.sleep(0.25)
            self.device.set_led(False, False)
            time.sleep(0.25)

    def _front_panel_error(self):
        # Red LED on for 2 seconds
        self.device.set_led(False, True)
        self.device.set_buzzer(500)
        time.sleep(2.0)

    def _front_panel_success(self):
        # Green blink 2 times
        self.device.set_buzzer(100)
        for i in range(2):
            self.device.set_led(False, False)
            time.sleep(0.1)
            self.device.set_led(True, False)
            time.sleep(0.1)

        self.device.set_led(False, False)

    def _detect_card(self):
        session, atr_data = self.device.open_emv_cl_session()
        if session is None:
            # No card detected, nothing more to do
            return

        self.logger.info("Card detected, ATR data: %s", str(atr_data))
        self.session = session

        # DOUBLE HACK: Run right away on card detect for now
        self._front_panel_success()
        self._trigger_authorized_system()
        return

        try:
            # HACK: Route session to internal SAM slot 1
            # FIXME: Remove hack
            #session, atr_data = self.device.open_iso7816_session(slot_number=1)

            client = tacapp_driver.TACAPPDriver(session, self.shared_key)

            # Step 1: Try to select applet
            success, serial_number = client.select_applet()
            if not success:
                self.logger.info("Could not select Access Control applet, not installed!")
                self._front_panel_warning(2)
                self.state = self.STATE_WAITING_FOR_REMOVAL
                self.session.close()
                return

            # If applet did not return a serial number, it is not personalized yet. Emit an error
            if len(serial_number) == 0:
                self.logger.info("Card not personalized!")
                self._front_panel_warning(3)
                self.state = self.STATE_WAITING_FOR_REMOVAL
                self.session.close()
                return

            # Step 2: Try to authenticate
            success = client.authenticate(self.location_id)
            if not success:
                self.logger.info("Authentication failed for card serial number: %s!", str(serial_number))
                self._front_panel_error()
            else:
                # TODO: Actuate something!
                self.logger.info("Authentication succeeded for card serial number: %s!", str(serial_number))
                self._front_panel_success()
                self._trigger_authorized_system()

            # Step 3: Clean-up
            self.state = self.STATE_WAITING_FOR_REMOVAL
            self.session.close()
            return
        except Exception as e:
            self.logger.warn("Error while trying to communicate with card: %s", e.message)

    def _trigger_authorized_system(self):
        self.logger.info("Actuating authorized system with '%s'", TRIGGER_DRIVER)
        os.system(TRIGGER_DRIVER)

def setup_logging():
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S',
                        filename='access_controller.log',
                        filemode='w')

    # define a Handler which writes DEBUG messages or higher to the sys.stderr
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG)
    # set a format which is simpler for console use
    formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')
    # tell the handler to use this format
    console.setFormatter(formatter)
    # add the handler to the root logger
    root_logger = logging.getLogger('')

    json_formatter = logging.Formatter('{ "loggerName":"%(name)s", "asciTime":"%(asctime)s", "fileName":"%(filename)s", "logRecordCreationTime":"%(created)f", "functionName":"%(funcName)s", "levelNo":"%(levelno)s", "lineNo":"%(lineno)d", "time":"%(msecs)d", "levelName":"%(levelname)s", "message":"%(message)s"}')
    loggly_handler = loggly.handlers.HTTPSHandler("https://logs-01.loggly.com/inputs/%s/tag/python" % LOGGLY_TOKEN, 'POST')
    loggly_handler.setFormatter(json_formatter)

    root_logger.addHandler(console)
    root_logger.addHandler(loggly_handler)

def main():
    setup_logging()

    server = AccessControlDaemon(sys.argv[1])
    server.start()

if __name__ == "__main__":
    main()
