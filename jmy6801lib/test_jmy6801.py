#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""
Test program for JMY6801 module

Author: Tennessee Carmel-Veilleux <tcv@ro.boto.ca>
Created on: 12/19/2015

Copyright 2015, Tennessee Carmel-Veilleux

"""

import time

import jcp05serial
import jmy6801
import tacapp_driver

SHARED_KEY = "3812A419C63BE77100120019803BE771011201010103E771"

def test_led(device):
    for i in range(5):
        device.set_led(False, False)
        time.sleep(0.1)
        device.set_led(True, False)
        time.sleep(0.1)
        device.set_led(False, True)
        time.sleep(0.1)
        device.set_led(True, True)
        time.sleep(0.1)


def test_buzzer(device):
    for i in range(3):
        device.set_buzzer(10)
        time.sleep(0.1)
        device.set_buzzer(20)
        time.sleep(0.1)
        device.set_buzzer(30)
        time.sleep(0.1)


def test_rf(device):
    for level in [device.RF_LEVEL_WEAKEST, device.RF_LEVEL_WEAK, device.RF_LEVEL_STRONG, device.RF_LEVEL_STRONGEST]:
        device.set_module_working_mode(False, False)

        for i in range(3):
            device.set_rf_output_level(level)
            device.set_module_working_mode(True, False)
            time.sleep(0.5)
            device.set_module_working_mode(False, False)
            time.sleep(0.5)

        time.sleep(1.0)


def test_iso7816(device, slot_number=1):
    session, atr_bytes = device.open_iso7816_session(slot_number=slot_number)

    if session is None:
        print "ERROR opening iso7816 session!"
        return False

    client = tacapp_driver.TACAPPDriver(session, SHARED_KEY)

    success, serial_number =  client.select_applet()
    if not success:
        print "Could not select Vahid's Access Control applet"
        return False

    print serial_number

    # If applet did not return a serial number, personalize the applet
    if len(serial_number) == 0:
        client.personalize()

    # TODO: Try a challenge
    success = client.authenticate("DEADBEEF")

    return True


def main():
    port = jcp05serial.JCP05SerialDevice("COM13", verbose=True)
    device = jmy6801.JMY6801(port)

    test_iso7816(device)

    #test_led(device)
    #test_buzzer(device)
    #test_rf(device)

    port.close()

if __name__ == "__main__":
    main()