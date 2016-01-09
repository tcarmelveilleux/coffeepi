#!/bin/sh
COFFEE_GPIO=4

# Make GPIO available to user program
gpio export $COFFEE_GPIO out

# Make sure GPIO is low
gpio -g write $COFFEE_GPIO 0

# Simlate button press for 0.5 seconds
gpio -g write $COFFEE_GPIO 1
sleep 0.5
gpio -g write $COFFEE_GPIO 0


