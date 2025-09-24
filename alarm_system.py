#!/usr/bin/env python3
# alarm_system.py — Manages the buzzer and LED hardware dynamically

import RPi.GPIO as GPIO
import time
from gi.repository import GLib

# --- State ---
_alarm_active = False
_on_trigger_callback = None
_on_clear_callback = None

# --- Setup ---
def setup_alarm(on_trigger_callback, on_clear_callback):
    """
    Initializes the alarm system callbacks. Pins are specified in each function call.
    """
    global _on_trigger_callback, _on_clear_callback
    _on_trigger_callback = on_trigger_callback
    _on_clear_callback = on_clear_callback
    
    GPIO.setwarnings(False)
    GPIO.setmode(GPIO.BCM)
    print("✅ Alarm system callbacks initialized.")

def is_active():
    """Returns True if the alarm is currently active."""
    return _alarm_active

# --- Core Alarm Logic ---
def trigger_alarm(buzzer_pin, led_pin):
    """
    Activates the alarm on specific pins passed as arguments.
    """
    global _alarm_active
    if _alarm_active:
        return
    _alarm_active = True
    print(f"🚨 Alarm triggered! (Buzzer: {buzzer_pin}, LED: {led_pin})")

    try:
        GPIO.setup(buzzer_pin, GPIO.OUT) # Ensure pin is configured
        GPIO.output(buzzer_pin, GPIO.HIGH)
        # Turn buzzer off after 3 seconds without blocking
        GLib.timeout_add_seconds(3, lambda: GPIO.output(buzzer_pin, GPIO.LOW) or False)
    except Exception as e:
        print(f"⚠️ Buzzer error: {e}")

    # Blink the specified alarm LED
    led_blink(led_pin, 2)
    
    # Notify the main application to switch advertisement mode via callback
    if _on_trigger_callback:
        _on_trigger_callback()

def clear_alarm():
    """
    Deactivates the alarm and calls the clear callback.
    """
    global _alarm_active
    if not _alarm_active:
        # Still call the callback to ensure the advertisement state is correct
        if _on_clear_callback:
            _on_clear_callback()
        return
        
    _alarm_active = False
    print("✅ Alarm cleared.")
    
    # Notify the main application to switch back to normal mode via callback
    if _on_clear_callback:
        _on_clear_callback()

# --- LED Helper Functions ---
def led_blink(pin_number, duration_seconds):
    """Blinks an LED on a given pin for a specific duration."""
    end_time = time.time() + duration_seconds
    try:
        GPIO.setup(pin_number, GPIO.OUT)
        while time.time() < end_time:
            GPIO.output(pin_number, GPIO.HIGH)
            time.sleep(0.2)
            GPIO.output(pin_number, GPIO.LOW)
            time.sleep(0.2)
    except Exception as e:
        print(f"⚠️ LED blink error: {e}")
    finally:
        # Ensure LED is left in the off state
        GPIO.output(pin_number, GPIO.LOW)

def led_continuous_glow(pin_number, duration_seconds):
    """Turns an LED on for a specific duration."""
    try:
        GPIO.setup(pin_number, GPIO.OUT)
        GPIO.output(pin_number, GPIO.HIGH)
        time.sleep(duration_seconds)
    except Exception as e:
        print(f"⚠️ LED glow error: {e}")
    finally:
        # Ensure LED is left in the off state
        GPIO.output(pin_number, GPIO.LOW)