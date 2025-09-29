from gpiozero import Button
from gpiozero.pins.pigpio import PiGPIOFactory
from signal import pause
import time

# --- IMPORTANT ---
# Make sure this pin number matches the GPIO pin your button is connected to.
BUTTON_PIN = 24 
# -----------------

print(f"--- Minimal Button Test on GPIO {BUTTON_PIN} ---")
print("One leg of the button must be on this GPIO pin.")
print("The other leg must be on a GROUND (GND) pin.")
print("\nPress the button. You should see a message.")
print("Press Ctrl+C to exit.")

try:
    # Force the pigpio factory to be certain
    factory = PiGPIOFactory()
    
    button = Button(BUTTON_PIN, pull_up=True, pin_factory=factory)

    def button_pressed():
        print(f"✅ ---> BUTTON PRESSED! <--- ({time.ctime()})")

    def button_released():
        print(f"⚪ ---> BUTTON RELEASED! <--- ({time.ctime()})")

    # Assign functions to both press and release events for clear feedback
    button.when_pressed = button_pressed
    button.when_released = button_released

    pause() # Wait here for events

except Exception as e:
    print(f"\n❌ An error occurred: {e}")