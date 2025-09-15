from gpiozero import Button
from signal import pause
import RPi.GPIO as GPIO
import time
# end_time = time.time() + 2
# while time.time() < end_time:
#     GPIO.setmode(GPIO.BCM)
#     GPIO.setup(17, GPIO.OUT)
#     #GPIO.output(BUZZER_PIN, GPIO.HIGH)
#     GPIO.output(17, GPIO.HIGH)
#     time.sleep(0.2)
#     GPIO.output(17, GPIO.LOW)
#     time.sleep(0.2)
# 
# button = Button(27)
# button.wait_for_press()
# button.when_pressed = lambda: print("Button was Pushed!")
# pause()

# 
# button_pin = 27  # Use your physical pin number
# 
# GPIO.setwarnings(False)
# GPIO.setmode(GPIO.BCM)
# #GPIO.setup(button_pin, GPIO.IN, pull_up_down=GPIO.PUD_DOWN)
# GPIO.setup(button_pin, GPIO.OUT)
# GPIO.output(button_pin, GPIO.HIGH)
# time.sleep(0.2)
# GPIO.output(button_pin, GPIO.LOW)
# time.sleep(0.2)


# def button_callback(channel):
#     status = GPIO.input(channel)
#     print(f"Status: {status} ({'HIGH' if status else 'LOW'}), Push button clicked")
# 
# GPIO.add_event_detect(button_pin, GPIO.BOTH, callback=button_callback, bouncetime=200)
# 
# print("Waiting for button press... Press Ctrl+C to exit.")
# 
# try:
#     while True:
#         time.sleep(1)  # Keep script running without busy wait
# except KeyboardInterrupt:
#     GPIO.cleanup()



#         GPIO.output(pin_number, GPIO.HIGH)
#         time.sleep(0.2)
#         GPIO.output(pin_number, GPIO.LOW)
#         time.sleep(0.2)

# GPIO.setup(button_pin, GPIO.IN, pull_up_down=GPIO.PUD_DOWN)
# print("press the button...")
# if GPIO.input(button_pin) == GPIO.HIGH:
#     print("Button was pushed!")
# time.sleep(0.1)
# 
# try:
#     while True:
#         if GPIO.input(button_pin) == GPIO.HIGH:
#             print("Button was pushed!")
#         time.sleep(0.1)
# except KeyboardInterrupt:
#     GPIO.cleanup()


button = Button(27, bounce_time=0.2)

def on_button_pressed():
    print("Button was pushed")
    
    # Add multiple conditions or actions here:
    status = True
    if status:
        print("Status is True")
        #led_contineous_glow(27,0.2)
    else:
        print("Status is False")
        
def led_contineous_glow(pin_number, timer):
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(pin_number, GPIO.OUT)
    GPIO.output(pin_number, GPIO.HIGH)
    time.sleep(timer)
    GPIO.output(pin_number, GPIO.LOW)
    time.sleep(timer)
    GPIO.cleanup()

button.when_pressed = on_button_pressed

pause()