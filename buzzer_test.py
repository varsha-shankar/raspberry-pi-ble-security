import RPi.GPIO as GPIO
import time
end_time = time.time() + 2
while time.time() < end_time:
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(17, GPIO.OUT)
    #GPIO.output(BUZZER_PIN, GPIO.HIGH)
    GPIO.output(17, GPIO.HIGH)
    time.sleep(0.2)
    GPIO.output(17, GPIO.LOW)
    time.sleep(0.2)
