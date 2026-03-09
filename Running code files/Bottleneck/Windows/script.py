# ctrl_r_looper.py
import time
import pyautogui

INTERVAL_SECONDS = 10.0   # how long to wait between presses
START_DELAY = 5          # time to switch to the target window

pyautogui.FAILSAFE = True  # move mouse to a corner to abort

print(f"Starting in {START_DELAY} seconds… switch to the window to refresh.")
time.sleep(START_DELAY)

try:
    while True:
        pyautogui.hotkey('ctrl', 'r')
        time.sleep(INTERVAL_SECONDS)
except KeyboardInterrupt:
    print("Stopped by Ctrl+C.")