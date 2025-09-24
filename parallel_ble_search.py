#!/usr/bin/env python3
# check_device_loop.py - Continuously scans for a specific BLE device and connects when available.

import asyncio
import sys
import subprocess
from bleak import BleakClient, BleakScanner, BleakError


async def scan_for_device(address, scan_time=5.0):
    """Scan for the target BLE device by MAC address."""
    print(f"🔍 Scanning for devices ({scan_time:.0f}s)...")
    devices = await BleakScanner.discover(timeout=scan_time)
    for d in devices:
        print(f"  Found: {d.address} - {d.name}")
        if d.address.upper() == address.upper():
            print(f"✅ Found target device {address}!")
            return True
    print(f"❌ Device {address} not found during scan.")
    return False


async def connect_to_device(address):
    """Try connecting to the device."""
    print(f"🔗 Attempting to connect to {address}...")
    subprocess.run(["bluetoothctl", "discoverable", "on"], check=False)
    subprocess.run(["bluetoothctl", "pairable", "on"], check=False)

    try:
        async with BleakClient(address, timeout=5.0) as client:
            print(f"✅ Success! Connected to device {address}.")
            # Example: Keep connection for a bit before exiting
            await asyncio.sleep(5)
            return True
    except BleakError as e:
        print(f"❌ Failed to connect: {e}")
    except Exception as e:
        print(f"⚠️ An unexpected error occurred: {e}")
    return False


async def main(address, scan_interval=10.0):
    """Continuously scan until the device is found and connected."""
    while True:
        found = await scan_for_device(address)
        if found:
            connected = await connect_to_device(address)
            if connected:
                print("🎉 Finished: Successfully connected, stopping loop.")
                break
        print(f"⏳ Waiting {scan_interval:.0f}s before next scan...")
        await asyncio.sleep(scan_interval)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <BLE_DEVICE_ADDRESS>")
        sys.exit(1)

    device_address = sys.argv[1]
    asyncio.run(main(device_address))
