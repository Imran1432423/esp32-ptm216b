#!/usr/bin/env python3

import asyncio
import binascii
import json
import struct
import sys

from bleak import BleakScanner

try:
    from Cryptodome.Cipher import AES
except ImportError:
    try:
        from Crypto.Cipher import AES
    except ImportError:
        sys.stderr.write("ERROR: crypto module is missing. Please install PyCryptodome.\n")
        sys.exit(1)


def load_devices(fpath):
    d = {'rpa':{}, 'static':{}}
    with open(fpath) as fd:
        for dev in json.load(fd):
            if 'rpa' in dev and dev['rpa']:
                d['rpa'][binascii.unhexlify(dev['key'])] = {'encryption': dev.get('encryption', False),
                                                            'address': binascii.unhexlify(dev['address'])[::-1],
                                                            'printable_address': dev['address'],
                                                            'key': binascii.unhexlify(dev['key']),
                                                            'ctr': 0}
            else:
                d['static'][dev['address']] = {'encryption': dev.get('encryption', False),
                                               'key': binascii.unhexlify(dev['key']),
                                               'address': binascii.unhexlify(dev['address'])[::-1],
                                               'printable_address': dev['address'],
                                               'ctr': 0}
    return d


def find_matching_dev(devices, address):
    address = address.replace(':','')
    a = binascii.unhexlify(address)
    if address in devices['static']:
        return devices['static'][address]
    elif (a[0] & 0xc0) == 0x40:
        p = b'\x00' * 13 + a[:3]
        h = a[3:]
        for k, dev in devices['rpa'].items():
            cipher = AES.new(k, AES.MODE_ECB)
            if h == cipher.encrypt(p)[-3:]:
                return dev


async def main():
    devices = load_devices(sys.argv[1])
    def callback(device, advertising_data):
        global LASTCTR
        if advertising_data and advertising_data.manufacturer_data:
            md = advertising_data.manufacturer_data
            if len(md) == 1 and 986 in md:
                md = md[986]
                dev = find_matching_dev(devices, device.address)
                if dev and len(md) == 9:
                    nonce = dev['address'] + md[:4] + b'\x00\x00\x00'
                    if dev['encryption']:
                        data = b'\x0c\xff\xda\x03' + md[:4]
                    else:
                        data = b'\x0c\xff\xda\x03' + md[:5]
                    cipher = AES.new(dev['key'], AES.MODE_CCM, nonce=nonce, mac_len=4, assoc_len=len(data))
                    cipher.update(data)
                    if dev['encryption']:
                        plaintext = cipher.decrypt_and_verify(md[4].to_bytes(), md[-4:])
                        status = plaintext[0]&0x1f
                    else:
                        status = md[4] & 0x1f
                        tag = cipher.digest()
                        if tag != md[-4:]:
                            sys.stderr.write(f'wrong tag {md} {dev}\n')
                            return
                    ctr = struct.unpack("<L", md[:4])[0]
                    if ctr <= dev['ctr']:
                        if ctr < dev['ctr']:
                            sys.stderr.write(f'wrong ctr {md} {dev}\n')
                        return
                    dev['ctr'] = ctr
                    buttons = []
                    if status & 0x2:
                        buttons.append('A0')
                    if status & 0x4:
                        buttons.append('A1')
                    if status & 0x8:
                        buttons.append('B0')
                    if status & 0x10:
                        buttons.append('B1')
                    pressed = bool(status &1)
                    print(dev['printable_address'],
                          f'{"pressed" if pressed else "released"}',
                          '+'.join(buttons))
    async with BleakScanner(callback) as _:
        await asyncio.Future()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.stderr.write(f'usage: {sys.argv[0]} <devices.json>\n')
        sys.exit(1)
    asyncio.run(main())
