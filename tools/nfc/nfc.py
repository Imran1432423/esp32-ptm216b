#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2025 Salvatore Mesoraca <s.mesoraca16@gmail.com>
# SPDX-License-Identifier: Apache-2.0


import argparse
import binascii
import os
import sys
import time


try:
    import smartcard
except ImportError:
    sys.stderr.write("ERROR: smartcard module is missing. Please install pyscard.\n")
    sys.exit(1)


def chunks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


class NFC:
    def __init__(self):
        readers = smartcard.System.readers()
        if not readers:
            raise RuntimeError("no reader found")
        self.reader = None
        for reader in readers:
            if 'ACR122U' in reader.name:
                self.reader = reader
        if self.reader is None:
            raise RuntimeError("ACR122U reader not found")
        self.conn = None
        self.logical_num = None

    def __enter__(self):
        while True:
            try:
                self.conn = self.reader.createConnection()
                self.conn.connect()
                self.logical_num = self.get_logical_number()
                return self
            except smartcard.Exceptions.NoCardException:
                time.sleep(0.1)

    def __exit__(self, a, b, c):
        if self.conn:
            self.conn.disconnect()
            self.conn = None

    def get_atr(self):
        return self.conn.getATR()

    def send_command(self, command):
        # Information about the magic byte sequences used here
        # can be obtained in section "6.1. Direct Transmit" of
        # ACR122U API doc [1], section "8.4.9 InCommunicateThru"
        # of PN533 User Manual [2] and in NT3H2111 datasheet [3].
        #
        # In short:
        #   Sending commands:
        #    [0xff, 0x00, 0x00, 0x00, len(DATA), DATA]
        #     ^ this is what you need to tell ACR122U to send DATA as is
        #       to the PN533 IC that it uses internally for NFC communication
        #    DATA = [0xd4, 0x42, COMMAND]
        #     ^ this is needed to tell the PN533 to transmit COMMAND as it
        #       is via NFC and that such command expects a response.
        #       Not all commands that we use in this script actually produce a
        #       response, but it doesn't really matter, it works anyway, we
        #       can simply ignore the error (see send_command_ack_only below).
        #    COMMAND
        #     ^ PTM216B internally uses NXP's "NTAG I2C plus 1k" [3] which is
        #       certified NFC Forum Type 2 Tag and ISO/IEC 14443 Part 2 and 3
        #       compliant.
        #   Response:
        #    [pndata, acret, acpar]
        #     ^ pndata = the output from PN533
        #       acret = the return code from ACR122U (0x90 is OK)
        #       acpar = should always be 0 for direct trasmit
        #    pndata
        #     ^ the first 2 bytes must be [0xd5, 0x43] for InCommunicateThru
        #       followed by 1 status byte where bits 0-5 indicate various errors.
        #       Anything that follows is the NFC command response.
        #
        # [1] https://www.acs.com.hk/download-manual/419/API-ACR122U-2.04.pdf
        # [2] https://www.nxp.com/docs/en/user-guide/157830_PN533_um080103.pdf
        # [3] https://www.nxp.com/docs/en/data-sheet/NT3H2111_2211.pdf

        cmd = [0xff, 0x00, 0x00, 0x00, len(command) + 2, 0xd4, 0x42] + command
        response = self.conn.transmit(cmd)
        pndata, acret, acpar = response
        if acret != 0x90 or acpar != 0:
            raise RuntimeError("ACR122U error")
        if pndata[0] != 0xd5 or pndata[1] != 0x43:
            raise RuntimeError("PN553 error 1")
        if (pndata[2] & 0x1f) != 0:
            raise RuntimeError("PN553 error 2: " + hex(pndata[2] & 0x1f), response)
        return pndata[3:]

    def get_logical_number(self):
        cmd = [0xff, 0x00, 0x00, 0x00, 3, 0xd4, 0x04]
        response = self.conn.transmit(cmd)
        pndata, acret, acpar = response
        if acret != 0x90 or acpar != 0:
            raise RuntimeError("ACR122U error")
        if pndata[0] == 0xd5 and pndata[1] == 5 and len(pndata) > 5:
            return pndata[5]
        return None

    def send_command_ack_only(self, command):
        cmd = [0xff, 0x00, 0x00, 0x00, len(command) + 2, 0xd4, 0x42] + command
        response = self.conn.transmit(cmd)
        pndata, acret, acpar = response
        if acret != 0x90 or acpar != 0:
            raise RuntimeError("ACR122U error")
        if pndata[0] != 0xd5 or pndata[1] != 0x43:
            raise RuntimeError("PN553 error 1")
        errcode = pndata[2] & 0x1f
        if errcode != 0 and errcode != 2:
            raise RuntimeError("PN553 error 2: " + hex(pndata[2] & 0x1f), response)
        return pndata[3:]

    def get_version(self):
        return self.send_command([0x60])

    def auth(self, pwd):
        r = nfc.send_command([0x1b] + pwd)
        if r != [0, 0]:
            raise RuntimeError("Auth failed:", r)
        return True

    def read_pages(self, start):
        return chunks(nfc.send_command([0x30, start]), 4)

    def full_dump(self):
        for p in range(0, 237, 4):
            for i, page in enumerate(nfc.read_pages(p)):
                print(f'{hex(p+i):03}:', ' '.join(hex(x)[2:].zfill(2) for x in page))

    def write_page(self, page, data):
        assert len(data) == 4
        nfc.send_command_ack_only([0xa2, page] + data)

    def get_info(self):
        r = {'encryption': False,
             'rpa': False,
             'key_hidden': False,
             'ctr':0,
             'key':b'',
             'addr':b''}
        config = next(self.read_pages(0xe))
        if (config[2] & 0x20) != 0:
            r['encryption'] = True
        if (config[0] & 0x10) != 0:
            r['rpa'] = True
        if (config[0] & 0x08) != 0:
            r['key_hidden'] = True
        ctr = next(self.read_pages(0xd))
        r['ctr'] = int.from_bytes(ctr, 'big')
        r['addr'] = b'\xE2\x15'
        addr = next(self.read_pages(0xc))
        if r['encryption']:
            addr[0] |= 0x80
        r['addr'] += bytes(addr)
        r['addr'] = binascii.hexlify(r['addr']).decode().upper()
        r['key'] = ''.join(binascii.hexlify(bytes(x)).decode().upper() for x in self.read_pages(0x14))
        return r

    def set_flags(self, encryption=None, rpa=None, custom_key=None, hide_key=None):
        current = next(self.read_pages(0xe))
        new_value = current[:]
        if encryption is not None:
            if encryption:
                new_value[2] |= 0x20
            else:
                new_value[2] &= 0xdf
        if rpa is not None:
            if rpa:
                new_value[0] |= 0x10
            else:
                new_value[0] &= 0xef
        if custom_key is not None:
            if custom_key:
                new_value[0] |= 0x04
            else:
                new_value[0] &= 0xfb
        if hide_key is not None:
            if hide_key:
                new_value[0] |= 0x08
            else:
                new_value[0] &= 0xf7
        if new_value != current:
            self.write_page(0xe, new_value)

    def new_key(self):
        key_o = os.urandom(16)
        key = chunks(key_o, 4)
        for page, data in enumerate(key, start=0x14):
            self.write_page(page, list(data))
        self.set_flags(custom_key=True)
        print("New key: " + binascii.hexlify(key_o).decode().upper())

    def set_password(self, password):
        assert len(password) == 4
        assert all(isinstance(c, int) for c in password)
        print(f"Password being set: {password}")
        self.write_page(0xe5, password)


def get_args():
    parser = argparse.ArgumentParser(description='NFC config tool for ptm216b. Requires ACR122U reader.')
    parser.add_argument('-p', '--password', dest='password', type=str, default=None,
                        help='raw password in hexadecimal format. Default: 0000E215. Not compatible with '
                             'PIN codes set via Enocean\'s app')
    subparsers = parser.add_subparsers(dest='cmd', required=True)
    subparsers.add_parser('dump', help='read and print current values')
    subparsers.add_parser('cycle-key', help='change they key to a new random one')
    subparsers.add_parser('raw-dump', help='dump the entire memory')
    subparsers.add_parser('set-high-security', help='enable encryption, RPA, and makes the key unreadable.')
    subparsers.add_parser('set-low-security', help='disable encryption, RPA, and makes the key readable.')
    sp = subparsers.add_parser('set-password', help='Change the NFC password. Be aware that '
                                                    'this is not compatible with Enocean\'s own '
                                                    'app. They use a proprietary encoding '
                                                    'algorithm to generate the password from '
                                                    'a 4 digit PIN code, while this script just use '
                                                    'the actual raw value. The only password that '
                                                    'works with both this script and Enocean\'s app '
                                                    'is the default one.' )
    sp.add_argument('new_password', type=str, help='the new password')
    return parser.parse_args()

if __name__ == '__main__':
    ATR = [0x3b, 0x8f, 0x80, 0x1, 0x80, 0x4f, 0xc, 0xa0, 0x0,
           0x0, 0x3, 0x6, 0x3, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x68]
    VERSION = [0x0, 0x4, 0x4, 0x5, 0x2, 0x2, 0x13, 0x3]
    DEFAULT_PWD = [0, 0, 0xe2, 0x15]

    args = get_args()
    if args.password is None:
        args.password = DEFAULT_PWD
    else:
        args.password = list(binascii.unhexlify(args.password))
        if len(args.password) != 4:
            sys.stderr.write("ERROR: password should be exactly 4 bytes\n")
            sys.exit(1)
    with NFC() as nfc:
        assert ATR == nfc.get_atr()
        assert VERSION == nfc.get_version()
        print ('Device detected')
        assert nfc.auth(args.password)
        if args.cmd == 'dump':
            info = nfc.get_info()
            print(f"""Address:\t{info['addr']}
Key:\t\t{info['key']}
Key hidden:\t{info['key_hidden']}
Counter:\t{info['ctr']}
Encryption:\t{info['encryption']}
RPA:\t\t{info['rpa']}""")
        elif args.cmd == 'raw-dump':
            nfc.full_dump()
        elif args.cmd == 'cycle-key':
            nfc.new_key()
        elif args.cmd == 'set-high-security':
            nfc.set_flags(encryption=True, rpa=True, hide_key=True)
            print('Security config updated')
        elif args.cmd == 'set-low-security':
            nfc.set_flags(encryption=False, rpa=False, hide_key=False)
            print('Security config updated')
        elif args.cmd == 'set-password':
            new_password = list(binascii.unhexlify(args.new_password))
            if len(new_password) != 4:
                sys.stderr.write("ERROR: password should be exactly 4 bytes\n")
                sys.exit(1)
            nfc.set_password(new_password)
            print(f"New password set: {args.new_password}")
