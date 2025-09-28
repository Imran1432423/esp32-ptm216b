#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2018-2025 Espressif Systems (Shanghai) CO LTD
# SPDX-FileCopyrightText: 2025 Salvatore Mesoraca <s.mesoraca16@gmail.com>
# SPDX-License-Identifier: Apache-2.0


import argparse
import asyncio
import math
import os
import struct
import sys

from getpass import getpass

try:
    import bleak
except ImportError:
    sys.stderr.write("ERROR: bleak module is missing. Please install it.\n")
    sys.exit(1)

import security
import transport

from utils import str_to_bytes


async def version_match(tp, protover, verbose=False):
    response = await tp.send_data('version', 'x')
    if verbose:
        print('proto-ver response : ', response)
    if response == protover:
        return True
    return False


async def establish_session(tp, sec):
    response = None
    while True:
        request = sec.security_session(response)
        if request is None:
            break
        response = await tp.send_data('security', request)
        if (response is None):
            return False
    return True


def chunkbytes(data, chunk_size):
    return (data[0+i:chunk_size+i] for i in range(0, len(data), chunk_size))


async def send_data(tp, sec, data):
    data = sec.encrypt_data(str_to_bytes(data)).decode('latin-1')
    response = await tp.send_data('firmware', data)
    return sec.decrypt_data(str_to_bytes(response))


async def reset(tp, sec):
    data = sec.encrypt_data(b'r').decode('latin-1')
    response = await tp.send_data('reset', data)
    return sec.decrypt_data(str_to_bytes(response)) == b'OK'


async def reset_board(tp, sec):
    data = sec.encrypt_data(b'R').decode('latin-1')
    response = await tp.send_data('reset', data)
    return sec.decrypt_data(str_to_bytes(response)) == b'OK'


async def send_firmware(tp, sec, data, key, key_pass=None, load_sign=None):
    if not load_sign:
        sign = security.sign(data, key, key_pass)
    else:
        with open(load_sign, 'rb') as fd:
            sign = fd.read()
    r = await send_data(tp, sec, struct.pack('<I', len(data)))
    if r != b'OK':
        print('Error:', r.decode('latin-1'))
        return False
    # We should calculate this value at runtime
    # but bleak has some issue determining the MTU
    # so we just hardcode a value that should work
    # when the MTU is set to 517
    chunk_size = 498
    for chunk in chunkbytes(sign, chunk_size):
        r = await send_data(tp, sec, chunk)
        if r != b'OK':
            print('Error:', r.decode('latin-1'))
            return False
    chunks = int(math.ceil(len(data) / chunk_size))
    lchunks = len(str(chunks))
    print((' ' * (lchunks-1)) + f'0/{chunks}', end='', flush=True)
    for i, chunk in enumerate(chunkbytes(data, chunk_size), 1):
        r = await send_data(tp, sec, chunk)
        if r != b'OK':
            print('\nError:', r.decode('latin-1'))
            return False
        print('\b'*9 + f'{str(i).rjust(lchunks)}/{chunks}', end='', flush=True)
    print()
    r = await send_data(tp, sec, 'END')
    if r != b'FOK':
        if r == b'OK':
            print('Error: expected more data')
        else:
            print('Error:', r.decode('latin-1'))
        return False
    return True


def gen_salt_source(password):
    print('#pragma once\n')

    salt, verifier = security.generate_salt_and_verifier('ota-admin', password, len_s=16)

    salt_str = ', '.join([format(b, '#04x') for b in salt])
    salt_c_arr = '\n    '.join(salt_str[i: i + 96] for i in range(0, len(salt_str), 96))
    print(f'static const constexpr char ota_salt[] = {{\n    {salt_c_arr}\n}};\n')  # noqa E702

    verifier_str = ', '.join([format(b, '#04x') for b in verifier])
    verifier_c_arr = '\n    '.join(verifier_str[i: i + 96] for i in range(0, len(verifier_str), 96))
    print(f'static const constexpr char ota_verifier[] = {{\n    {verifier_c_arr}\n}};\n')  # noqa E702


def get_key_password_if_needed(args):
    if args.key_password is None:
        if sys.stdin.isatty() and security.key_requires_password(args.key):
            args.key_password = getpass('Key Password: ')


def get_password_if_needed(args):
    if not args.password:
        if sys.stdin.isatty():
            args.password = getpass('Password: ')
        else:
            raise RuntimeError('Password cannot be empty!')


async def main():
    project_dir = os.path.realpath(os.path.dirname(os.path.abspath(__file__)) + '/../../')
    parser = argparse.ArgumentParser(description='OTA updates tool')
    parser.add_argument('-v','--verbose', help='Increase output verbosity', action='store_true')
    subparsers = parser.add_subparsers(dest='cmd', required=True)
    gk = subparsers.add_parser('generate-keys', help='Generate an RSA keypair for OTA updates signing')
    gk.add_argument('--key-password', dest='key_password', type=str, default=None,
                    help='Private key encryption password')
    gk.add_argument('-s', '--key-size', dest='ksize', type=int, default=2048,
                    help='The size in bits of the generated RSA key. Default is 2048.')
    si = subparsers.add_parser('sign', help='Create detached signature for a file')
    si.add_argument('--key-password', dest='key_password', type=str, default=None,
                    help='Private key encryption password')
    si.add_argument('--key', dest='key', type=str,
                    default=os.path.join(project_dir, 'keys/priv.der'),
                    help='Key used to sign the firmware')
    si.add_argument('sign_file', type=str, help='the file to sign')
    v = subparsers.add_parser('generate-verifier', help='Internal use only')
    v.add_argument('-p', '--password', dest='password', type=str, default='',
                   help='Password')
    u = subparsers.add_parser('update', help='Perform an OTA update')
    u.add_argument('-p', '--password', dest='password', type=str, default='',
                   help='Password')
    u.add_argument('--load-sign', dest='load_sign', type=str,
                   help='Load signature from file')
    u.add_argument('-f', '--firmware', dest='fw_file', type=str,
                   default=os.path.join(project_dir, 'build/ptm216b.bin'),
                   help='The firmware file')
    u.add_argument('--key', dest='key', type=str,
                   default=os.path.join(project_dir, 'keys/priv.der'),
                   help='Key used to sign the firmware')
    u.add_argument('--key-password', dest='key_password', type=str, default=None,
                    help='Private key encryption password')
    r = subparsers.add_parser('reset-board', help='Reset board and exits OTA mode')
    r.add_argument('-p', '--password', dest='password', type=str, default='',
                   help='Password')
    args = parser.parse_args()

    if args.cmd == 'generate-keys':
        priv, pub = security.generate_key(args.key_password, args.ksize)
        with open('./priv.der', 'wb') as fd:
            fd.write(priv)
        with open('./pub.der', 'wb') as fd:
            fd.write(pub)
    elif args.cmd == 'sign':
        get_key_password_if_needed(args)
        if os.path.exists(args.sign_file + '.sign'):
            raise RuntimeError('Signature already exists')
        with open(args.sign_file, 'rb') as fd:
            sign = security.sign(fd.read(), args.key, args.key_password)
        with open(args.sign_file + '.sign', 'wb') as fd:
            fd.write(sign)
    elif args.cmd == 'generate-verifier':
        get_password_if_needed(args)
        gen_salt_source(args.password)
    else:
        get_password_if_needed(args)
        if args.cmd != 'reset-board' and not args.load_sign:
            get_key_password_if_needed(args)
        for i in range(1, 4):
            obj_transport = transport.Transport_BLE(nu_lookup={'security': 'ff51',
                                                               'firmware': 'ff52',
                                                               'version': 'ff53',
                                                               'reset': 'ff54'},
                                                    service_uuid='3ed83ac2-1caa-4299-bb75-910ea9a11f71')
            await obj_transport.connect(devname='OTA')

            firmware_complete = False
            try:
                obj_security = security.Security2(1, 'ota-admin', args.password, args.verbose)

                if not await version_match(obj_transport, 'ota-v1', args.verbose):
                    raise RuntimeError('Error in protocol version matching')
                print("Correct version")

                if not await establish_session(obj_transport, obj_security):
                    raise RuntimeError('Error in establishing session')
                print("Session establish session")

                if args.cmd == 'reset-board':
                    if await reset_board(obj_transport, obj_security):
                        print('Board reset')
                    else:
                        print('ERROR')
                    return

                if not await reset(obj_transport, obj_security):
                    raise RuntimeError('Error during reset')

                print('Sending firmware...')
                if await send_firmware(obj_transport,
                                       obj_security,
                                       open(args.fw_file, 'rb').read(),
                                       args.key,
                                       args.key_password,
                                       args.load_sign):
                    print('Firmware sent')
                    firmware_complete = True
                    break
                else:
                    print('FAILED')
            except bleak.exc.BleakDBusError as ex:
                if i < 3:
                    print(f'Error: {ex}: trying again {i}/3')
                else:
                    print(f'Error: {ex}: too many attempts, abort')
                    await reset_board(obj_transport, obj_security)
            finally:
                await obj_transport.disconnect()

        if firmware_complete:
            print('waiting 2 minutes for ack... (trigger OTA again on the device)')
            def adv_filter(_, adv_data):
                if adv_data and adv_data.manufacturer_data:
                    md = adv_data.manufacturer_data
                    if len(md) == 1 and 1242 in md:
                        md = md[1242]
                        if md == b'OTA OK' or md == b'OTA FAIL':
                            return True
                return False
            r = await bleak.BleakScanner.find_device_by_filter(adv_filter, timeout=120)
            if r:
                if r.details['props']['ManufacturerData'][1242] == b'OTA OK':
                    print('Update completed!')
                else:
                    print('Update FAILED!')
            else:
                print('Update status unknown, no ACK received!')


if __name__ == '__main__':
    asyncio.run(main())
