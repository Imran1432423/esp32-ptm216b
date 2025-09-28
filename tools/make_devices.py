#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2025 Salvatore Mesoraca <s.mesoraca16@gmail.com>
# SPDX-License-Identifier: Apache-2.0


import binascii
import json
import os


TEMPLATE = """#pragma once

#include <array>
#include <unordered_map>
#include <utility>
#include <vector>

#include "events.hpp"
#include "ptm216b_types.hpp"

namespace ptm216b {{

using events::trigger_helpers::bitwise_and;
using events::trigger_helpers::exact_match;
using events::trigger_helpers::exact_match_timer;
using events::actions::light_toggle;
using events::actions::light_off;
using events::actions::light_on;
using events::actions::ota;
using events::actions::action_f;

static const constexpr std::array devices = {{
{devices}
}};

using event_handler_t = std::function<bool(const std::vector<uint8_t>&)>;

static const std::unordered_map<device, std::vector<std::pair<event_handler_t,action_f>>> events_handlers_exact{{
{events_handlers_exact}
}};

static const std::unordered_map<device, std::vector<std::pair<event_handler_t,action_f>>> events_handlers_incremental = {{{{
{events_handlers_incremental}
}}}};

}};"""

def get_number_from_keys(keys):
    n = 0
    values = {'A0': 0x2,
              'A1': 0x4,
              'B0': 0x8,
              'B1': 0x10}
    for k in keys:
        n |= values[k]
    return n

def make_devices(fobj):
    data =json.load(fobj)
    devices = ""
    events_handlers_exact = ""
    events_handlers_incremental = ""
    for d in data:
        current_dev = "\tdevice{ "
        if 'address' in d:
            address = ', '.join([ hex(x) for x in binascii.unhexlify(d['address']) ])
            current_dev += f"{{ {{ {address} }} }}, "
        else:
            current_dev += "{{ }}, "
        key = ', '.join([ hex(x) for x in binascii.unhexlify(d['key']) ])
        current_dev += f"{{ {{ {key} }} }}, "
        if 'encryption' in d:
            current_dev += f"{str(d['encryption']).lower()}, "
        else:
            current_dev += "false, "
        if 'rpa' in d:
            current_dev += f"{str(d['rpa']).lower()}, "
        else:
            current_dev += "false, "
        current_dev += "},\n"
        devices += current_dev
        if 'actions' in d:
            events_handlers_exact += f"\t{{ {current_dev.strip()}\n\t\t{{"
            events_handlers_incremental += f"\t{{ {current_dev.strip()}\n\t\t{{"
            for action in d['actions']:
                if 'trigger' in action and 'action' in action:
                    if 'name' in action['trigger']:
                        fs = f"{{ [](const std::vector<uint8_t>& raw){{%s}}, {action['action']} }}, "
                        tname = action['trigger']['name'].lower()
                        if tname == 'raw':
                            value = ', '.join([ hex(x) for x in binascii.unhexlify(action['trigger']['value']) ])
                            events_handlers_exact += fs % f"return exact_match(raw, {{{value}}});"
                        elif 'keys' in action['trigger']:
                            n = get_number_from_keys(action['trigger']['keys'])
                            if tname == 'long_press' and action['trigger']['duration']:
                                events_handlers_exact += fs % f"return exact_match_timer(raw, {{{hex(n|0x1)}}}, {{{hex(n)}}}, {action['trigger']['duration']});"
                            else:
                                if tname == 'press':
                                    n |= 0x1
                                if len(action['trigger']['keys']) == 1:
                                    events_handlers_incremental += fs % f"return bitwise_and(raw, {{{hex(n)}}});"
                                else:
                                    events_handlers_exact += fs % f"return exact_match(raw, {{{hex(n)}}});"
            events_handlers_exact += "}},\n"
            events_handlers_incremental += "}},\n"

    return TEMPLATE.format(devices=devices,
                           events_handlers_exact=events_handlers_exact,
                           events_handlers_incremental=events_handlers_incremental)

def use_colors():
    if os.environ.get('NO_COLOR', '0') != '0':
        return False
    if os.environ.get('CLICOLOR', '1') == '0':
        if os.environ.get('CLICOLOR_FORCE', '0') == '0':
            return False
    return True

if __name__ == '__main__':
    import sys

    try:
        with open(sys.argv[1]) as fobj:
            print(make_devices(fobj))
    except (FileNotFoundError, IsADirectoryError):
        prefix = ''
        suffix = ''
        if use_colors():
            prefix = '\033[40;31m'
            suffix = '\033[0m'
        sys.stderr.write(f"{prefix}ERROR: File '{os.path.basename(sys.argv[1])}' does not exist{suffix}\n")
        sys.exit(1)
