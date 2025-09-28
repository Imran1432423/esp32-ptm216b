/*
 * SPDX-FileCopyrightText: 2025 Salvatore Mesoraca <s.mesoraca16@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <cstdint>
#include <vector>

namespace ptm216b {

static void ptm216b_stop() noexcept;

static void send_adv(const std::vector<uint8_t> &) noexcept;

};
