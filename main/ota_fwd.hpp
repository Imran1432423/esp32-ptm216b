/*
 * SPDX-FileCopyrightText: 2025 Salvatore Mesoraca <s.mesoraca16@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

namespace ota {

[[maybe_unused]] bool pending_verify() noexcept;
[[maybe_unused]] void verify_fw() noexcept;
[[maybe_unused]] void revert_fw() noexcept;
[[maybe_unused]] void ota_start() noexcept;

};
