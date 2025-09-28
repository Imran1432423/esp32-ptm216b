/*
 * SPDX-FileCopyrightText: 2025 Salvatore Mesoraca <s.mesoraca16@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iterator>

namespace ptm216b {

static const constexpr size_t address_size = 6;
using address_t = std::array<uint8_t, address_size>;
static const constexpr size_t key_size = 16;
using key_t = std::array<uint8_t, key_size>;

static const constexpr address_t empty_address{};

struct device
{
    address_t address;
    key_t key;
    bool encryption{ false };
    bool rpa;
    bool operator==(const device &d) const
    {
        return address == d.address && rpa == d.rpa && key == d.key &&
               encryption == d.encryption;
    }
};

};

template<>
struct std::hash<ptm216b::address_t>
{
    std::size_t operator()(const ptm216b::address_t &a) const noexcept
    {
        uint32_t t;
        memcpy(&t, &a[2], sizeof(t));
        return std::hash<uint32_t>{}(t);
    }
};

template<>
struct std::hash<ptm216b::key_t>
{
    std::size_t operator()(const ptm216b::key_t &k) const noexcept
    {
        uint32_t t;
        memcpy(&t, k.data(), sizeof(t));
        return std::hash<uint32_t>{}(t);
    }
};

template<>
struct std::hash<ptm216b::device>
{
    std::size_t operator()(const ptm216b::device &d) const noexcept
    {
        return std::hash<ptm216b::address_t>{}(d.address);
    }
};
