/*
 * SPDX-FileCopyrightText: 2025 Salvatore Mesoraca <s.mesoraca16@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <limits>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string.h>
#include <unordered_map>
#include <vector>

#include <host/ble_hs.h>
#include <host/ble_hs_adv.h>
#include <host/util/util.h>
#include <nimble/nimble_port.h>
#include <nimble/nimble_port_freertos.h>

#include <esp_log.h>

#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/task.h>

#include <mbedtls/aes.h>
#include <mbedtls/base64.h>
#include <mbedtls/ccm.h>

#include "ptm216b_devices.hpp"
#include "ptm216b_types.hpp"

namespace ptm216b {

static const constexpr char *log_tag = "ptm216b";

template<std::size_t N>
static std::vector<uint8_t>
encode_base64(const std::array<uint8_t, N> &data)
{
    std::vector<uint8_t> encoded;
    size_t size;
    mbedtls_base64_encode(nullptr, 0, &size, data.data(), data.size());
    encoded.resize(size + 1);
    mbedtls_base64_encode(encoded.data(), encoded.size() - 1, &size, data.data(), data.size());
    encoded.resize(size + 1);
    encoded.shrink_to_fit();
    return encoded;
}

class ptm216b_error : public std::runtime_error
{
  public:
    ptm216b_error(const char *s)
            : std::runtime_error(s)
    {
    }
};

struct message
{
    static const constexpr size_t min_payload_size = 9;
    static const constexpr size_t max_payload_size = 13;
    address_t address;
    std::span<const uint8_t> get_payload() const
    {
        return { payload_buf.begin(), p_size };
    }
    void set_address(const uint8_t *addr) noexcept
    {
        std::reverse_copy(addr, addr + address.size(), address.begin());
    }
    void set_payload(const uint8_t *data, size_t s)
    {
        set_payload_size(s);
        memcpy(payload_buf.data(), data, s);
    }
    bool operator==(const message &b) const
    {
        return address == b.address && p_size == b.p_size && payload_buf == b.payload_buf;
    }

  private:
    std::array<uint8_t, max_payload_size> payload_buf;
    size_t p_size;
    void set_payload_size(size_t s)
    {
        if (s < min_payload_size)
            throw ptm216b_error("payload too small");
        if (s > max_payload_size)
            throw ptm216b_error("payload too big");
        p_size = s;
    }
};

class ptm216b
{
  public:
    using callback_t = std::function<void(const device &, const std::vector<uint8_t> &)>;

    static ptm216b &get_instance()
    {
        static ptm216b instance{};
        return instance;
    }

    ~ptm216b() noexcept
    {
        try {
            stop();
        } catch (const std::exception &e) {
            ESP_LOGE(log_tag, "destructor: %s", e.what());
        } catch (...) {
            ESP_LOGE(log_tag, "destructor");
        }
        cleanup();
    }

    ptm216b(const ptm216b &other) = delete;
    ptm216b &operator=(const ptm216b &other) = delete;
    ptm216b(ptm216b &&other) = delete;
    ptm216b &operator=(ptm216b &&other) = delete;

    void start()
    {
        if (started)
            return;
        ESP_LOGI(log_tag, "Starting BLE...");
        ESP_ERROR_CHECK(nimble_port_init());
        ble_hs_cfg.sync_cb = ble_sync_cb;
        nimble_port_freertos_init(ble_host_task);
        ESP_LOGI(log_tag, "BLE started");
        last_good_message = esp_timer_get_time();
        started = true;
    }

    void stop()
    {
        if (!started)
            return;
        ESP_LOGI(log_tag, "Stopping BLE...");
        auto ret = nimble_port_stop();
        if (ret != 0)
            throw ptm216b_error("nimble stop port error");
        ESP_ERROR_CHECK(nimble_port_deinit());
        started = false;
        nvs_dumper_helper();
        ESP_LOGI(log_tag, "BLE stopped");
    }

    static void send_adv(const std::vector<uint8_t> &mfg_data) noexcept
    {
        ble_gap_adv_params params{};
        ble_hs_adv_fields fields{};

        fields.mfg_data = mfg_data.data();
        fields.mfg_data_len = mfg_data.size();
        params.conn_mode = BLE_GAP_CONN_MODE_UND;
        params.disc_mode = BLE_GAP_DISC_MODE_GEN;

        auto ret = ble_gap_adv_set_fields(&fields);
        if (ret != 0) {
            ESP_LOGE(log_tag, "send_adv: set fields: %d", ret);
            return;
        }

        ret = ble_gap_adv_start(
                BLE_OWN_ADDR_RPA_RANDOM_DEFAULT, nullptr, 100, &params, gap_adv_cb, nullptr);
        if (ret != 0)
            ESP_LOGE(log_tag, "send_adv: adv: %d", ret);
    }

    void set_cb(callback_t cb)
    {
        const std::lock_guard lock(cb_lock);
        callback = std::move(cb);
    }

  private:
    static const constexpr char nvs_namespace[] = { "ptm216b_ctrs" };
    std::vector<TaskHandle_t> tasks;
    QueueHandle_t queue{ nullptr };
    std::unordered_map<address_t, device> device_map;
    std::unordered_map<address_t, std::atomic_uint32_t> device_ctrs;
    std::unordered_map<address_t, mbedtls_aes_context> device_irk_ctxs;
    std::unordered_map<address_t, int64_t> ban_list;
    callback_t callback{};
    std::mutex cb_lock;
    bool started{ false };
    int64_t last_good_message{ 0 };

    void cleanup() noexcept
    {
        for (auto &task : tasks)
            vTaskDelete(task);
        vQueueDelete(queue);
    }

    ptm216b()
    {
        for (const auto &d : devices) {
            device_map.emplace(d.address, d);
            device_ctrs.emplace(std::piecewise_construct,
                                std::forward_as_tuple(d.address),
                                std::forward_as_tuple(0));
            if (d.rpa) {
                mbedtls_aes_context ctx;
                mbedtls_aes_init(&ctx);
                mbedtls_aes_setkey_enc(&ctx, d.key.data(), d.key.size() * 8);
                device_irk_ctxs.emplace(std::piecewise_construct,
                                        std::forward_as_tuple(d.address),
                                        std::forward_as_tuple(ctx));
            }
        }
        nvs_handle_t h;
        auto ret = nvs_open(nvs_namespace, NVS_READONLY, &h);
        if (ret != ESP_ERR_NVS_NOT_FOUND) {
            ESP_ERROR_CHECK(ret);
            for (auto &[key, dev_ctr] : device_ctrs) {
                uint32_t val = 0;
                const auto encodedk = encode_base64(key);
                ret = nvs_get_u32(h, reinterpret_cast<const char *>(encodedk.data()), &val);
                if (ret != ESP_ERR_NVS_NOT_FOUND) {
                    ESP_ERROR_CHECK(ret);
                    dev_ctr.store(val, std::memory_order_relaxed);
                }
            }
            nvs_close(h);
        }
        callback = [](const device &dev, const std::vector<uint8_t> &data) {
            const auto ex = events_handlers_exact.find(dev);
            if (ex != events_handlers_exact.end()) {
                for (const auto &[handler, action] : ex->second) {
                    if (handler(data)) {
                        action();
                        return;
                    }
                }
            }
            const auto in = events_handlers_incremental.find(dev);
            if (in != events_handlers_incremental.end())
                for (const auto &[handler, action] : in->second)
                    if (handler(data))
                        action();
        };
        queue = xQueueCreate(20, sizeof(message));
        if (queue == nullptr)
            throw ptm216b_error("queue not created");
        TaskHandle_t taskp;
        static const constexpr configSTACK_DEPTH_TYPE q_consumer_stack_size = 8192;
        static const constexpr UBaseType_t q_consumer_prio = tskIDLE_PRIORITY + 5;
        auto taskr = xTaskCreate(q_consumer,
                                 "q_consumer",
                                 q_consumer_stack_size,
                                 this,
                                 q_consumer_prio,
                                 &taskp);
        if (taskr != pdPASS) {
            cleanup();
            throw ptm216b_error("queue consumer not created");
        }
        tasks.emplace_back(taskp);
        static const constexpr configSTACK_DEPTH_TYPE nvs_dumper_stack_size = 4096;
        static const constexpr UBaseType_t nvs_dumper_prio = tskIDLE_PRIORITY + 1;
        taskr = xTaskCreate(nvs_dumper,
                            "nvs_dumper",
                            nvs_dumper_stack_size,
                            this,
                            nvs_dumper_prio,
                            &taskp);
        if (taskr != pdPASS) {
            cleanup();
            throw ptm216b_error("queue consumer not created");
        }
        tasks.emplace_back(taskp);

        start();
    }

    enum class parse_error : uint8_t
    {
        unknown_sender,
        invalid_packet,
        old_ctr,
        invalid_signature,
        banned,
        exception
    };

    void call_cb(const device &device, const std::vector<uint8_t> &data) noexcept
    {
        try {
            const std::lock_guard lock(cb_lock);
            callback(device, data);
        } catch (const std::exception &e) {
            ESP_LOGE(log_tag, "event callback: %s", e.what());
        } catch (...) {
            ESP_LOGE(log_tag, "event callback: exception");
        }
    }

    static bool is_rpa(const address_t &a) noexcept
    {
        return (a[0] & 0xc0) == 0x40;
    }

    static key_t rpa_padded_rand(const address_t &a)
    {
        key_t p{};
        std::copy(a.begin(), a.begin() + 3, p.begin() + 13);
        return p;
    }

    std::expected<std::tuple<const device &, std::atomic_uint32_t &>, parse_error>
    find_rpa_match(const address_t &rpa)
    {
        const auto p = rpa_padded_rand(rpa);
        std::array<uint8_t, 3> ahash;
        std::copy(rpa.begin() + 3, rpa.end(), ahash.begin());
        for (auto &[addr, ctx] : device_irk_ctxs) {
            key_t output;
            mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, p.data(), output.data());
            if (timingsafe_bcmp(ahash.data(), output.data() + 13, ahash.size()) == 0) {
                auto dev_it = device_map.find(addr);
                auto ctr_it = device_ctrs.find(addr);
                if (dev_it != device_map.end() && ctr_it != device_ctrs.end()) {
                    const auto &d = dev_it->second;
                    auto &dev_ctr = ctr_it->second;
                    return std::tuple<const device &, std::atomic_uint32_t &>{ d, dev_ctr };
                }
            }
        }
        return std::unexpected{ parse_error::unknown_sender };
    }

    std::expected<std::tuple<const device &, std::atomic_uint32_t &>, parse_error>
    find_address_match(const address_t &addr)
    {
        if (is_rpa(addr))
            return find_rpa_match(addr);
        auto dev_it = device_map.find(addr);
        auto ctr_it = device_ctrs.find(addr);
        if (dev_it != device_map.end() && ctr_it != device_ctrs.end()) {
            const auto &d = dev_it->second;
            auto &dev_ctr = ctr_it->second;
            return std::tuple<const device &, std::atomic_uint32_t &>{ d, dev_ctr };
        }
        return std::unexpected{ parse_error::unknown_sender };
    }

    bool is_banned(const device &d, const bool short_ban)
    {
        static const constexpr int64_t s_to_us = 1000000;
        static const constexpr int64_t short_timeout = s_to_us * 2;
        static const constexpr int64_t long_timeout = s_to_us * 60 * 60 * 6;
        auto ban_el = ban_list.find(d.address);
        if (ban_el != ban_list.end()) {
            const auto timeout =
                    esp_timer_get_time() - (short_ban ? short_timeout : long_timeout);
            const auto time = ban_el->second;
            if (time < timeout) {
                ban_list.erase(ban_el);
                return true;
            }
        }
        return false;
    }

    void ban_device(const device &d)
    {
        const auto time = esp_timer_get_time();
        ban_list.emplace(d.address, time);
    }

    std::expected<std::pair<device, std::vector<uint8_t>>, parse_error> parse_payload(
            const message &m) noexcept
    {
        static const constexpr uint32_t wrap_tolerance = 100;
        static const constexpr uint32_t bruteforce_treshold = 50;
        static const constexpr int64_t bruteforce_treshold_time =
                int64_t{ 1000000 } * 3600 * 24 * 7;
        try {
            auto addr_match = find_address_match(m.address);
            if (addr_match.has_value()) {
                auto &[device, dev_ctr] = *addr_match;
                const auto payload = m.get_payload();
                if (payload.size() >= 9) {
                    uint32_t ctr;
                    std::vector<uint8_t> content;
                    uint8_t tag[4];
                    const auto content_size = payload.size() - sizeof(ctr) - sizeof(tag);
                    content.resize(content_size);
                    memcpy(&ctr, payload.data(), sizeof(ctr));
                    memcpy(content.data(), payload.data() + sizeof(ctr), content.size());
                    memcpy(tag, payload.data() + sizeof(ctr) + content_size, sizeof(tag));
                    const uint32_t last_ctr = dev_ctr.load(std::memory_order_relaxed);
                    if (ctr > last_ctr ||
                        ((std::numeric_limits<uint16_t>::max() - last_ctr) < wrap_tolerance &&
                         ctr < wrap_tolerance)) {
                        const auto mtime = esp_timer_get_time();
                        bool short_ban = false;
                        if ((ctr - last_ctr) < bruteforce_treshold &&
                            (mtime - last_good_message) < bruteforce_treshold_time)
                            short_ban = true;
                        if (is_banned(device, short_ban)) {
                            ESP_LOGI(log_tag, "parse_payload: banned");
                            return std::unexpected{ parse_error::banned };
                        }
                        std::array<uint8_t, 13> nonce = { 0 };
                        std::reverse_copy(
                                device.address.begin(), device.address.end(), nonce.begin());
                        memcpy(nonce.data() + m.address.size(), &ctr, sizeof(ctr));

                        std::vector<uint8_t> data = { 0x0c, 0xff, 0xda, 0x03 };
                        data.resize(payload.size());
                        std::span<uint8_t> data_write(data.begin() + 4, data.end());
                        std::copy(payload.begin(),
                                  payload.begin() + data_write.size(),
                                  data_write.data());

                        mbedtls_ccm_context ctx;
                        mbedtls_ccm_init(&ctx);
                        int r = mbedtls_ccm_setkey(&ctx,
                                                   MBEDTLS_CIPHER_ID_AES,
                                                   device.key.data(),
                                                   device.key.size() * 8);
                        if (r) {
                            ESP_LOGE(log_tag, "mbedtls error: %d", r);
                            return std::unexpected{ parse_error::exception };
                        }
                        if (device.encryption) {
                            data.resize(data.size() - content_size);
                            std::vector<uint8_t> output(content_size);
                            r = mbedtls_ccm_auth_decrypt(&ctx,
                                                         content_size,
                                                         nonce.data(),
                                                         nonce.size(),
                                                         data.data(),
                                                         data.size(),
                                                         content.data(),
                                                         output.data(),
                                                         tag,
                                                         sizeof(tag));
                            content = std::move(output);
                        } else {
                            r = mbedtls_ccm_auth_decrypt(&ctx,
                                                         0,
                                                         nonce.data(),
                                                         nonce.size(),
                                                         data.data(),
                                                         data.size(),
                                                         nullptr,
                                                         nullptr,
                                                         tag,
                                                         sizeof(tag));
                        }
                        mbedtls_ccm_free(&ctx);
                        if (r == 0) {
                            dev_ctr.store(ctr, std::memory_order_relaxed);
                            last_good_message = mtime;
                            return std::pair{ device, content };
                        }
                        ban_device(device);
                        ESP_LOGI(log_tag, "parse_payload: invalid signature");
                        return std::unexpected{ parse_error::invalid_signature };
                    } else if (ctr < last_ctr) {
                        ESP_LOGI(log_tag, "parse_payload: old_ctr");
                        return std::unexpected{ parse_error::old_ctr };
                    }
                } else {
                    ESP_LOGI(log_tag, "parse_payload: invalid_packet");
                    return std::unexpected{ parse_error::invalid_packet };
                }
            } else {
                ESP_LOGV(log_tag, "parse_payload: error %d", addr_match.error());
                return std::unexpected{ addr_match.error() };
            }
        } catch (const std::exception &e) {
            ESP_LOGE(log_tag, "parse_payload: %s", e.what());
        } catch (...) {
            ESP_LOGE(log_tag, "parse_payload: exception");
        }
        return std::unexpected{ parse_error::exception };
    }

    static void q_consumer(void *data) noexcept
    {
        auto *obj = reinterpret_cast<ptm216b *>(data);
        message prev_m;

        while (true) {
            message m;
            if (xQueueReceive(obj->queue, &m, portMAX_DELAY) == pdPASS) {
                if (m == prev_m)
                    continue;
                const auto content = obj->parse_payload(m);
                if (content.has_value()) {
                    const auto &[dev, data] = *content;
                    obj->call_cb(dev, data);
                }
                prev_m = std::move(m);
            }
        }
    }

    void nvs_dumper_helper() noexcept
    {
        nvs_handle_t h;
        bool open = false;
        try {
            static std::mutex m;
            const std::lock_guard lock(m);
            auto ret = nvs_open(nvs_namespace, NVS_READWRITE, &h);
            if (ret == ESP_OK) {
                open = true;
                bool to_commit = false;
                for (auto &[key, dev_ctr] : device_ctrs) {
                    const uint32_t last_ctr = dev_ctr.load(std::memory_order_relaxed);
                    uint32_t val;
                    const auto encodedk = encode_base64(key);
                    const auto *kptr = reinterpret_cast<const char *>(encodedk.data());
                    ret = nvs_get_u32(h, kptr, &val);
                    if (ret != ESP_OK || val != last_ctr) {
                        ret = nvs_set_u32(h, kptr, last_ctr);
                        if (ret == ESP_OK)
                            to_commit = true;
                        else
                            ESP_LOGE(log_tag,
                                     "nvs_dumper_helper: write error %d: %s",
                                     ret,
                                     kptr);
                    }
                }
                if (to_commit) {
                    ret = nvs_commit(h);
                    if (ret != ESP_OK)
                        ESP_LOGE(log_tag, "nvs_dumper_helper: commit error %d", ret);
                    else
                        ESP_LOGI(log_tag, "counters saved to NVS");
                }
            } else {
                ESP_LOGE(log_tag, "nvs_dumper_helper: open error %d", ret);
            }
        } catch (const std::exception &e) {
            ESP_LOGE(log_tag, "nvs_dumper_helper: %s", e.what());
        } catch (...) {
            ESP_LOGE(log_tag, "nvs_dumper_helper: exception");
        }
        if (open)
            nvs_close(h);
    }

    static void nvs_dumper(void *data) noexcept
    {
        auto *obj = reinterpret_cast<ptm216b *>(data);
        while (true) {
            vTaskDelay(20 * 60 * 1000 / portTICK_PERIOD_MS);
            obj->nvs_dumper_helper();
        }
    }

    static void ble_host_task(void *)
    {
        ESP_LOGI(log_tag, "BLE Host Task Started");
        nimble_port_run();
        nimble_port_freertos_deinit();
    }
    static void ble_set_rnd_addr()
    {
        ble_addr_t addr;
        auto rc = ble_hs_id_gen_rnd(0, &addr);
        if (rc != 0) {
            ESP_LOGE(log_tag, "generating random address: rc=%d", rc);
            ESP_ERROR_CHECK(ESP_FAIL);
        }
        rc = ble_hs_id_set_rnd(addr.val);
        if (rc != 0) {
            ESP_LOGE(log_tag, "setting random address: rc=%d", rc);
            ESP_ERROR_CHECK(ESP_FAIL);
        }
    }
    static void ble_sync_cb() noexcept
    {
        ble_set_rnd_addr();
        ble_gap_disc_params disc_params{};
        disc_params.filter_duplicates = 0;
        disc_params.passive = 1;
        disc_params.itvl = 0x1b;
        disc_params.window = 0x14;
        disc_params.filter_policy = BLE_HCI_SCAN_FILT_NO_WL;
        disc_params.limited = 0;
        ptm216b *obj = nullptr;
        try {
            obj = &ptm216b::get_instance();
        } catch (const std::exception &e) {
            ESP_LOGE(log_tag, "ptm216b instance creation: %s", e.what());
            return;
        } catch (...) {
            ESP_LOGE(log_tag, "ptm216b instance creation: exception");
            return;
        }
        auto rc = ble_gap_disc(
                BLE_OWN_ADDR_RPA_RANDOM_DEFAULT, BLE_HS_FOREVER, &disc_params, gap_cb, obj);
        if (rc != 0) {
            ESP_LOGE(log_tag, "discovery: %d\n", rc);
        }
    }
    static int gap_cb(ble_gap_event *event, void *param) noexcept
    {
        if (event->type == BLE_GAP_EVENT_DISC) {
            ble_hs_adv_fields fields;
            auto rc = ble_hs_adv_parse_fields(
                    &fields, event->disc.data, event->disc.length_data);
            if (rc == 0 && fields.mfg_data != nullptr && fields.mfg_data_len > 2 &&
                fields.mfg_data[0] == 0xda && fields.mfg_data[1] == 0x03) [[unlikely]] {
                fields.mfg_data += 2;
                fields.mfg_data_len -= 2;
                if (fields.mfg_data_len >= message::min_payload_size &&
                    fields.mfg_data_len <= message::max_payload_size) [[likely]] {
                    message m;
                    try {
                        m.set_payload(fields.mfg_data, fields.mfg_data_len);
                    } catch (const std::exception &e) {
                        ESP_LOGE(log_tag, "set payload: %s", e.what());
                        return 0;
                    } catch (...) {
                        ESP_LOGE(log_tag, "set payload: exception");
                    }
                    m.set_address(event->disc.addr.val);
                    static_assert(std::is_trivially_copyable_v<message>);
                    auto *obj = reinterpret_cast<ptm216b *>(param);
                    if (xQueueSend(obj->queue, &m, 100 / portTICK_PERIOD_MS) != pdPASS)
                        ESP_LOGE(log_tag, "enqueue failed");
                }
            }
        }
        return 0;
    }
    static int gap_adv_cb(ble_gap_event *event, void *)
    {
        if (event->type == BLE_GAP_EVENT_ADV_COMPLETE)
            ESP_LOGI(log_tag, "adv complete");
        return 0;
    }
};

[[maybe_unused]] static void
ptm216b_stop() noexcept
{
    try {
        auto &p = ptm216b::ptm216b::get_instance();
        p.stop();
    } catch (const std::exception &ex) {
        ESP_LOGE(log_tag, "exception: %s", ex.what());
    } catch (...) {
        ESP_LOGE(log_tag, "exception");
    }
}

[[maybe_unused]] static void
send_adv(const std::vector<uint8_t> &mfg_data) noexcept
{
    try {
        auto &p = ptm216b::ptm216b::get_instance();
        p.send_adv(mfg_data);
    } catch (const std::exception &ex) {
        ESP_LOGE(log_tag, "exception: %s", ex.what());
    } catch (...) {
        ESP_LOGE(log_tag, "exception");
    }
}

};
