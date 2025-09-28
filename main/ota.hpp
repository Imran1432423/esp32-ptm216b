/*
 * SPDX-FileCopyrightText: 2025 Salvatore Mesoraca <s.mesoraca16@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#if PTM216B_OTA

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <span>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <esp_app_format.h>
#include <esp_flash.h>
#include <esp_log.h>
#include <esp_mac.h>
#include <esp_ota_ops.h>
#include <esp_random.h>
#include <esp_srp.h>
#include <hal/efuse_hal.h>
#include <protocomm.h>
#include <protocomm_ble.h>
#include <protocomm_security2.h>

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include <mbedtls/pk.h>

#include "ota_verifier.hpp"
#include "ptm216b_fwd.hpp"

namespace ota {

extern const char pub_der_start[] asm("_binary_pub_der_start");
extern const char pub_der_end[] asm("_binary_pub_der_end");
static const std::span<const char> pub_der{ pub_der_start, pub_der_end };

static const constexpr char *ota_tag = "ota";
static const constexpr char custom_version[] = { "ota-v1" };

static std::vector<uint8_t>
random_bd_addr()
{
    std::vector<uint8_t> r(6);
    esp_fill_random(r.data(), r.size());
    r[5] |= 0xc0u;
    return r;
}

static bool
pending_verify() noexcept
{
    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_ota_img_states_t ota_state;
    if (esp_ota_get_state_partition(running, &ota_state) == ESP_OK)
        if (ota_state == ESP_OTA_IMG_PENDING_VERIFY)
            return true;
    return false;
}

static void
verify_fw() noexcept
{
    std::vector<uint8_t> mfg = { 0xda, 0x04, 0x4f, 0x54, 0x41, 0x20, 0x4f, 0x4b };
    ptm216b::send_adv(mfg);
    esp_ota_mark_app_valid_cancel_rollback();
}

static void
revert_fw()
{
    std::vector<uint8_t> mfg = { 0xda, 0x04, 0x4f, 0x54, 0x41, 0x20, 0x46, 0x41, 0x49, 0x4c };
    ptm216b::send_adv(mfg);
    esp_ota_mark_app_invalid_rollback_and_reboot();
}

class ble
{
  public:
    class ble_error : public std::runtime_error
    {
      public:
        ble_error(const char *s)
                : std::runtime_error(s)
        {
        }
    };

    static ble &get_instance()
    {
        static ble instance{};
        return instance;
    }

    ~ble()
    {
        if (pc != nullptr)
            protocomm_delete(pc);
        mbedtls_md_free(&mdctx);
        mbedtls_pk_free(&ctx);
    }
    ble(const ble &other) = delete;
    ble &operator=(const ble &other) = delete;
    ble(ble &&other) = delete;
    ble &operator=(ble &&other) = delete;

  private:
    std::string sn;
    std::string name{ "OTA" };
    uint32_t current_session{ 0 };
    uint32_t size{ 0 };
    uint32_t recv_size{ 0 };
    esp_ota_handle_t ota_handle;
    esp_partition_t next;
    std::mutex m;
    mbedtls_pk_context ctx{};
    mbedtls_md_context_t mdctx{};
    size_t sig_size;
    std::vector<uint8_t> signature;
    size_t hash_size;
    std::atomic_flag restarting = ATOMIC_FLAG_INIT;
    bool header_ok{ false };
    static const constexpr uint8_t service_uuid[16] = { 0x71, 0x1f, 0xa1, 0xa9, 0x0e, 0x91,
                                                        0x75, 0xbb, 0x99, 0x42, 0xaa, 0x1c,
                                                        0xc2, 0x3a, 0xd8, 0x3e };
    std::vector<uint8_t> ble_addr;
    protocomm_t *pc = nullptr;
    protocomm_ble_config_t ble_config{};
    protocomm_security2_params_t sec2_params{};
    protocomm_ble_name_uuid_t nu_lookup_table[4] = {
        { "security", 0xFF51 },
        { "firmware", 0xFF52 },
        { "version", 0xFF53 },
        { "reset", 0xFF54 },
    };

    ble()
    {
        if (pending_verify()) {
            throw ble_error(
                    "impossible to run ota while verification of current image is still pending");
        }
        mbedtls_pk_init(&ctx);
        auto r = mbedtls_pk_parse_public_key(
                &ctx, reinterpret_cast<const unsigned char *>(pub_der.data()), pub_der.size());
        if (r != 0) {
            ESP_LOGE(ota_tag, "pub key error %d", r);
            ESP_ERROR_CHECK(ESP_FAIL);
        }
        sig_size = mbedtls_rsa_get_len(mbedtls_pk_rsa(ctx));
        signature.reserve(sig_size);

        init_mdctx();

        static const constexpr configSTACK_DEPTH_TYPE countdown_stacksize = 4096;
        static const constexpr UBaseType_t countdown_prio = tskIDLE_PRIORITY + 1;

        auto taskr = xTaskCreate(countdown,
                                 "ota_countdown",
                                 countdown_stacksize,
                                 this,
                                 countdown_prio,
                                 nullptr);
        if (taskr != pdPASS) {
            ESP_LOGE(ota_tag, "countdown creation failure %d", taskr);
            ESP_ERROR_CHECK(ESP_FAIL);
        }

        memcpy(ble_config.device_name,
               name.data(),
               std::min(name.size(), size_t{ MAX_BLE_DEVNAME_LEN }));
        static_assert(sizeof(service_uuid) == sizeof(ble_config.service_uuid));
        memcpy(ble_config.service_uuid, service_uuid, sizeof(service_uuid));
        ble_config.nu_lookup_count = sizeof(nu_lookup_table) / sizeof(nu_lookup_table[0]);
        ble_config.nu_lookup = nu_lookup_table;
        ble_config.ble_sm_sc = 1;
        ble_config.ble_link_encryption = 1;
        ble_addr = random_bd_addr();
        ble_config.ble_addr = ble_addr.data();
        pc = protocomm_new();
        ESP_ERROR_CHECK(protocomm_ble_start(pc, &ble_config));
        sec2_params.salt = ota_salt;
        sec2_params.salt_len = sizeof(ota_salt);
        sec2_params.verifier = ota_verifier;
        sec2_params.verifier_len = sizeof(ota_verifier);
        ESP_ERROR_CHECK(
                protocomm_set_security(pc, "security", &protocomm_security2, &sec2_params));
        ESP_ERROR_CHECK(protocomm_add_endpoint(pc, "firmware", ota_handler, this));
        ESP_ERROR_CHECK(protocomm_set_version(pc, "version", custom_version));
        ESP_ERROR_CHECK(protocomm_add_endpoint(pc, "reset", reset_handler, this));

        ESP_LOGI(ota_tag, "ble ota started");
    }

    void init_mdctx() noexcept
    {
        mbedtls_md_init(&mdctx);
        auto r = mbedtls_md_setup(&mdctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
        if (r != 0) {
            ESP_LOGE(ota_tag, "md setup error %d", r);
            ESP_ERROR_CHECK(ESP_FAIL);
        }
        r = mbedtls_md_starts(&mdctx);
        if (r != 0) {
            ESP_LOGE(ota_tag, "md starts error %d", r);
            ESP_ERROR_CHECK(ESP_FAIL);
        }
        hash_size = mbedtls_md_get_size(mbedtls_md_info_from_ctx(&mdctx));
    }

    static esp_err_t ota_handler(uint32_t session_id,
                                 const uint8_t *inbuf,
                                 const ssize_t inlen,
                                 uint8_t **outbuf,
                                 ssize_t *outlen,
                                 void *priv_data) noexcept
    {
        static const constexpr uint8_t end_tag[] = { 0x45, 0x4e, 0x44 };
        static const constexpr uint8_t ok_tag[] = { 0x4f, 0x4b };
        static const constexpr uint8_t fok_tag[] = { 0x46, 0x4f, 0x4b };
        if (inlen <= 0)
            return ESP_OK;
        auto *obj = reinterpret_cast<ble *>(priv_data);
        ESP_LOGI(ota_tag, "Received message of len: %zd", inlen);

        try {
            if (obj->restarting.test())
                throw ble_error("restarting");
            const std::lock_guard lock(obj->m);

            if (obj->size == 0 && inlen == sizeof(obj->size)) {
                memcpy(&obj->size, inbuf, sizeof(obj->size));
                if (obj->size < sizeof(esp_image_header_t))
                    throw ble_error("image too small");
                obj->current_session = session_id;
                const auto *current = esp_ota_get_running_partition();
                const auto *tmp = esp_ota_get_next_update_partition(current);
                memcpy(&(obj->next), tmp, sizeof(obj->next));
                auto r = esp_ota_begin(&(obj->next), obj->size, &(obj->ota_handle));
                if (r != ESP_OK)
                    throw ble_error(esp_err_to_name(r));
                ESP_LOGI(ota_tag, "firmware size read");
            } else if (session_id != obj->current_session) {
                throw ble_error("multiple sessions not supported");
            } else if (obj->signature.size() < obj->sig_size) {
                obj->signature.insert(obj->signature.end(), inbuf, inbuf + inlen);
                ESP_LOGI(ota_tag, "reading signature");
            } else if (!obj->header_ok) {
                if (inlen < sizeof(esp_image_header_t))
                    throw ble_error("broken header");
                const auto *hdr = reinterpret_cast<const esp_image_header_t *>(inbuf);
                if (hdr->magic != ESP_IMAGE_HEADER_MAGIC)
                    throw ble_error("not an esp image");
                if (hdr->chip_id != CONFIG_IDF_FIRMWARE_CHIP_ID)
                    throw ble_error("chip id mismatch");
                auto chip_rev = efuse_hal_blk_version();
                if (hdr->min_chip_rev_full > chip_rev)
                    throw ble_error("chip min rev mismatch");
                if (hdr->max_chip_rev_full < chip_rev)
                    throw ble_error("chip max rev mismatch");
                uint32_t flash_size;
                esp_flash_get_size(nullptr, &flash_size);
                if (image_get_flash_size(static_cast<esp_image_flash_size_t>(hdr->spi_size)) !=
                    flash_size)
                    throw ble_error("wrong flash size");
                auto r = mbedtls_md_update(&(obj->mdctx), inbuf, inlen);
                if (r != 0)
                    throw ble_error("hashing error");
                obj->recv_size += inlen;
                r = esp_ota_write(obj->ota_handle, inbuf, inlen);
                if (r != ESP_OK)
                    throw ble_error(esp_err_to_name(r));
                obj->header_ok = true;
                ESP_LOGI(ota_tag, "Header validated");
            } else if (inlen == sizeof(end_tag) &&
                       memcmp(inbuf, end_tag, sizeof(end_tag)) == 0) {
                ESP_LOGI(ota_tag, "final packet received");
                if (obj->size != obj->recv_size)
                    throw ble_error("wrong data size");
                std::vector<uint8_t> hash(obj->hash_size);
                auto r = mbedtls_md_finish(&(obj->mdctx), hash.data());
                if (r != 0)
                    throw ble_error("hashing error");
                ESP_LOGI(ota_tag, "calculated hash:");
                ESP_LOG_BUFFER_HEX(ota_tag, hash.data(), hash.size());
                mbedtls_pk_rsassa_pss_options options;
                options.mgf1_hash_id = MBEDTLS_MD_SHA256;
                options.expected_salt_len = MBEDTLS_RSA_SALT_LEN_ANY;
                r = mbedtls_pk_verify_ext(MBEDTLS_PK_RSASSA_PSS,
                                          &options,
                                          &(obj->ctx),
                                          MBEDTLS_MD_SHA256,
                                          hash.data(),
                                          hash.size(),
                                          obj->signature.data(),
                                          obj->signature.size());
                if (r != 0)
                    throw ble_error("signature error");
                r = esp_ota_end(obj->ota_handle);
                if (r != ESP_OK)
                    throw ble_error(esp_err_to_name(r));
                r = esp_ota_set_boot_partition(&(obj->next));
                if (r != ESP_OK)
                    throw ble_error(esp_err_to_name(r));
                *outlen = sizeof(fok_tag);
                *outbuf = reinterpret_cast<uint8_t *>(malloc(*outlen));
                if (*outbuf == nullptr) {
                    ESP_LOGE(ota_tag, "System out of memory");
                    return ESP_ERR_NO_MEM;
                }
                memcpy(*outbuf, fok_tag, *outlen);
                obj->delayed_restart();
                return ESP_OK;
            } else {
                if ((obj->size - inlen) < obj->recv_size)
                    throw ble_error("too much data");
                auto r = mbedtls_md_update(&(obj->mdctx), inbuf, inlen);
                if (r != 0)
                    throw ble_error("hashing error");
                obj->recv_size += inlen;
                r = esp_ota_write(obj->ota_handle, inbuf, inlen);
                if (r != ESP_OK)
                    throw ble_error(esp_err_to_name(r));
            }
            *outlen = sizeof(ok_tag);
            *outbuf = reinterpret_cast<uint8_t *>(malloc(*outlen));
            if (*outbuf == nullptr) {
                ESP_LOGE(ota_tag, "System out of memory");
                return ESP_ERR_NO_MEM;
            }
            memcpy(*outbuf, ok_tag, *outlen);
        } catch (const std::exception &ex) {
            const std::lock_guard lock(obj->m);
            esp_ota_abort(obj->ota_handle);
            *outlen = strlen(ex.what());
            *outbuf = reinterpret_cast<uint8_t *>(malloc(*outlen));
            if (*outbuf == nullptr) {
                ESP_LOGE(ota_tag, "System out of memory");
                return ESP_ERR_NO_MEM;
            }
            ESP_LOGE(ota_tag, "exception: %s", ex.what());
            memcpy(*outbuf, ex.what(), *outlen);
            obj->delayed_restart();
        } catch (...) {
            const std::lock_guard lock(obj->m);
            esp_ota_abort(obj->ota_handle);
            static const constexpr char ex[] = { "exception" };
            *outlen = strlen(ex);
            *outbuf = reinterpret_cast<uint8_t *>(malloc(*outlen));
            if (*outbuf == nullptr) {
                ESP_LOGE(ota_tag, "System out of memory");
                return ESP_ERR_NO_MEM;
            }
            ESP_LOGE(ota_tag, "exception");
            memcpy(*outbuf, ex, *outlen);
            obj->delayed_restart();
        }
        return ESP_OK;
    }

    static esp_err_t reset_handler(uint32_t /*session_id*/,
                                   const uint8_t *inbuf,
                                   const ssize_t inlen,
                                   uint8_t **outbuf,
                                   ssize_t *outlen,
                                   void *priv_data) noexcept
    {
        static const constexpr uint8_t ok_tag[] = { 0x4f, 0x4b };
        static const constexpr uint8_t reset_status_tag = 0x72;
        static const constexpr uint8_t reset_board_tag = 0x52;
        auto *obj = reinterpret_cast<ble *>(priv_data);
        *outlen = 0;
        *outbuf = nullptr;

        if (inlen != 1 || obj->restarting.test())
            return ESP_OK;

        if (*inbuf == reset_board_tag) {
            ESP_LOGI(ota_tag, "Reset board");
            *outlen = sizeof(ok_tag);
            *outbuf = reinterpret_cast<uint8_t *>(malloc(*outlen));
            if (*outbuf == nullptr) {
                ESP_LOGE(ota_tag, "System out of memory");
                return ESP_ERR_NO_MEM;
            }
            memcpy(*outbuf, ok_tag, *outlen);
            obj->delayed_restart();
            return ESP_OK;
        }

        if (*inbuf == reset_status_tag) {
            ESP_LOGI(ota_tag, "Reset status");
            try {
                const std::lock_guard lock(obj->m);
                esp_ota_abort(obj->ota_handle);
                obj->size = 0;
                obj->recv_size = 0;
                obj->current_session = 0;
                obj->header_ok = false;
                obj->signature.clear();
                obj->signature.reserve(obj->sig_size);
                mbedtls_md_free(&(obj->mdctx));
                obj->init_mdctx();
            } catch (const std::exception &ex) {
                const std::lock_guard lock(obj->m);
                esp_ota_abort(obj->ota_handle);
                *outlen = strlen(ex.what());
                *outbuf = reinterpret_cast<uint8_t *>(malloc(*outlen));
                if (*outbuf == nullptr) {
                    ESP_LOGE(ota_tag, "System out of memory");
                    return ESP_ERR_NO_MEM;
                }
                ESP_LOGE(ota_tag, "exception: %s", ex.what());
                memcpy(*outbuf, ex.what(), *outlen);
                obj->delayed_restart();
                return ESP_OK;
            } catch (...) {
                const std::lock_guard lock(obj->m);
                esp_ota_abort(obj->ota_handle);
                static const constexpr char ex[] = { "exception" };
                *outlen = strlen(ex);
                *outbuf = reinterpret_cast<uint8_t *>(malloc(*outlen));
                if (*outbuf == nullptr) {
                    ESP_LOGE(ota_tag, "System out of memory");
                    return ESP_ERR_NO_MEM;
                }
                ESP_LOGE(ota_tag, "exception");
                memcpy(*outbuf, ex, *outlen);
                obj->delayed_restart();
                return ESP_OK;
            }
            *outlen = sizeof(ok_tag);
            *outbuf = reinterpret_cast<uint8_t *>(malloc(*outlen));
            if (*outbuf == nullptr) {
                ESP_LOGE(ota_tag, "System out of memory");
                return ESP_ERR_NO_MEM;
            }
            memcpy(*outbuf, ok_tag, *outlen);
            return ESP_OK;
        }

        return ESP_OK;
    }

    static void restarter(void * /* param */) noexcept
    {
        vTaskDelay(5000 / portTICK_PERIOD_MS);
        esp_restart();
    }

    void delayed_restart() noexcept
    {
        static const constexpr configSTACK_DEPTH_TYPE restarter_stack_size = 1024;
        static const constexpr UBaseType_t restarter_prio = tskIDLE_PRIORITY + 1;

        if (restarting.test_and_set()) {
            ESP_LOGW(ota_tag, "already restarting");
            return;
        }

        ESP_LOGI(ota_tag, "restarting device in 5 seconds...");
        auto taskr = xTaskCreate(restarter,
                                 "restarter",
                                 restarter_stack_size,
                                 nullptr,
                                 restarter_prio,
                                 nullptr);
        if (taskr != pdPASS)
            esp_restart();
    }

    static void countdown(void *param)
    {
        auto *obj = reinterpret_cast<ble *>(param);

        size_t prev_recv_size = 0;
        while (true) {
            vTaskDelay(60000 / portTICK_PERIOD_MS);
            const std::lock_guard lock(obj->m);
            if (obj->size == 0 || obj->recv_size == prev_recv_size) {
                ESP_LOGI(ota_tag, "no activity in 60 seconds...");
                obj->delayed_restart();
                vTaskDelete(nullptr);
                return;
            }
            prev_recv_size = obj->recv_size;
        }
    }

    static int image_get_flash_size(const esp_image_flash_size_t app_flash_size)
    {
        switch (app_flash_size) {
        case ESP_IMAGE_FLASH_SIZE_1MB:
            return 1 * 1024 * 1024;
        case ESP_IMAGE_FLASH_SIZE_2MB:
            return 2 * 1024 * 1024;
        case ESP_IMAGE_FLASH_SIZE_4MB:
            return 4 * 1024 * 1024;
        case ESP_IMAGE_FLASH_SIZE_8MB:
            return 8 * 1024 * 1024;
        case ESP_IMAGE_FLASH_SIZE_16MB:
            return 16 * 1024 * 1024;
        case ESP_IMAGE_FLASH_SIZE_32MB:
            return 32 * 1024 * 1024;
        case ESP_IMAGE_FLASH_SIZE_64MB:
            return 64 * 1024 * 1024;
        case ESP_IMAGE_FLASH_SIZE_128MB:
            return 128 * 1024 * 1024;
        default:
            return 0;
        }
    }
};

static void
ota_start() noexcept
{
    ptm216b::ptm216b_stop();
    try {
        auto &up = ota::ble::get_instance();
        (void) up;
    } catch (const std::exception &ex) {
        ESP_LOGE("ota", "exception: %s", ex.what());
    } catch (...) {
        ESP_LOGE("ota", "exception");
    }
}

};

#else   // PTM216B_OTA

#include "ota_fwd.hpp"

#endif   // PTM216B_OTA
