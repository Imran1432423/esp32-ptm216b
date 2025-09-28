/*
 * SPDX-FileCopyrightText: 2025 Salvatore Mesoraca <s.mesoraca16@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#include <nvs.h>
#include <nvs_flash.h>

#include <driver/gpio.h>
#include <esp_event.h>
#include <esp_log.h>

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include "buttons.hpp"
#include "constants.hpp"
#include "ota.hpp"
#include "ptm216b.hpp"
#include "ptm216b_types.hpp"
#include "relay.hpp"

static const constexpr char *TAG = "app_main";

extern "C" void
app_main(void)
{
    ESP_LOGI(TAG, "started");

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_ERROR_CHECK(esp_event_loop_create_default());

    ESP_ERROR_CHECK(gpio_reset_pin(config::led_gpio));
    ESP_ERROR_CHECK(gpio_set_direction(config::led_gpio, GPIO_MODE_OUTPUT));
    ESP_ERROR_CHECK(gpio_set_level(config::led_gpio, config::led_status));

    relay::relay::get_instance();
    buttons::buttons::get_instance();
    ptm216b::ptm216b::get_instance();

    if (config::ota_enable) {
        if (ota::pending_verify()) {
            ESP_LOGI(TAG, "new firmware detected, waiting for verification...");
            vTaskDelay(120000 / portTICK_PERIOD_MS);
            if (ota::pending_verify()) {
                ESP_LOGE(TAG, "no OTA ack in 2 minutes, reverting fw...");
                ota::revert_fw();
            }
        }
    }
}
