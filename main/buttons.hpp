/*
 * SPDX-FileCopyrightText: 2025 Salvatore Mesoraca <s.mesoraca16@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <cstdint>
#include <stdexcept>

#include <driver/gpio.h>

#include "constants.hpp"
#include "events.hpp"

namespace buttons {

static const constexpr char *log_tag = "buttons";

class buttons_error : public std::runtime_error
{
  public:
    buttons_error(const char *s)
            : std::runtime_error(s)
    {
    }
};

enum class button_id : uint32_t
{
    internal = 0x1,
    s2 = 0x2
};

static constexpr uint32_t
operator&(uint32_t a, button_id b)
{
    return a & static_cast<uint32_t>(b);
}

class buttons
{
  public:
    static buttons &get_instance() noexcept
    {
        static buttons instance{};
        return instance;
    }

    ~buttons()
    {
        vTaskDelete(task_h);
    }
    buttons(const buttons &other) = delete;
    buttons &operator=(const buttons &other) = delete;
    buttons(buttons &&other) = delete;
    buttons &operator=(buttons &&other) = delete;

  private:
    TaskHandle_t task_h{ nullptr };

    static void config_gpio(const gpio_num_t gpio)
    {
        gpio_config_t conf = {};
        conf.pull_down_en = GPIO_PULLDOWN_DISABLE;
        conf.intr_type = GPIO_INTR_ANYEDGE;
        conf.pin_bit_mask = (1ULL << gpio);
        conf.mode = GPIO_MODE_INPUT;
        conf.pull_up_en = GPIO_PULLUP_ENABLE;
        ESP_ERROR_CHECK(gpio_config(&conf));
    }

    static void handler_button(void *arg)
    {
        auto task = reinterpret_cast<TaskHandle_t>(arg);
        xTaskNotifyFromISR(
                task, static_cast<uint32_t>(button_id::internal), eSetBits, nullptr);
    }

    static void handler_s2(void *arg)
    {
        auto task = reinterpret_cast<TaskHandle_t>(arg);
        xTaskNotifyFromISR(task, static_cast<uint32_t>(button_id::s2), eSetBits, nullptr);
    }

    static void task(void *)
    {
        auto prev_b_state = gpio_get_level(config::button_gpio);
        auto prev_s2_state = gpio_get_level(config::s2_gpio);
        auto press_time = esp_timer_get_time();
        static const constexpr int64_t press_time_for_ota_us = 10LL * 1000 * 1000;
        while (true) {
            auto bid = ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
            int b_state;
            int s2_state;
            if (bid != 0) {
                if ((bid & button_id::internal) != 0)
                    b_state = gpio_get_level(config::button_gpio);
                if ((bid & button_id::s2) != 0)
                    s2_state = gpio_get_level(config::s2_gpio);
                vTaskDelay(config::gpio_debounce_delay / portTICK_PERIOD_MS);
                if ((bid & button_id::internal) != 0) {
                    auto state2 = gpio_get_level(config::button_gpio);
                    if (b_state == state2 && state2 != prev_b_state) {
                        prev_b_state = b_state;
                        ESP_LOGI(log_tag, "gpio: internal: %d", state2);
                        if (state2 == 0) {
                            events::actions::light_toggle();
                            press_time = esp_timer_get_time();
                        } else if (config::ota_on_internal_button) {
                            const auto now = esp_timer_get_time();
                            if (now - press_time >= press_time_for_ota_us)
                                events::actions::ota();
                        }
                    }
                }
                if ((bid & button_id::s2) != 0) {
                    auto state2 = gpio_get_level(config::s2_gpio);
                    if (s2_state == state2 && state2 != prev_s2_state) {
                        prev_s2_state = s2_state;
                        ESP_LOGI(log_tag, "gpio: s2: %d", state2);
                        if (config::s2_monostable) {
                            if (state2 == 0)
                                events::actions::light_toggle();
                        } else {
                            events::actions::light_toggle();
                        }
                    }
                }
            }
        }
    }

    buttons() noexcept
    {
        config_gpio(config::button_gpio);
        config_gpio(config::s2_gpio);

        ESP_ERROR_CHECK(gpio_install_isr_service(0));

        static const constexpr configSTACK_DEPTH_TYPE task_stacksize = 4096;
        static const constexpr UBaseType_t task_prio = tskIDLE_PRIORITY + 1;
        auto taskr =
                xTaskCreate(task, "buttons_task", task_stacksize, nullptr, task_prio, &task_h);
        if (taskr != pdPASS) {
            ESP_LOGE(log_tag, "task creation failure %d", taskr);
            ESP_ERROR_CHECK(ESP_FAIL);
        }

        ESP_ERROR_CHECK(gpio_isr_handler_add(config::s2_gpio, handler_s2, task_h));
        ESP_ERROR_CHECK(gpio_isr_handler_add(config::button_gpio, handler_button, task_h));
    }
};

};
