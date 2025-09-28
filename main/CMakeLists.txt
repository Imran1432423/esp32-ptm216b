# SPDX-FileCopyrightText: 2025 Salvatore Mesoraca <s.mesoraca16@gmail.com>
# SPDX-License-Identifier: Apache-2.0

idf_build_get_property(project_dir PROJECT_DIR)

idf_component_register(SRCS "main.cpp"
                       PRIV_REQUIRES bt nvs_flash mbedtls protocomm app_update spi_flash
                           bootloader_support esp_driver_gpio
                       INCLUDE_DIRS ".")

add_custom_target(devices ALL
                    "${CMAKE_CURRENT_SOURCE_DIR}/../tools/make_devices.py"
                    "${CMAKE_CURRENT_SOURCE_DIR}/../${CONFIG_PTM216B_DEVICES_FILE}" >
                    "${CMAKE_CURRENT_BINARY_DIR}/include/ptm216b_devices.hpp"
                    BYPRODUCTS "${CMAKE_CURRENT_BINARY_DIR}/include/ptm216b_devices.hpp")
add_dependencies("${COMPONENT_TARGET}" devices)

if (CONFIG_PTM216B_OTA)
    if(CONFIG_PTM216B_OTA_PASSWORD STREQUAL "")
        message(WARNING "please set OTA password via menuconfig")
    endif()
    add_custom_target(ota_verifier ALL
                        "${CMAKE_CURRENT_SOURCE_DIR}/../tools/ota/ota.py"
                            generate-verifier -p "${CONFIG_PTM216B_OTA_PASSWORD}" >
                        "${CMAKE_CURRENT_BINARY_DIR}/include/ota_verifier.hpp"
                        BYPRODUCTS "${CMAKE_CURRENT_BINARY_DIR}/include/ota_verifier.hpp")
    add_dependencies("${COMPONENT_TARGET}" ota_verifier)
    target_add_binary_data("${COMPONENT_TARGET}" "${project_dir}/keys/pub.der" BINARY)
endif()

target_include_directories("${COMPONENT_TARGET}" AFTER PRIVATE
                           "${CMAKE_CURRENT_BINARY_DIR}/include/")
