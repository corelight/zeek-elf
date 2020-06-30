
cmake_minimum_required(VERSION 3.0 FATAL_ERROR)

project(ZeekPluginELF)

include(ZeekPlugin)

zeek_plugin_begin(Zeek ELF)
zeek_plugin_pac(
        src/elf.pac
        src/elf-analyzer.pac
        src/elf-file-headers.pac
        src/elf-file.pac
)
zeek_plugin_cc(src/elf.cc src/Plugin.cc)
zeek_plugin_bif(src/elf.bif src/types.bif src/events.bif)
zeek_plugin_dist_files(README.md CHANGES COPYING VERSION)
zeek_plugin_end()

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()
