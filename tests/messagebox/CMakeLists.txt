add_library(messagebox SHARED "main.cpp")

add_custom_command(
    OUTPUT "$<CONFIG>/messagebox.dll.hpp"
    COMMAND $<OUTPUT_CONFIG:$<TARGET_FILE:bin2h>> $<TARGET_FILE:messagebox> ${CMAKE_SOURCE_DIR}/tests/messagebox/messagebox.dll.hpp.in $<CONFIG>/messagebox.dll.hpp
    DEPENDS "$<TARGET_FILE:messagebox>"
    COMMENT "Generating header with embedded MessageBox DLL"
)

add_library(messagebox-header INTERFACE)

target_sources(
    messagebox-header
    PUBLIC
        FILE_SET
            messagebox_header
        TYPE    
            HEADERS
        BASE_DIRS
            "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>"
        FILES
            "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>/messagebox.dll.hpp"
)

target_include_directories(messagebox-header INTERFACE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})