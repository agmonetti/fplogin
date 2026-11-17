cmake_minimum_required(VERSION 3.16)
project(ThemeContextContract LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
enable_testing()
find_package(Qt5 5.15 REQUIRED COMPONENTS Quick Network Test)
foreach(required SDDM_SOURCE_ROOT SDDM_CONSTANTS_DIR)
    if(NOT EXISTS "${${required}}")
        message(FATAL_ERROR "${required} must name a persistent SDDM source/build directory")
    endif()
endforeach()
add_executable(ThemeContextTest ThemeContextTest.cpp
    ${SDDM_SOURCE_ROOT}/src/greeter/GreeterProxy.cpp
    ${SDDM_SOURCE_ROOT}/src/greeter/SessionModel.cpp
    ${SDDM_SOURCE_ROOT}/src/greeter/ScreenModel.cpp
    ${SDDM_SOURCE_ROOT}/src/common/Session.cpp
    ${SDDM_SOURCE_ROOT}/src/common/Configuration.cpp
    ${SDDM_SOURCE_ROOT}/src/common/ConfigReader.cpp
    ${SDDM_SOURCE_ROOT}/src/common/ThemeConfig.cpp
    ${SDDM_SOURCE_ROOT}/src/common/SocketWriter.cpp)
target_include_directories(ThemeContextTest PRIVATE
    ${SDDM_SOURCE_ROOT}/src/greeter ${SDDM_SOURCE_ROOT}/src/common ${SDDM_CONSTANTS_DIR})
target_link_libraries(ThemeContextTest Qt5::Quick Qt5::Network Qt5::Test)
add_test(NAME ThemeContextContract COMMAND ThemeContextTest)
