cmake_minimum_required(VERSION 3.16)
project(ThemeAutomaticContract LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
enable_testing()
set(FPL_QT_MAJOR 5 CACHE STRING "Qt major for the theme consumer")
if(NOT FPL_QT_MAJOR MATCHES "^[56]$")
    message(FATAL_ERROR "FPL_QT_MAJOR must be 5 or 6")
endif()
find_package(Qt${FPL_QT_MAJOR} REQUIRED COMPONENTS Quick Network Test)
foreach(required SDDM_SOURCE_ROOT SDDM_CONSTANTS_DIR)
    if(NOT EXISTS "${${required}}")
        message(FATAL_ERROR "${required} must name a persistent SDDM source/build directory")
    endif()
endforeach()
add_executable(ThemeAutoTest ThemeAutoTest.cpp
    ${SDDM_SOURCE_ROOT}/src/greeter/ThemeAuthentication.cpp
    ${SDDM_SOURCE_ROOT}/src/greeter/GreeterProxy.cpp
    ${SDDM_SOURCE_ROOT}/src/greeter/SessionModel.cpp
    ${SDDM_SOURCE_ROOT}/src/greeter/ScreenModel.cpp
    ${SDDM_SOURCE_ROOT}/src/common/Session.cpp
    ${SDDM_SOURCE_ROOT}/src/common/Configuration.cpp
    ${SDDM_SOURCE_ROOT}/src/common/ConfigReader.cpp
    ${SDDM_SOURCE_ROOT}/src/common/ThemeConfig.cpp
    ${SDDM_SOURCE_ROOT}/src/common/SocketWriter.cpp)
target_include_directories(ThemeAutoTest PRIVATE
    ${SDDM_SOURCE_ROOT}/src/greeter ${SDDM_SOURCE_ROOT}/src/common ${SDDM_CONSTANTS_DIR})
target_link_libraries(ThemeAutoTest Qt${FPL_QT_MAJOR}::Quick Qt${FPL_QT_MAJOR}::Network Qt${FPL_QT_MAJOR}::Test)
add_test(NAME ThemeAutomaticContract COMMAND ThemeAutoTest)
