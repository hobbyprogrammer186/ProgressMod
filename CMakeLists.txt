cmake_minimum_required(VERSION 3.20)
project(ProgressMod)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets)
find_package(Python3 REQUIRED COMPONENTS Interpreter Development.Embed)
find_package(pybind11 REQUIRED)

if(DEFINED CMAKE_TOOLCHAIN_FILE OR DEFINED ENV{VCPKG_ROOT})
    find_package(capstone REQUIRED CONFIG)
    find_package(ELF REQUIRED CONFIG)
else()
    pkg_check_modules(CAPSTONE REQUIRED IMPORTED_TARGET capstone)
    pkg_check_modules(ELF REQUIRED IMPORTED_TARGET libelf)
endif()

include_directories(include)
add_subdirectory(src)
