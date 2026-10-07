# mrc_decoder — C++ engine + CLI + pybind11 module
cmake_minimum_required(VERSION 3.16)
project(mrc_decoder LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# ---- Dependencies -----------------------------------------------------------
# libpcap (Unix) / Npcap SDK (Windows). Provide PCAP_ROOT if not auto-found.
# Set -DMRC_WITH_PCAP=OFF to build without capture reading (engine returns an
# error at runtime; useful to compile/test the rest without the SDK installed).
option(MRC_WITH_PCAP "Build with libpcap/Npcap support" ON)

if(MRC_WITH_PCAP)
  find_path(PCAP_INCLUDE_DIR pcap.h
    HINTS ${PCAP_ROOT}/Include ${PCAP_ROOT}/include $ENV{PCAP_ROOT}/Include)
  find_library(PCAP_LIBRARY NAMES pcap wpcap
    HINTS ${PCAP_ROOT}/Lib/x64 ${PCAP_ROOT}/Lib ${PCAP_ROOT}/lib
          $ENV{PCAP_ROOT}/Lib/x64 $ENV{PCAP_ROOT}/Lib)
  if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
    message(FATAL_ERROR
      "libpcap / Npcap SDK not found.\n"
      "  Windows: download the Npcap SDK from https://npcap.com/#download, unzip it, then\n"
      "           re-run:  cmake -S . -B build -DPCAP_ROOT=C:/path/to/npcap-sdk\n"
      "  Linux:   install libpcap-dev (apt install libpcap-dev).\n"
      "  Or configure without capture support:  cmake -S . -B build -DMRC_WITH_PCAP=OFF")
  endif()
endif()

# mdflib (https://github.com/ihedvall/mdflib). Provide mdflib_DIR if not on prefix path.
find_package(mdflib QUIET)

# pugixml for ARXML parsing: prefer system package, else fetch.
find_package(pugixml QUIET)
if(NOT pugixml_FOUND)
  include(FetchContent)
  FetchContent_Declare(pugixml
    GIT_REPOSITORY https://github.com/zeux/pugixml.git
    GIT_TAG v1.14)
  FetchContent_MakeAvailable(pugixml)
endif()

# ---- Core library -----------------------------------------------------------
add_library(mrc_core
  cpp/src/mrc_packet.cpp
  cpp/src/pcap_reader.cpp
  cpp/src/decode_model.cpp
  cpp/src/mdf_writer.cpp
  cpp/src/engine.cpp
)
target_include_directories(mrc_core PUBLIC cpp/include)
# Built into the pybind11 shared module, so the static lib needs PIC.
set_property(TARGET mrc_core PROPERTY POSITION_INDEPENDENT_CODE ON)
target_link_libraries(mrc_core PUBLIC pugixml::pugixml)
if(MRC_WITH_PCAP)
  target_include_directories(mrc_core PUBLIC ${PCAP_INCLUDE_DIR})
  target_link_libraries(mrc_core PUBLIC ${PCAP_LIBRARY})
  target_compile_definitions(mrc_core PUBLIC MRC_HAVE_PCAP=1)
endif()
if(mdflib_FOUND)
  target_link_libraries(mrc_core PUBLIC mdflib::mdflib)
  target_compile_definitions(mrc_core PUBLIC MRC_HAVE_MDFLIB=1)
endif()

# ---- CLI --------------------------------------------------------------------
add_executable(mrc_decoder cpp/src/main.cpp)
target_link_libraries(mrc_decoder PRIVATE mrc_core)

# ---- Tests ------------------------------------------------------------------
enable_testing()
add_executable(test_decode_model cpp/tests/test_decode_model.cpp)
target_link_libraries(test_decode_model PRIVATE mrc_core)
add_test(NAME decode_model COMMAND test_decode_model)

# ---- Python module (optional) ----------------------------------------------
find_package(pybind11 QUIET)
if(pybind11_FOUND)
  pybind11_add_module(mrc_engine cpp/bindings/pybind_module.cpp)
  target_link_libraries(mrc_engine PRIVATE mrc_core)
endif()
