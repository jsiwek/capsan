project(capsan C CXX)
cmake_minimum_required(VERSION 2.6.3)
set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

# Prepend MacPorts and Fink search paths to the default one.
if ( APPLE )
    list(INSERT CMAKE_SYSTEM_PREFIX_PATH 0 /opt/local)
    list(INSERT CMAKE_SYSTEM_PREFIX_PATH 0 /sw)
endif ()

find_package(libpcap REQUIRED)
find_package(openssl REQUIRED)

include_directories(BEFORE ${LIBPCAP_INCLUDE_DIR})
include_directories(BEFORE ${OPENSSL_INCLUDE_DIR})

if ( NOT CMAKE_BUILD_TYPE )
    message(STATUS "Defaulting to 'RelWithDebInfo' build configuration.")
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif ()

set(CMAKE_C_FLAGS         "${CMAKE_C_FLAGS} -Wall")
set(CMAKE_CXX_FLAGS       "${CMAKE_CXX_FLAGS} -Wall")
set(CMAKE_C_FLAGS_DEBUG   "${CMAKE_C_FLAGS_DEBUG} -DDEBUG")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUG")

# Expose C99 functionality from inttypes.h, which would otherwise not be
# available in C++.
add_definitions(-D__STDC_FORMAT_MACROS)

add_executable(capsan
               main.cpp
               IPv4Anonymizer.cpp
               IPv4Anonymizer.hpp
               LinkLayerSanitizer.cpp
               LinkLayerSanitizer.hpp
               Packet.hpp
               PortAnonymizer.cpp
               PortAnonymizer.hpp
)
target_link_libraries(capsan ${LIBPCAP_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY})

if ( CMAKE_BUILD_TYPE )
    string(TOUPPER ${CMAKE_BUILD_TYPE} BuildType)
endif ()

message(
    "\n=================|  capsan Config Summary  |=================="
    "\nBuild Type:      ${CMAKE_BUILD_TYPE}"
    "\n"
    "\nCC:              ${CMAKE_C_COMPILER}"
    "\nCFLAGS:          ${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${BuildType}}"
    "\nCXX:             ${CMAKE_CXX_COMPILER}"
    "\nCXXFLAGS:        ${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${BuildType}}"
    "\n================================================================"
)
