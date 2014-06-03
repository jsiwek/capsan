# Tries to locate libpcap header and libraries.
#
# Usage:
#
#     find_package(libpcap)
#
#     LIBPCAP_ROOT_DIR may be defined beforehand to hint at install location.
#
# Variables defined after calling:
#
#     LIBPCAP_FOUND       - whether libpcap installation is located
#     LIBPCAP_INCLUDE_DIR - path to libpcap header
#     LIBPCAP_LIBRARY     - path of libpcap library

find_path(LIBPCAP_ROOT_DIR
    NAMES include/pcap.h
)

find_path(LIBPCAP_INCLUDE_DIR
    NAMES pcap.h
    HINTS ${LIBPCAP_ROOT_DIR}/include
)

find_library(LIBPCAP_LIBRARY
    NAMES pcap
    HINTS ${LIBPCAP_ROOT_DIR}/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(libpcap DEFAULT_MSG
    LIBPCAP_INCLUDE_DIR
    LIBPCAP_LIBRARY
)

mark_as_advanced(
    LIBPCAP_ROOT_DIR
    LIBPCAP_INCLUDE_DIR
    LIBPCAP_LIBRARY
)
