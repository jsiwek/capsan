# Tries to locate OpenSSL header and libraries.
#
# Usage:
#
#     find_package(openssl)
#
#     OPENSSL_ROOT_DIR may be defined beforehand to hint at install location.
#
# Variables defined after calling:
#
#     OPENSSL_FOUND          - whether OpenSSL installation is located
#     OPENSSL_INCLUDE_DIR    - path to OpenSSL headers
#     OPENSSL_LIBRARIES      - paths of OpenSSL libraries
#     OPENSSL_SSL_LIBRARY    - path of OpenSSL ssl library
#     OPENSSL_CRYPTO_LIBRARY - path of OpenSSL crypto library

find_path(OPENSSL_ROOT_DIR
    NAMES include/openssl/ssl.h
)

find_path(OPENSSL_INCLUDE_DIR
    NAMES openssl/ssl.h
    HINTS ${OPENSSL_ROOT_DIR}/include
)

find_library(OPENSSL_SSL_LIBRARY
    NAMES ssl
    HINTS ${OPENSSL_ROOT_DIR}/lib
)

find_library(OPENSSL_CRYPTO_LIBRARY
    NAMES crypto
    HINTS ${OPENSSL_ROOT_DIR}/lib
)

set(OPENSSL_LIBRARIES ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY}
    CACHE STRING "OpenSSL SSL and crypto libraries" FORCE
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(openssl DEFAULT_MSG
    OPENSSL_INCLUDE_DIR
    OPENSSL_SSL_LIBRARY
    OPENSSL_CRYPTO_LIBRARY
)

mark_as_advanced(
    OPENSSL_ROOT_DIR
    OPENSSL_INCLUDE_DIR
    OPENSSL_SSL_LIBRARY
    OPENSSL_CRYPTO_LIBRARY
    OPENSSL_LIBRARIES
)
