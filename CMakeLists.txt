cmake_minimum_required(VERSION 3.7)

project(cmpClient)

if(NOT DEFINED CMPCLIENT_VERSION )
    set(CMPCLIENT_VERSION 0.9.1)
endif()

set(SRC_DIR ${PROJECT_SOURCE_DIR}/src)

find_package(OpenSSL REQUIRED)

include_directories(
    ${PROJECT_SOURCE_DIR}/include
    ${OpenSSL_INCLUDE_DIRS}
)

add_library(libgencmpcl SHARED
    ${SRC_DIR}/genericCMPClient.c
)

add_executable(cmpClientDemo
    ${SRC_DIR}/cmpClientDemo.c
)

target_link_libraries(cmpClientDemo
    SecUtils
    libgencmpcl
    ${OPENSSL_LIBRARIES}
    cmp
)

set_property(TARGET libgencmpcl PROPERTY C_STANDARD 90)
set_property(TARGET cmpClientDemo PROPERTY C_STANDARD 90)

set_target_properties(libgencmpcl PROPERTIES
    VERSION ${CMPCLIENT_VERSION}
)

install(TARGETS libgencmpcl
    LIBRARY
        DESTINATION lib
        COMPONENT Library
    PUBLIC_HEADER
        DESTINATION include
        COMPONENT Development
)

install(TARGETS cmpClientDemo
    RUNTIME
        DESTINATION bin
)

install(DIRECTORY creds
    DESTINATION share/cmpclient
)

if (NOT YOCTO_BUILD)
    find_package(Wget)

    if(WGET_FOUND)

        set(CRL_URL "https://ppki-playground.ct.siemens.com/ejbca/publicweb/webdist/certdist?cmd=crl&issuer=CN%3dPPKI+Playground+ECC+Root+CA+v1.0%2cOU%3dCorporate+Technology%2cOU%3dFor+internal+test+purposes+only%2cO%3dSiemens%2cC%3dDE")
        message(STATUS ${CRL_URL})

        execute_process(COMMAND ${WGET_EXECUTABLE} "--no-check-certificate" "-OPPKIPlaygroundECCRootCAv10.crl" ${CRL_URL}
            WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/creds/crls
            RESULT_VARIABLE WGET_SUBMOD_RESULT
        )

        if(NOT WGET_SUBMOD_RESULT EQUAL "0")
           message(FATAL_ERROR "wget failed with ${WGET_SUBMOD_RESULT}")
        endif()

    else()
        message(FATAL_ERROR "WGET not found please install wget...")
    endif()

add_subdirectory(cmpossl)
add_subdirectory(securityUtilities)

endif()
