cmake_minimum_required(VERSION 3.7)

project(gencmp)

if(NOT DEFINED CMPCLIENT_VERSION)
  set(CMPCLIENT_VERSION_MAJOR 2)
  set(CMPCLIENT_VERSION ${CMPCLIENT_VERSION_MAJOR}.0)
endif()
message(STATUS "generic CMP client version " ${CMPCLIENT_VERSION})

# set(CMAKE_VERBOSE_MAKEFILE ON)

# set(GIT_PROGRESS --progress) # not available for all git versions and gives lengthy output in CI runs
set(GIT_DEPTH --depth 1) # used to speed up getting submodules

if(DEFINED ENV{OPENSSL_DIR})
  set(OpenSSL_INCLUDE_DIRS $ENV{OPENSSL_DIR}/include)
  set(OPENSSL_LIBRARIES $ENV{OPENSSL_DIR}/libssl.so $ENV{OPENSSL_DIR}/libcrypto.so)
  add_definitions(-isystem ${OpenSSL_INCLUDE_DIRS})
else()
  find_package(OpenSSL REQUIRED)
endif()

set(SRC_DIR ${PROJECT_SOURCE_DIR}/src)
set(INC_DIR ${PROJECT_SOURCE_DIR}/include)
set(CMPOSSL_INC_DIR ${PROJECT_SOURCE_DIR}/cmpossl/include)

include_directories(
  ${INC_DIR}
  ${PROJECT_SOURCE_DIR}/libsecutils/include
  ${CMPOSSL_INC_DIR}
  ${CMPOSSL_INC_DIR}/cmp
  ${CMAKE_SYSROOT}/usr/include/cmp
  )
# does not work for OpenSSL 3.0+:
# add_definitions(-isystem ${CMPOSSL_INC_DIR}/cmp)
# add_definitions(-isystem ${CMAKE_SYSROOT}/usr/include/cmp)

add_library(${PROJECT_NAME} SHARED
  ${SRC_DIR}/genericCMPClient.c
)

add_executable(cmpClient
  ${SRC_DIR}/cmpClient.c
)

target_link_libraries(cmpClient
  ${OPENSSL_LIBRARIES}
  ${PROJECT_NAME}
  secutils
  cmp
)

if((CMAKE_BUILD_TYPE MATCHES Debug) AND (NOT DEFINED ENV{NDEBUG}))
  message("build mode: Debug")
  add_definitions(-g -O0)
  set(DEBUG_FLAGS -fsanitize=address -fsanitize=undefined -fno-sanitize-recover=all)
  add_definitions(${DEBUG_FLAGS})
  link_libraries(${DEBUG_FLAGS})
else()
  message("build mode: Release")
  add_definitions(-DNDEBUG=1 -O2)
endif()

add_definitions(-DCMP_STANDALONE -DDEBUG_UNUSED)
add_definitions(-DPEDANTIC -pedantic)
add_definitions(-Wall -Wextra -Wmissing-prototypes -Wstrict-prototypes
  -Wswitch -Wsign-compare -Wshadow -Wformat -Wtype-limits -Wundef)

# set_property(TARGET ${PROJECT_NAME} PROPERTY C_STANDARD 90)
# set_property(TARGET cmpClient PROPERTY C_STANDARD 90)

set_target_properties(${PROJECT_NAME} PROPERTIES
  VERSION ${CMPCLIENT_VERSION} SOVERSION ${CMPCLIENT_VERSION_MAJOR}
  PUBLIC_HEADER "${INC_DIR}/genericCMPClient.h"
)

ADD_CUSTOM_TARGET(update
  COMMAND echo "updating repo and submodules"
  COMMAND git submodule update ${GIT_PROGRESS} ${GIT_DEPTH} libsecutils cmpossl
  COMMAND git fetch
  COMMAND git rebase
)

ADD_CUSTOM_TARGET(build # just an alias
  COMMAND make all
)

install(TARGETS ${PROJECT_NAME}
  LIBRARY
    DESTINATION lib
    COMPONENT Library
  PUBLIC_HEADER
    DESTINATION include
    COMPONENT Development
)

install(TARGETS cmpClient
  RUNTIME
  DESTINATION bin
)

if (NOT YOCTO_BUILD)

  # find_package(secutils 2.0)
  if(NOT secutils_FOUND)
    if(NOT EXISTS libsecutils/CMakeLists.txt)
      message(STATUS "fetching git submodule libsecutils")
      find_package(Git)
      if(GIT_FOUND)
        execute_process(COMMAND
          git submodule update ${GIT_PROGRESS} --init ${GIT_DEPTH} libsecutils
          RESULT_VARIABLE GIT_SUBMODULE_RESULT
          )
        if(NOT GIT_SUBMODULE_RESULT EQUAL "0")
          message(FATAL_ERROR "git failed with exit code ${GIT_SUBMODULE_RESULT}")
        endif()
      else()
        message(FATAL_ERROR "Git not found; please install git.")
      endif()
    endif()
    add_subdirectory(libsecutils)
  endif()

  # find_package(cmp 2.0)
  if(NOT libcmp_FOUND)
    if(NOT EXISTS cmpossl/CMakeLists.txt)
      message(STATUS "fetching git submodule cmpossl")
      find_package(Git)
      if(GIT_FOUND)
        execute_process(COMMAND
          git submodule update ${GIT_PROGRESS} --init ${GIT_DEPTH} cmpossl
          RESULT_VARIABLE GIT_SUBMODULE_RESULT
          )
        if(NOT GIT_SUBMODULE_RESULT EQUAL "0")
          message(FATAL_ERROR "git failed with exit code ${GIT_SUBMODULE_RESULT}")
        endif()
      else()
        message(FATAL_ERROR "Git not found; please install git.")
      endif()
    endif()
    add_subdirectory(cmpossl)
  endif()

endif()
