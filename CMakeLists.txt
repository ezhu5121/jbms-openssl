cmake_minimum_required(VERSION 2.8)
project(jbms-openssl)
find_package(PkgConfig REQUIRED)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

#add_definitions(-DOPENSSL_API_COMPAT=0x10000000L)

#### Dependencies
find_package(jbms-utility REQUIRED)
find_package(jbms-array_view REQUIRED)
#find_package(OpenSSL 1.0 EXACT REQUIRED)
set(ENV{PKG_CONFIG_PATH}  "/usr/local/ssl/lib/pkgconfig")
pkg_check_modules(OPENSSL REQUIRED openssl)

#### Includes
set (${PROJECT_NAME}_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src")
set (${PROJECT_NAME}_INCLUDE_DIRS
  "${${PROJECT_NAME}_INCLUDE_DIR}"
  ${OPENSSL_INCLUDEDIR}
  ${jbms-utility_INCLUDE_DIRS}
  ${jbms-array_view_INCLUDE_DIRS} )


#### Build tests
include_directories(${${PROJECT_NAME}_INCLUDE_DIRS})

#### Install headers
set(header_install_dir "include/${PROJECT_NAME}")
install(DIRECTORY "${${PROJECT_NAME}_INCLUDE_DIR}" DESTINATION "${header_install_dir}")

#### Generate CMake modules for importing this package
include(jbms-WriteConfig)


write_config_file(
  TEMPLATE "${CMAKE_CURRENT_SOURCE_DIR}/config.cmake.in"
  PATH_VARS ${PROJECT_NAME}_INCLUDE_DIR
  REL_PATH "${header_install_dir}" )
