cmake_minimum_required(VERSION 2.8)
project(jbms-openssl)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)


#### Dependencies
find_package(boost-endian REQUIRED)
find_package(jbms-utility REQUIRED)
find_package(jbms-array_view REQUIRED)
find_package(OpenSSL REQUIRED)


#### Includes
set (${PROJECT_NAME}_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src")
set (${PROJECT_NAME}_INCLUDE_DIRS
  "${${PROJECT_NAME}_INCLUDE_DIR}"
  ${OPENSSL_INCLUDE_DIRS}
  ${boost-endian_INCLUDE_DIRS}
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
