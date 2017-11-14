# Install script for directory: /home/blue/Downloads/libRaptorQ-0.1.X

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Release")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

if(NOT CMAKE_INSTALL_COMPONENT OR "${CMAKE_INSTALL_COMPONENT}" STREQUAL "Unspecified")
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/RaptorQ" TYPE FILE FILES
    "/home/blue/Downloads/libRaptorQ-0.1.X/src/Interleaver.hpp"
    "/home/blue/Downloads/libRaptorQ-0.1.X/src/multiplication.hpp"
    "/home/blue/Downloads/libRaptorQ-0.1.X/src/table2.hpp"
    "/home/blue/Downloads/libRaptorQ-0.1.X/src/degree.hpp"
    "/home/blue/Downloads/libRaptorQ-0.1.X/src/common.hpp"
    "/home/blue/Downloads/libRaptorQ-0.1.X/src/Encoder.hpp"
    "/home/blue/Downloads/libRaptorQ-0.1.X/src/Decoder.hpp"
    "/home/blue/Downloads/libRaptorQ-0.1.X/src/Rand.hpp"
    "/home/blue/Downloads/libRaptorQ-0.1.X/src/Precode_Matrix.hpp"
    "/home/blue/Downloads/libRaptorQ-0.1.X/src/Parameters.hpp"
    "/home/blue/Downloads/libRaptorQ-0.1.X/src/Graph.hpp"
    "/home/blue/Downloads/libRaptorQ-0.1.X/src/De_Interleaver.hpp"
    "/home/blue/Downloads/libRaptorQ-0.1.X/src/RaptorQ.hpp"
    "/home/blue/Downloads/libRaptorQ-0.1.X/src/cRaptorQ.h"
    )
endif()

if(NOT CMAKE_INSTALL_COMPONENT OR "${CMAKE_INSTALL_COMPONENT}" STREQUAL "libraries")
  foreach(file
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libRaptorQ.so.0.1.10"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libRaptorQ.so.0"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libRaptorQ.so"
      )
    if(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      file(RPATH_CHECK
           FILE "${file}"
           RPATH "")
    endif()
  endforeach()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES
    "/home/blue/Downloads/libRaptorQ-0.1.X/build/lib/libRaptorQ.so.0.1.10"
    "/home/blue/Downloads/libRaptorQ-0.1.X/build/lib/libRaptorQ.so.0"
    "/home/blue/Downloads/libRaptorQ-0.1.X/build/lib/libRaptorQ.so"
    )
  foreach(file
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libRaptorQ.so.0.1.10"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libRaptorQ.so.0"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libRaptorQ.so"
      )
    if(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      if(CMAKE_INSTALL_DO_STRIP)
        execute_process(COMMAND "/usr/bin/strip" "${file}")
      endif()
    endif()
  endforeach()
endif()

if(NOT CMAKE_INSTALL_COMPONENT OR "${CMAKE_INSTALL_COMPONENT}" STREQUAL "libraries")
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY FILES "/home/blue/Downloads/libRaptorQ-0.1.X/build/lib/libRaptorQ.0.a")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("/home/blue/Downloads/libRaptorQ-0.1.X/build/doc/cmake_install.cmake")

endif()

if(CMAKE_INSTALL_COMPONENT)
  set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INSTALL_COMPONENT}.txt")
else()
  set(CMAKE_INSTALL_MANIFEST "install_manifest.txt")
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
file(WRITE "/home/blue/Downloads/libRaptorQ-0.1.X/build/${CMAKE_INSTALL_MANIFEST}"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
