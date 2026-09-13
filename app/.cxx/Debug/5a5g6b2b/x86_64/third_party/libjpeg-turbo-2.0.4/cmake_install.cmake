# Install script for directory: /home/cocomelonc/research/purrview/app/src/main/cpp/third_party/libjpeg-turbo-2.0.4

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
    set(CMAKE_INSTALL_CONFIG_NAME "Debug")
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

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "TRUE")
endif()

# Set default install directory permissions.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/home/cocomelonc/Android/Sdk/ndk/27.3.13750724/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-objdump")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY FILES "/home/cocomelonc/research/purrview/app/.cxx/Debug/5a5g6b2b/x86_64/third_party/libjpeg-turbo-2.0.4/libjpeg.a")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE PROGRAM RENAME "cjpeg" FILES "/home/cocomelonc/research/purrview/app/.cxx/Debug/5a5g6b2b/x86_64/third_party/libjpeg-turbo-2.0.4/cjpeg-static")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE PROGRAM RENAME "djpeg" FILES "/home/cocomelonc/research/purrview/app/.cxx/Debug/5a5g6b2b/x86_64/third_party/libjpeg-turbo-2.0.4/djpeg-static")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE PROGRAM RENAME "jpegtran" FILES "/home/cocomelonc/research/purrview/app/.cxx/Debug/5a5g6b2b/x86_64/third_party/libjpeg-turbo-2.0.4/jpegtran-static")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/rdjpgcom" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/rdjpgcom")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/rdjpgcom"
         RPATH "")
  endif()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE EXECUTABLE FILES "/home/cocomelonc/research/purrview/app/build/intermediates/cxx/Debug/5a5g6b2b/obj/x86_64/rdjpgcom")
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/rdjpgcom" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/rdjpgcom")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/home/cocomelonc/Android/Sdk/ndk/27.3.13750724/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip" "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/rdjpgcom")
    endif()
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/wrjpgcom" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/wrjpgcom")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/wrjpgcom"
         RPATH "")
  endif()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE EXECUTABLE FILES "/home/cocomelonc/research/purrview/app/build/intermediates/cxx/Debug/5a5g6b2b/obj/x86_64/wrjpgcom")
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/wrjpgcom" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/wrjpgcom")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/home/cocomelonc/Android/Sdk/ndk/27.3.13750724/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip" "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/wrjpgcom")
    endif()
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/share/doc/libjpeg-turbo" TYPE FILE FILES
    "/home/cocomelonc/research/purrview/app/src/main/cpp/third_party/libjpeg-turbo-2.0.4/README.ijg"
    "/home/cocomelonc/research/purrview/app/src/main/cpp/third_party/libjpeg-turbo-2.0.4/README.md"
    "/home/cocomelonc/research/purrview/app/src/main/cpp/third_party/libjpeg-turbo-2.0.4/example.txt"
    "/home/cocomelonc/research/purrview/app/src/main/cpp/third_party/libjpeg-turbo-2.0.4/tjexample.c"
    "/home/cocomelonc/research/purrview/app/src/main/cpp/third_party/libjpeg-turbo-2.0.4/libjpeg.txt"
    "/home/cocomelonc/research/purrview/app/src/main/cpp/third_party/libjpeg-turbo-2.0.4/structure.txt"
    "/home/cocomelonc/research/purrview/app/src/main/cpp/third_party/libjpeg-turbo-2.0.4/usage.txt"
    "/home/cocomelonc/research/purrview/app/src/main/cpp/third_party/libjpeg-turbo-2.0.4/wizard.txt"
    "/home/cocomelonc/research/purrview/app/src/main/cpp/third_party/libjpeg-turbo-2.0.4/LICENSE.md"
    )
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/share/man/man1" TYPE FILE FILES
    "/home/cocomelonc/research/purrview/app/src/main/cpp/third_party/libjpeg-turbo-2.0.4/cjpeg.1"
    "/home/cocomelonc/research/purrview/app/src/main/cpp/third_party/libjpeg-turbo-2.0.4/djpeg.1"
    "/home/cocomelonc/research/purrview/app/src/main/cpp/third_party/libjpeg-turbo-2.0.4/jpegtran.1"
    "/home/cocomelonc/research/purrview/app/src/main/cpp/third_party/libjpeg-turbo-2.0.4/rdjpgcom.1"
    "/home/cocomelonc/research/purrview/app/src/main/cpp/third_party/libjpeg-turbo-2.0.4/wrjpgcom.1"
    )
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/pkgconfig" TYPE FILE FILES
    "/home/cocomelonc/research/purrview/app/.cxx/Debug/5a5g6b2b/x86_64/third_party/libjpeg-turbo-2.0.4/pkgscripts/libjpeg.pc"
    "/home/cocomelonc/research/purrview/app/.cxx/Debug/5a5g6b2b/x86_64/third_party/libjpeg-turbo-2.0.4/pkgscripts/libturbojpeg.pc"
    )
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include" TYPE FILE FILES
    "/home/cocomelonc/research/purrview/app/.cxx/Debug/5a5g6b2b/x86_64/third_party/libjpeg-turbo-2.0.4/jconfig.h"
    "/home/cocomelonc/research/purrview/app/src/main/cpp/third_party/libjpeg-turbo-2.0.4/jerror.h"
    "/home/cocomelonc/research/purrview/app/src/main/cpp/third_party/libjpeg-turbo-2.0.4/jmorecfg.h"
    "/home/cocomelonc/research/purrview/app/src/main/cpp/third_party/libjpeg-turbo-2.0.4/jpeglib.h"
    )
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("/home/cocomelonc/research/purrview/app/.cxx/Debug/5a5g6b2b/x86_64/third_party/libjpeg-turbo-2.0.4/md5/cmake_install.cmake")

endif()

