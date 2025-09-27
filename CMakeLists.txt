cmake_minimum_required(VERSION 3.27)
option(MACOS "Enable building for macOS" OFF)
project(x8A4 C)

set(CMAKE_C_STANDARD 17)
string(COMPARE EQUAL "${CMAKE_OSX_ARCHITECTURES}" "" arch_not_set)
if(NOT DEFINED CMAKE_OSX_ARCHITECTURES OR arch_not_set)
    set(CMAKE_OSX_ARCHITECTURES arm64)
endif()
set(CMAKE_OSX_DEPLOYMENT_TARGET "")

if(MACOS)
    set(ENT mac_ent.plist)
    set(BUILD_SDK macosx)
else()
    set(ENT tfp0.plist)
    set(BUILD_SDK iphoneos)
endif()

find_program(LDID ldid2)
if(NOT LDID)
    find_program(LDID ldid)
    if(NOT LDID)
        message(FATAL_ERROR "Please install Procursus ldid before building! (https://github.com/ProcursusTeam/ldid)")
    endif()
endif()

find_program(XCRUN xcrun)
if(XCRUN)
execute_process(COMMAND ${XCRUN} --sdk ${BUILD_SDK} --show-sdk-path
        OUTPUT_VARIABLE CMAKE_OSX_SYSROOT
        ERROR_QUIET
        OUTPUT_STRIP_TRAILING_WHITESPACE)
endif()

find_program(GIT git)
if(GIT)
    if(NOT DEFINED VERSION_COMMIT_COUNT)
        execute_process(COMMAND ${GIT} rev-list --count HEAD WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}" OUTPUT_VARIABLE VERSION_COMMIT_COUNT ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)
    endif()
    if(NOT DEFINED VERSION_COMMIT_SHA)
        execute_process(COMMAND ${GIT} rev-parse HEAD WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}" OUTPUT_VARIABLE VERSION_COMMIT_SHA ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)
    endif()
else()
    set(VERSION_COMMIT_COUNT "0")
    set(VERSION_COMMIT_SHA "unknown")
endif()

add_library(x8A4 STATIC SHARED x8A4.c
        Logger/logger.c
        Include/x8A4/Logger/logger.h
        Kernel/slide.c
        Include/x8A4/Kernel/slide.h
        Services/services.c
        Include/x8A4/Services/services.h
        Registry/registry.c
        Include/x8A4/Registry/registry.h
        Kernel/kernel.c
        Include/x8A4/Kernel/kernel.h
        Kernel/offsets.c
        Include/x8A4/Kernel/offsets.h
        Kernel/kpf.c
        Include/x8A4/Kernel/kpf.h
        Kernel/osobject.c
        Include/x8A4/Kernel/osobject.h
        Kernel/nvram.c
        Include/x8A4/Kernel/nvram.h)

target_include_directories(x8A4 PRIVATE
        "${CMAKE_SOURCE_DIR}/Include/choma"
        "${CMAKE_SOURCE_DIR}/Include")

set(RPATH "/var/jb/usr/lib")
set(RPATH2 "/usr/lib")
set(RPATH3 "/opt/procursus/lib")
set(RPATH4 "/usr/local/lib")
set_target_properties(x8A4
        PROPERTIES
#        LINK_FLAGS "-Wl,-rpath,${RPATH} -Wl,-rpath,${RPATH2} -L/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/15.0.0/lib/darwin/ -lclang_rt.asan_abi_ios -lclang_rt.asan_ios_dynamic")
        LINK_FLAGS "-Wl,-rpath,${RPATH} -Wl,-rpath,${RPATH2} -Wl,-rpath,${RPATH3} -Wl,-rpath,${RPATH4} ")
set_target_properties(x8A4
        PROPERTIES
#        COMPILE_FLAGS "-Wall -Werror -fsanitize=address -fsanitize-address-use-after-scope -fno-omit-frame-pointer")
        COMPILE_FLAGS "-Wall -Werror -Wno-deprecated-declarations")

set(SOVERSION 1)
set_target_properties(x8A4 PROPERTIES SOVERSION ${SOVERSION})


target_link_directories(x8A4 PRIVATE
        "${CMAKE_SOURCE_DIR}/Lib")

target_link_libraries(x8A4
        "-framework CoreFoundation"
        "-framework IOKit"
        krw
        compression
        choma
        XPF)

add_executable(x8A4_CLI x8A4_CLI.c)

add_definitions(
        -DVERSION_COMMIT_COUNT="${VERSION_COMMIT_COUNT}"
        -DVERSION_COMMIT_SHA="${VERSION_COMMIT_SHA}"
        -DSOVERSION=${SOVERSION}
        )
if(DEFINED RELEASE)
    add_definitions(-DRELEASE="1")
endif()

target_include_directories(x8A4_CLI PRIVATE "${CMAKE_SOURCE_DIR}/Include")

set(RPATH "/var/jb/usr/lib")
set(RPATH2 "/usr/lib")
set(RPATH3 "/opt/procursus/lib")
set(RPATH4 "/usr/local/lib")
set_target_properties(x8A4_CLI
        PROPERTIES
#        LINK_FLAGS "-Wl,-rpath,${RPATH} -Wl,-rpath,${RPATH2} -L/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/15.0.0/lib/darwin -lclang_rt.asan_abi_ios -lclang_rt.asan_ios_dynamic")
        LINK_FLAGS "-Wl,-rpath,${RPATH} -Wl,-rpath,${RPATH2} -Wl,-rpath,${RPATH3} -Wl,-rpath,${RPATH4} ")
set_target_properties(x8A4_CLI
        PROPERTIES
#        COMPILE_FLAGS "-Wall -Werror -fsanitize=address -fsanitize-address-use-after-scope -fno-omit-frame-pointer")
        COMPILE_FLAGS "-Wall -Werror")


target_link_directories(x8A4_CLI PRIVATE
        "${CMAKE_SOURCE_DIR}/Lib")

target_link_libraries(x8A4_CLI
        "x8A4")

add_custom_command(TARGET x8A4 POST_BUILD
        COMMAND ${LDID} -S -Hsha256 -Cadhoc ${CMAKE_CURRENT_BINARY_DIR}/libx8A4.${SOVERSION}.dylib
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Signing libx8A4.${SOVERSION}.dylib..."
)

add_custom_command(TARGET x8A4_CLI POST_BUILD
        COMMAND ${LDID} -S${ENT} -Hsha256 -Cadhoc ${CMAKE_CURRENT_BINARY_DIR}/x8A4_CLI
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Signing x8A4_CLI"
)
#
#SET(CMAKE_EXPORT_COMPILE_COMMANDS 1)
#get_cmake_property(_variableNames VARIABLES)
#list (SORT _variableNames)
#foreach (_variableName ${_variableNames})
#    message(STATUS "${_variableName}=${${_variableName}}")
#endforeach()