project(aesfs)
cmake_minimum_required(VERSION 2.8.8)

set(CMAKE_VERBOSE_MAKEFILE on)

### libcryptr ###

add_library(cryptr SHARED ./cryptr.cpp)

find_package(PythonLibs 2.7.12 REQUIRED)
if(PythonLibs_FOUND)
    include_directories("${PYTHON_INCLUDE_DIRS}")
    target_link_libraries(cryptr ${PYTHON_LIBRARIES})
endif()

find_package(Boost REQUIRED)
if(Boost_FOUND)
    include_directories("${Boost_INCLUDE_DIRS}")
    set(Boost_USE_STATIC_LIBS OFF)
    set(Boost_USE_MULTITHREADED ON)
    set(Boost_USE_STATIC_RUNTIME OFF)
    if(PYTHONLIBS_VERSION_STRING MATCHES "^2*")
        set(Boost_COMPONENTS python)
    else()
        set(Boost_COMPONENTS python3)
    endif()
    find_package(Boost REQUIRED COMPONENTS ${Boost_COMPONENTS})
    target_link_libraries(cryptr ${Boost_LIBRARIES})
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
find_package(CryptoPP REQUIRED)
if(CRYPTOPP_FOUND)
    target_link_libraries(cryptr ${CRYPTOPP_LIBRARIES} pthread)
endif()

### aesfs ###

aux_source_directory(. SRC_LIST)
list(REMOVE_ITEM SRC_LIST "./cryptr.cpp")

add_executable(${PROJECT_NAME} ${SRC_LIST})

find_package(Boost REQUIRED)
if(Boost_FOUND)
    include_directories("${Boost_INCLUDE_DIRS}")
    set(Boost_USE_STATIC_LIBS OFF)
    set(Boost_USE_MULTITHREADED ON)
    set(Boost_USE_STATIC_RUNTIME OFF)
    set(Boost_COMPONENTS system log)
    find_package(Boost REQUIRED COMPONENTS ${Boost_COMPONENTS})
    target_compile_options(${PROJECT_NAME} PUBLIC -DBOOST_LOG_DYN_LINK)
    target_link_libraries(${PROJECT_NAME} PUBLIC ${Boost_LIBRARIES})
endif()

find_package(PkgConfig REQUIRED)
if(PkgConfig_FOUND)
    pkg_search_module(FUSE REQUIRED fuse)

    target_compile_options(${PROJECT_NAME} PUBLIC ${FUSE_CFLAGS})
    target_link_libraries(${PROJECT_NAME} PUBLIC ${FUSE_LDFLAGS})
endif()
