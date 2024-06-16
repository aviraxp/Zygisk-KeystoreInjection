cmake_minimum_required(VERSION 3.22.1)

project(keystoreinjection)

find_package(cxx REQUIRED CONFIG)

link_libraries(log)

link_libraries(cxx::cxx)

add_library(${CMAKE_PROJECT_NAME} SHARED main.cpp)
