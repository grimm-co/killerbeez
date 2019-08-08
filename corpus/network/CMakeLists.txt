cmake_minimum_required (VERSION 2.8.8)
project (network-linux)

add_executable(server-linux ${PROJECT_SOURCE_DIR}/server/server.cpp)
add_executable(client-linux ${PROJECT_SOURCE_DIR}/client/client.cpp)
