cmake_minimum_required(VERSION 3.10)

# Set the project name and version
project(Rule VERSION 1.0)
add_definitions(-D_WIN32_WINNT=0x0A00)

# Specify the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Add an executable
add_executable(Rule main.cpp)

# Find and link Crow (assuming it's installed as a system package)
# Crow is typically used as a header-only library, so you may need to manually specify its location
# or include it in your project directly if it's not part of the system package
target_link_libraries(Rule ws2_32)
find_path(CROW_INCLUDE_DIRS "crow.h")
if(CROW_INCLUDE_DIRS)
    target_include_directories(Rule PRIVATE ${CROW_INCLUDE_DIRS})
else()
    message(FATAL_ERROR "Could not find Crow headers. Ensure they are installed or specify the path manually.")
endif()

# Find and link YAML-CPP
find_package(yaml-cpp REQUIRED)
if(yaml-cpp_FOUND)
    target_link_libraries(Rule yaml-cpp::yaml-cpp)
else()
    message(FATAL_ERROR "YAML-CPP not found. Please install it using your package manager.")
endif()

find_package(OpenSSL REQUIRED)
target_link_libraries(Rule OpenSSL::SSL OpenSSL::Crypto)
# Add httplib as a header-only library


target_include_directories(Rule PRIVATE ${CMAKE_SOURCE_DIR})


# Define other necessary compile options
target_compile_options(Rule PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /permissive->
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
)