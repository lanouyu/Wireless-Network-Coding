# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.5

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/blue/Downloads/libRaptorQ-0.1.X

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/blue/Downloads/libRaptorQ-0.1.X/build

# Include any dependencies generated for this target.
include CMakeFiles/libRaptorQ-test.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/libRaptorQ-test.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/libRaptorQ-test.dir/flags.make

CMakeFiles/libRaptorQ-test.dir/test/rfc_test.cpp.o: CMakeFiles/libRaptorQ-test.dir/flags.make
CMakeFiles/libRaptorQ-test.dir/test/rfc_test.cpp.o: ../test/rfc_test.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/blue/Downloads/libRaptorQ-0.1.X/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/libRaptorQ-test.dir/test/rfc_test.cpp.o"
	/usr/bin/c++   $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/libRaptorQ-test.dir/test/rfc_test.cpp.o -c /home/blue/Downloads/libRaptorQ-0.1.X/test/rfc_test.cpp

CMakeFiles/libRaptorQ-test.dir/test/rfc_test.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/libRaptorQ-test.dir/test/rfc_test.cpp.i"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/blue/Downloads/libRaptorQ-0.1.X/test/rfc_test.cpp > CMakeFiles/libRaptorQ-test.dir/test/rfc_test.cpp.i

CMakeFiles/libRaptorQ-test.dir/test/rfc_test.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/libRaptorQ-test.dir/test/rfc_test.cpp.s"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/blue/Downloads/libRaptorQ-0.1.X/test/rfc_test.cpp -o CMakeFiles/libRaptorQ-test.dir/test/rfc_test.cpp.s

CMakeFiles/libRaptorQ-test.dir/test/rfc_test.cpp.o.requires:

.PHONY : CMakeFiles/libRaptorQ-test.dir/test/rfc_test.cpp.o.requires

CMakeFiles/libRaptorQ-test.dir/test/rfc_test.cpp.o.provides: CMakeFiles/libRaptorQ-test.dir/test/rfc_test.cpp.o.requires
	$(MAKE) -f CMakeFiles/libRaptorQ-test.dir/build.make CMakeFiles/libRaptorQ-test.dir/test/rfc_test.cpp.o.provides.build
.PHONY : CMakeFiles/libRaptorQ-test.dir/test/rfc_test.cpp.o.provides

CMakeFiles/libRaptorQ-test.dir/test/rfc_test.cpp.o.provides.build: CMakeFiles/libRaptorQ-test.dir/test/rfc_test.cpp.o


# Object files for target libRaptorQ-test
libRaptorQ__test_OBJECTS = \
"CMakeFiles/libRaptorQ-test.dir/test/rfc_test.cpp.o"

# External object files for target libRaptorQ-test
libRaptorQ__test_EXTERNAL_OBJECTS =

libRaptorQ-test: CMakeFiles/libRaptorQ-test.dir/test/rfc_test.cpp.o
libRaptorQ-test: CMakeFiles/libRaptorQ-test.dir/build.make
libRaptorQ-test: lib/libRaptorQ.so.0.1.10
libRaptorQ-test: CMakeFiles/libRaptorQ-test.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/blue/Downloads/libRaptorQ-0.1.X/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable libRaptorQ-test"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/libRaptorQ-test.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/libRaptorQ-test.dir/build: libRaptorQ-test

.PHONY : CMakeFiles/libRaptorQ-test.dir/build

CMakeFiles/libRaptorQ-test.dir/requires: CMakeFiles/libRaptorQ-test.dir/test/rfc_test.cpp.o.requires

.PHONY : CMakeFiles/libRaptorQ-test.dir/requires

CMakeFiles/libRaptorQ-test.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/libRaptorQ-test.dir/cmake_clean.cmake
.PHONY : CMakeFiles/libRaptorQ-test.dir/clean

CMakeFiles/libRaptorQ-test.dir/depend:
	cd /home/blue/Downloads/libRaptorQ-0.1.X/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/blue/Downloads/libRaptorQ-0.1.X /home/blue/Downloads/libRaptorQ-0.1.X /home/blue/Downloads/libRaptorQ-0.1.X/build /home/blue/Downloads/libRaptorQ-0.1.X/build /home/blue/Downloads/libRaptorQ-0.1.X/build/CMakeFiles/libRaptorQ-test.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/libRaptorQ-test.dir/depend
