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

# Utility rule file for Make_static_deterministic.

# Include the progress variables for this target.
include CMakeFiles/Make_static_deterministic.dir/progress.make

CMakeFiles/Make_static_deterministic: deterministic.run


deterministic.run: lib/libRaptorQ.0.a
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/blue/Downloads/libRaptorQ-0.1.X/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Removing creation date from library..."
	./make_deterministic /home/blue/Downloads/libRaptorQ-0.1.X/build/lib/libRaptorQ.0.a

Make_static_deterministic: CMakeFiles/Make_static_deterministic
Make_static_deterministic: deterministic.run
Make_static_deterministic: CMakeFiles/Make_static_deterministic.dir/build.make

.PHONY : Make_static_deterministic

# Rule to build all files generated by this target.
CMakeFiles/Make_static_deterministic.dir/build: Make_static_deterministic

.PHONY : CMakeFiles/Make_static_deterministic.dir/build

CMakeFiles/Make_static_deterministic.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/Make_static_deterministic.dir/cmake_clean.cmake
.PHONY : CMakeFiles/Make_static_deterministic.dir/clean

CMakeFiles/Make_static_deterministic.dir/depend:
	cd /home/blue/Downloads/libRaptorQ-0.1.X/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/blue/Downloads/libRaptorQ-0.1.X /home/blue/Downloads/libRaptorQ-0.1.X /home/blue/Downloads/libRaptorQ-0.1.X/build /home/blue/Downloads/libRaptorQ-0.1.X/build /home/blue/Downloads/libRaptorQ-0.1.X/build/CMakeFiles/Make_static_deterministic.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/Make_static_deterministic.dir/depend

