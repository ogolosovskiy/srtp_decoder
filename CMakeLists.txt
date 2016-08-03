cmake_minimum_required(VERSION 3.0)
project(example_project)

###############################################################################
## file globbing ##############################################################
###############################################################################

file(GLOB_RECURSE sources      src/*.cpp src/*.h)

###############################################################################
## target definitions #########################################################
###############################################################################

add_executable(srtp_decoder ${sources})
target_compile_options(srtp_decoder PUBLIC -std=c++1y -Wall -Wfloat-conversion)

# this lets me include files relative to the root src dir with a <> pair
target_include_directories(srtp_decoder PUBLIC src)

###############################################################################
## dependencies ###############################################################
###############################################################################


#################### PCAP ###################

if (PCAP_INCLUDE_DIR)
  set(PCAP_FOUND TRUE)
else (PCAP_INCLUDE_DIR)

  find_program(PCAP_CONFIG_EXECUTABLE  NAMES pcap-config PATHS)
  
  if (PCAP_CONFIG_EXECUTABLE)
      MESSAGE(STATUS "pcap-config found at: ${PCAP_CONFIG_EXECUTABLE}")
  else (PCAP_CONFIG_EXECUTABLE)
      MESSAGE(FATAL_ERROR "pcap-config is required, but not found! Do you have libpcap >= 1.0?")
  endif (PCAP_CONFIG_EXECUTABLE)

  exec_program(${PCAP_CONFIG_EXECUTABLE} ARGS --cflags OUTPUT_VARIABLE PCAP_CFLAGS )
  exec_program(${PCAP_CONFIG_EXECUTABLE} ARGS --libs   OUTPUT_VARIABLE PCAP_LIBRARIES )
  
  MESSAGE(STATUS "libpcap cflas: " ${PCAP_CFLAGS})
  MESSAGE(STATUS "libpcap libraries: " ${PCAP_LIBRARIES})
  
  set(PCAP_FOUND TRUE)
endif (PCAP_INCLUDE_DIR)

if (PCAP_FOUND)
   target_link_libraries(example PUBLIC
   	${PCAP_LIBRARIES}
   )
endif (PCAP_FOUND)

################## SRTP ######################

find_path(SRTP_INCLUDE_DIRS
	NAMES srtp/srtp.h
	PATH_SUFFIXES include
)

if(NOT  SRTP_INCLUDE_DIRS)
	MESSAGE(FATAL_ERROR "SRTP_INCLUDE_DIRS not found")
else()
	MESSAGE(STATUS "libsrtp found at: ${SRTP_INCLUDE_DIRS}")
endif()

if(SRTP_INCLUDE_DIRS)
	set(HAVE_SRTP_SRTP_H 1)
endif()

find_library(SRTP_LIBRARIES
	NAMES srtp
	PATH_SUFFIXES bin lib)

if(NOT SRTP_LIBRARIES)
	MESSAGE(FATAL_ERROR "SRTP_LIBRARIES not found")
else()
	MESSAGE(STATUS "libsrtp libs found at: ${SRTP_LIBRARIES}")
endif()

if (SRTP_LIBRARIES)
   target_link_libraries(example PUBLIC
        ${SRTP_LIBRARIES}
   )
endif (SRTP_LIBRARIES)

include_directories(${SRTP_INCLUDE_DIRS})

###############################################################################
## packaging ##################################################################
###############################################################################

# all install commands get the same destination. this allows us to use paths
# relative to the executable.
install(TARGETS example DESTINATION example_destination)
# this is basically a repeat of the file copy instruction that copies the
# resources in the build directory, but here we tell cmake that we want it
# in the package
install(DIRECTORY resources DESTINATION example_destination)

# now comse everything we need, to create a package
# there are a lot more variables you can set, and some
# you need to set for some package types, but we want to
# be minimal here
set(CPACK_PACKAGE_NAME "srtp_decoder")
set(CPACK_PACKAGE_VERSION "1.0.0")

# we don't want to split our program up into several things
set(CPACK_MONOLITHIC_INSTALL 1)

# This must be last
include(CPack)
