CMAKE_MINIMUM_REQUIRED ( VERSION 2.8 )
PROJECT ( cryptohaze )

SET ( CMAKE_INSTALL_PREFIX ${PROJECT_BINARY_DIR}/bin CACHE PATH "Directory to install binaries to" FORCE )

# todo - make platform independent
SET ( CH_ARCH_LIB_SUFFIX x86_64 )
SET ( CH_LIB_FOLDER linux_64 )
SET ( CH_THREAD_LIBRARIES pthread )

# Locate required libraries
#--------------------------

# Find CUDA libs/includes
FIND_PACKAGE ( CUDA )
IF ( NOT CUDA_FOUND)
    MESSAGE ( FATAL_ERROR "ERROR:  CUDA required, not found" )

ELSEIF ( ${CUDA_SDK_ROOT_DIR} STREQUAL "CUDA_SDK_ROOT_DIR-NOTFOUND" )
    # this can be set either via -DCUDA_SDK_ROOT_DIR:OPTION=/path/to/sdk
    # OR by setting the NVSDKCUDA_ROOT environment variable.  We're expecting
    # it to point to the /path/to/NVIDIA_GPU_Computing_SDK/C folder
    MESSAGE ( FATAL_ERROR "CUDA_SDK_ROOT_DIR not set, point cmake option to /path/NVIDIA_GPU_Computing_SDK/C or set NVSDKCUDA_ROOT envvar" )

ENDIF ( NOT CUDA_FOUND )

SET ( GENCODE_SM_10 -gencode=arch=compute_10,code=sm_10 -gencode=arch=compute_10,code=compute_10) 
SET ( GENCODE_SM_20 -gencode=arch=compute_20,code=sm_20 -gencode=arch=compute_20,code=compute_20) 

# Option to allow user to add additional gencode archs
SET ( CH_GENCODE_ADDITIONAL_ARCH "" CACHE STRING "Allows specification of additional NVCC gencode flags" )
SET ( CUDA_SDK_LIBRARIES libcutil_${CH_ARCH_LIB_SUFFIX}.a; )

# Find/set OpenCL headers + lib 
SET ( OPENCL_INCLUDE_DIR ${CUDA_SDK_ROOT_DIR}/../OpenCL/common/inc )
SET ( OPENCL_LIBRARIES OpenCL )

# Find boost headers/libs
SET ( BOOST_MIN_VERSION "1.48.0" )
# Force static boost libs and have it show up in CMake config 
SET ( Boost_USE_STATIC_LIBS ON CACHE BOOL "Compile against static boost" FORCE )

FIND_PACKAGE ( Boost ${BOOST_MIN_VERSION} COMPONENTS random system filesystem thread )
IF ( NOT Boost_FOUND )
    MESSAGE ( FATAL_ERROR "ERROR: Minimum version of Boost ${BOOST_MIN_VERSION} required" )
ENDIF ( NOT Boost_FOUND )

FIND_PACKAGE(CURL REQUIRED)

SET ( CURSES_NEED_NCURSES TRUE )
FIND_PACKAGE(Curses REQUIRED)

# Setup include paths and library paths
#--------------------------------------

SET ( CH_PLATFORM_LINK_DIR ${cryptohaze_SOURCE_DIR}/libs/${CH_THREAD_LIBRARIES} )

# main include dir all cryptohaze sources rely on
SET ( CH_INCLUDE_DIR ${cryptohaze_SOURCE_DIR}/inc )

# all include directories combined (boost, curses, curl, cuda, etc)
SET ( INCLUDE_DIRS 
    ${CH_INCLUDE_DIR}
    ${CUDA_INCLUDE_DIRS}
    ${CUDA_SDK_ROOT_DIR}/common/inc
    ${OPENCL_INCLUDE_DIR}
    ${Boost_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
    ${CURSES_INCLUDE_DIR}
    )

INCLUDE_DIRECTORIES ( ${INCLUDE_DIRS} )
CUDA_INCLUDE_DIRECTORIES ( ${INCLUDE_DIRS} )

SET ( CUDA_NVCC_FLAGS 
      ${CUDA_NVCC_FLAGS}
      ${GENCODE_SM_10}
      ${GENCODE_SM_20}
      ${CH_GENCODE_ADDITIONAL_ARCH}
      --compiler-options -fno-strict-aliasing

      CACHE STRING "NVCC compilier flags" FORCE
      )

LINK_DIRECTORIES (
    ${CUDA_SDK_ROOT_DIR}/lib
    #${CH_PLATFORM_LINK_DIR}  it's clashing with system libs... needs to be an option
    )

ADD_SUBDIRECTORY (
    src/
    )

