# Cryptohaze makefile include.
# Many bits are direct from the nVidia makefiles.

# detect OS
OSUPPER = $(shell uname -s 2>/dev/null | tr [:lower:] [:upper:])
OSLOWER = $(shell uname -s 2>/dev/null | tr [:upper:] [:lower:])

# 'linux' is output for Linux system, 'darwin' for OS X
DARWIN = $(strip $(findstring DARWIN, $(OSUPPER)))
ifneq ($(DARWIN),)
	SNOWLEOPARD = $(strip $(findstring 10.6, $(shell egrep "<string>10\.6" /System/Library/CoreServices/SystemVersion.plist)))
endif


# Set the root CUDA install path - this should be the same on OS X & Linux
CUDA_INSTALL_PATH ?= /usr/local/cuda

# Get the CUDA SDK root - this will differ on Linux & OS X.
ifneq ($(DARWIN),)
	# Darwin build - /Developer/GPU Computing/
	CUDA_SDK_INSTALL_PATH ?= /Developer/GPU\ Computing
	# And I keep my boost install in /Developer/
	INCLUDES += -I /Developer/boost_1_47_0
else
	# Linux - assume home directory
	CUDA_SDK_INSTALL_PATH ?= /home/ubuntu/NVIDIA_GPU_Computing_SDK
endif

# Pieces pulled from nvidia makefile

# Set the include root only if it is not set.
INCLUDE_ROOT ?= ./

# check if verbose
ifeq ($(verbose), 1)
	VERBOSE :=
else
	VERBOSE := @
endif

# check if 32-bit build (why?)
ifeq ($(32bit), 1)
	BUILD64 := 0
else
	BUILD64 := 1
endif

# Check for static boost linking
ifeq ($(staticboost), 1)
	STATIC_BOOST := 1
else
	STATIC_BOOST := 0
endif


# Some basic compiler setup - make debug code, we will strip later.
NVCC       := $(CUDA_INSTALL_PATH)/bin/nvcc
CXX        := g++ -g -fPIC
CC         := gcc -g -fPIC
LINK       := LD_RUN_PATH=./lib64 g++ -fPIC 
#***changed paths to my current pwd for project
INCLUDES  += -I. -I$(CUDA_INSTALL_PATH)/include -I$(COMMONDIR)/inc -I$(SHAREDDIR)/inc \
        -I$(INCLUDE_ROOT)/inc \
        -I/usr/lib \
        -I/usr/include/boost \
	-I/home/ubuntu/boost2/ \
	-I/home/ubuntu/NVIDIA_GPU_Computing_SDK/C/common/inc \
	-I/home/ubuntu/NVIDIA_GPU_Computing_SDK/C/lib \
        -I$(INCLUDE_ROOT) -I $(CUDA_SDK_INSTALL_PATH)/OpenCL/common/inc

GENCODE_SM10 := -gencode=arch=compute_10,code=\"sm_10,compute_10\"
GENCODE_SM20 := -gencode=arch=compute_20,code=\"sm_20,compute_20\"

#\"\"

ifeq "$(BUILD64)" "0"
    LIB_ARCH        = i386
    CUDPPLIB_SUFFIX = i386
    NVCCFLAGS      += -m32
    ifneq ($(DARWIN),)
       CXX_ARCH_FLAGS += -arch i386
    else
       CXX_ARCH_FLAGS += -m32
    endif
else
    LIB_ARCH        = x86_64
    CUDPPLIB_SUFFIX = x86_64
    NVCCFLAGS      += -m64 
    ifneq ($(DARWIN),)
       CXX_ARCH_FLAGS += -arch x86_64
    else
       CXX_ARCH_FLAGS += -m64
    endif
endif
#****more library additions are needed here*****
ifeq "$(BUILD64)" "1"
    # If this is a 64-bit build, set the appropriate libraries.
    ifneq ($(DARWIN),)
        # Darwin does not use lib64
	LIB       := -L$(CUDA_INSTALL_PATH)/lib -L$(CUDA_SDK_INSTALL_PATH)/C/lib
    else
        # Linux uses lib64
	LIB       := -L$(CUDA_INSTALL_PATH)/lib64 -L $(CUDA_SDK_INSTALL_PATH)/C/lib \
	 -L$(CUDA_INSTALL_PATH)/lib   -L /home/ubuntu/boost2/stage/lib \
	 -L$(CUDA_INSTALL_PATH)/lib64 -L /usr/local/cuda/lib64 \
	 -L$(CUDA_INSTALL_PATH)/lib   -L /home/ubuntu/NVIDIA_GPU_Computing_SDK/C/lib \
         -L$(CUDA_INSTALL_PATH)/lib   -L /usr/lib 	
    endif
else
	LIB       := -L$(CUDA_INSTALL_PATH)/lib -L $(CUDA_SDK_INSTALL_PATH)/C/lib \
	-L$(CUDA_INSTALL_PATH)/lib -L /home/ubuntu/boost2/stage/lib \
        -L$(CUDA_INSTALL_PATH)/lib -L /usr/local/cuda/lib \
	-L$(CUDA_INSTALL_PATH)/lib -L /home/ubuntu/NVIDIA_GPU_Computing_SDK/C/lib \
	-L$(CUDA_INSTALL_PATH)/lib   -L /usr/lib
endif


INCLUDES  += -I. -I./inc -I$(CUDA_INSTALL_PATH)/include -I $(CUDA_SDK_INSTALL_PATH)/C/common/inc \
 -I $(CUDA_SDK_INSTALL_PATH)/shared/inc

# Warning flags
CXXWARN_FLAGS := \
	-W -Wall \
	-Wimplicit \
	-Wswitch \
	-Wformat \
	-Wchar-subscripts \
	-Wparentheses \
	-Wmultichar \
	-Wtrigraphs \
	-Wpointer-arith \
	-Wcast-align \
	-Wreturn-type \
	-Wno-unused-function \
	$(SPACE)

CWARN_FLAGS := $(CXXWARN_FLAGS) \
	-Wstrict-prototypes \
	-Wmissing-prototypes \
	-Wmissing-declarations \
	-Wnested-externs \
	-Wmain \


CXXFLAGS  += $(CXXWARN_FLAGS) $(CXX_ARCH_FLAGS)
CFLAGS    += $(CWARN_FLAGS) $(CXX_ARCH_FLAGS)
LINKFLAGS +=
LINK      += $(LINKFLAGS) $(CXX_ARCH_FLAGS)


COMMONFLAGS += $(INCLUDES) -DUNIX

NVCCFLAGS += --ptxas-options=-v

# Debug/release configuration
ifeq ($(dbg),1)
	COMMONFLAGS += -g
	NVCCFLAGS   += -D_DEBUG
	CXXFLAGS    += -D_DEBUG
	CFLAGS      += -D_DEBUG
	BINSUBDIR   := debug
	LIBSUFFIX   := D
else
	COMMONFLAGS += -O2
	BINSUBDIR   := release
	LIBSUFFIX   :=
	NVCCFLAGS   += --compiler-options -fno-strict-aliasing
	CXXFLAGS    += -fno-strict-aliasing
	CFLAGS      += -fno-strict-aliasing
endif

# Add common flags
NVCCFLAGS += $(COMMONFLAGS)
CXXFLAGS  += $(COMMONFLAGS)
CFLAGS    += $(COMMONFLAGS)

OBJDIR = objs
