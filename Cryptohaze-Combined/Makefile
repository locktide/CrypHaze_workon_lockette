# Makefile for the entire Cryptohaze suite.

include Makefile.inc


BUILDIR = objs
TARGETDIR = binaries

TARGET    := $(TARGETDIR)/$(EXECUTABLE)
LINKLINE  = $(LINK) -o $(TARGET) $(OBJS) $(LIB)


ifeq "$(BUILD64)" "0"
	LIB_CUDA += $(LIB) -lcudart -lcutil_i386
else
	LIB_CUDA += $(LIB) -lcudart -lcutil_x86_64
endif

ifneq ($(DARWIN),)
    # Darwin libs path
    LIB_OPENCL += $(LIB) -framework OpenCL
else
    # Linux libs path
    LIB_OPENCL += $(LIB) -lOpenCL
endif


##### This section includes the various "bits" we need to build GRT utilities.

# CU files needed to generate a table.
GRT_GENERATE_TABLE_CU_FILES = GRTGenerateTableMD5.cu GRTGenerateTableNTLM.cu GRTGenerateTableSHA1.cu
GRT_GENERATE_TABLE_CU_OBJS = $(patsubst %.cu,$(BUILDIR)/%.cu.o,$(notdir $(GRT_GENERATE_TABLE_CU_FILES)))

GRT_GENERATE_TABLE_CPP_FILES = GRTGenerateTable.cpp GRTGenerateTableMD5.cpp \
  GRTGenerateTableNTLM.cpp GRTGenerateTableSHA1.cpp
GRT_GENERATE_TABLE_CPP_OBJS = $(patsubst %.cpp,$(BUILDIR)/%.cpp.o,$(notdir $(GRT_GENERATE_TABLE_CPP_FILES)))

GRTCL_GENERATE_TABLE_CPP_FILES = GRTCLGenerateTable.cpp GRTCLGenerateTableMD5.cpp \
  GRTCLGenerateTableNTLM.cpp GRTCLGenerateTableSHA1.cpp
GRTCL_GENERATE_TABLE_CPP_OBJS = $(patsubst %.cpp,$(BUILDIR)/%.cpp.o,$(notdir $(GRTCL_GENERATE_TABLE_CPP_FILES)))

GRT_TABLE_HEADER_CPP_FILES = GRTTableHeaderV1.cpp GRTTableHeaderV2.cpp \
  GRTTableHeaderVWeb.cpp GRTTableHeaderV3.cpp
GRT_TABLE_HEADER_CPP_OBJS = $(patsubst %.cpp,$(BUILDIR)/%.cpp.o,$(notdir $(GRT_TABLE_HEADER_CPP_FILES)))

GRT_TABLE_SEARCH_CPP_FILES = GRTTableSearchV1.cpp GRTTableSearchV2.cpp \
  GRTTableSearchVWeb.cpp GRTTableSearchV3.cpp mtwist.cpp
GRT_TABLE_SEARCH_CPP_OBJS = $(patsubst %.cpp,$(BUILDIR)/%.cpp.o,$(notdir $(GRT_TABLE_SEARCH_CPP_FILES)))

GRT_COMMON_CPP_FILES = GRTHashes.cpp GRTCommon.cpp GRTCharsetSingle.cpp
GRT_COMMON_CPP_OBJS = $(patsubst %.cpp,$(BUILDIR)/%.cpp.o,$(notdir $(GRT_COMMON_CPP_FILES)))

GRT_CUDA_CPP_FILES = CUDA_Common.cpp
GRT_CUDA_CPP_OBJS = $(patsubst %.cpp,$(BUILDIR)/%.cpp.o,$(notdir $(GRT_CUDA_CPP_FILES)))


GRTCL_OPENCL_CPP_FILES = GRTOpenCL.cpp GRTCLUtils.cpp
GRTCL_OPENCL_CPP_OBJS = $(patsubst %.cpp,$(BUILDIR)/%.cpp.o,$(notdir $(GRTCL_OPENCL_CPP_FILES)))

GRT_CANDIDATE_HASH_CU_FILES = GRTCandidateHashesMD5.cu GRTCandidateHashesNTLM.cu \
  GRTCandidateHashesSHA1.cu
GRT_CANDIDATE_HASH_CU_OBJS = $(patsubst %.cu,$(BUILDIR)/%.cu.o,$(notdir $(GRT_CANDIDATE_HASH_CU_FILES)))

GRT_CANDIDATE_HASH_CPP_FILES = GRTCandidateHashes.cpp GRTCandidateHashesMD5.cpp \
  GRTCandidateHashesNTLM.cpp GRTCandidateHashesSHA1.cpp
GRT_CANDIDATE_HASH_CPP_OBJS = $(patsubst %.cpp,$(BUILDIR)/%.cpp.o,$(notdir $(GRT_CANDIDATE_HASH_CPP_FILES)))

GRTCL_CANDIDATE_HASH_CPP_FILES = GRTCLCandidateHashes.cpp GRTCLCandidateHashesMD5.cpp \
  GRTCLCandidateHashesNTLM.cpp GRTCLCandidateHashesSHA1.cpp
GRTCL_CANDIDATE_HASH_CPP_OBJS = $(patsubst %.cpp,$(BUILDIR)/%.cpp.o,$(notdir $(GRTCL_CANDIDATE_HASH_CPP_FILES)))

GRT_REGENERATE_CHAIN_CU_FILES = GRTRegenerateChainsMD5.cu GRTRegenerateChainsNTLM.cu \
  GRTRegenerateChainsSHA1.cu
GRT_REGENERATE_CHAIN_CU_OBJS = $(patsubst %.cu,$(BUILDIR)/%.cu.o,$(notdir $(GRT_REGENERATE_CHAIN_CU_FILES)))

GRT_REGENERATE_CHAIN_CPP_FILES = GRTRegenerateChains.cpp GRTRegenerateChainsMD5.cpp \
  GRTRegenerateChainsNTLM.cpp GRTRegenerateChainsSHA1.cpp
GRT_REGENERATE_CHAIN_CPP_OBJS = $(patsubst %.cpp,$(BUILDIR)/%.cpp.o,$(notdir $(GRT_REGENERATE_CHAIN_CPP_FILES)))

GRTCL_REGENERATE_CHAIN_CPP_FILES = GRTCLRegenerateChains.cpp GRTCLRegenerateChainsMD5.cpp \
  GRTCLRegenerateChainsNTLM.cpp GRTCLRegenerateChainsSHA1.cpp
GRTCL_REGENERATE_CHAIN_CPP_OBJS = $(patsubst %.cpp,$(BUILDIR)/%.cpp.o,$(notdir $(GRTCL_REGENERATE_CHAIN_CPP_FILES)))

GRT_CHAINRUNNER_CPP_FILES = GRTChainRunner.cpp GRTChainRunnerMD5.cpp GRTChainRunnerNTLM.cpp \
  GRTChainRunnerSHA1.cpp
GRT_CHAINRUNNER_CPP_OBJS = $(patsubst %.cpp,$(BUILDIR)/%.cpp.o,$(notdir $(GRT_CHAINRUNNER_CPP_FILES)))

# This is the binary-specific code
GRT_CRACK_CPP_FILES = GRTCrack.cpp GRTCrackCommandLineData.cpp GRTWorkunit.cpp \
  GRTHashFilePlain.cpp GRTCrackDisplayDebug.cpp GRTCrackDisplayCurses.cpp
GRT_CRACK_CPP_OBJS = $(patsubst %.cpp,$(BUILDIR)/%.cpp.o,$(notdir $(GRT_CRACK_CPP_FILES)))

GRTCL_CRACK_CPP_FILES = GRTCLCrack.cpp GRTCLCrackCommandLineData.cpp GRTWorkunit.cpp \
  GRTHashFilePlain.cpp GRTCrackDisplayDebug.cpp GRTCrackDisplayCurses.cpp
GRTCL_CRACK_CPP_OBJS = $(patsubst %.cpp,$(BUILDIR)/%.cpp.o,$(notdir $(GRTCL_CRACK_CPP_FILES)))

GRT_GEN_CPP_FILES = GRTGen.cpp GRTGenCommandLineData.cpp
GRT_GEN_CPP_OBJS = $(patsubst %.cpp,$(BUILDIR)/%.cpp.o,$(notdir $(GRT_GEN_CPP_FILES)))

GRTCL_GEN_CPP_FILES = GRTCLGen.cpp GRTCLGenCommandLineData.cpp
GRTCL_GEN_CPP_OBJS = $(patsubst %.cpp,$(BUILDIR)/%.cpp.o,$(notdir $(GRTCL_GEN_CPP_FILES)))

GRT_ANALYZE_CPP_FILES = GRTAnalyzeTable.cpp
GRT_ANALYZE_CPP_OBJS = $(patsubst %.cpp,$(BUILDIR)/%.cpp.o,$(notdir $(GRT_ANALYZE_CPP_FILES)))

GRT_CONVERT_CPP_FILES = GRTConvertTables.cpp
GRT_CONVERT_CPP_OBJS = $(patsubst %.cpp,$(BUILDIR)/%.cpp.o,$(notdir $(GRT_CONVERT_CPP_FILES)))

GRT_BULK_CONVERT_CPP_FILES = GRTBulkConvert.cpp
GRT_BULK_CONVERT_CPP_OBJS = $(patsubst %.cpp,$(BUILDIR)/%.cpp.o,$(notdir $(GRT_BULK_CONVERT_CPP_FILES)))

GRT_INDEX_CPP_FILES = GRTMakeIndex.cpp GRTMakeIndexCommandLineData.cpp
GRT_INDEX_CPP_OBJS = $(patsubst %.cpp,$(BUILDIR)/%.cpp.o,$(notdir $(GRT_INDEX_CPP_FILES)))

GRT_MERGE_CPP_FILES = GRTMerge.cpp GRTMergeCommandLineData.cpp
GRT_MERGE_CPP_OBJS = $(patsubst %.cpp,$(BUILDIR)/%.cpp.o,$(notdir $(GRT_MERGE_CPP_FILES)))

GRT_MAKE_TESTFILE_CPP_FILES = GRTMakeTestFile.cpp
GRT_MAKE_TESTFILE_CPP_OBJS = $(patsubst %.cpp,$(BUILDIR)/%.cpp.o,$(notdir $(GRT_MAKE_TESTFILE_CPP_FILES)))

GRT_VERIFY_CPP_FILES = GRTVerifyTable.cpp
GRT_VERIFY_CPP_OBJS = $(patsubst %.cpp,$(BUILDIR)/%.cpp.o,$(notdir $(GRT_VERIFY_CPP_FILES)))

GRT_SEARCH_TABLE_CPP_FILES = GRTSearchTables.cpp
GRT_SEARCH_TABLE_CPP_OBJS = $(patsubst %.cpp,$(BUILDIR)/%.cpp.o,$(notdir $(GRT_SEARCH_TABLE_CPP_FILES)))

GRTCL_SHOW_CONFIG_CPP_FILES = GRTCLShowConfiguration.cpp
GRTCL_SHOW_CONFIG_CPP_OBJS = $(patsubst %.cpp,$(BUILDIR)/%.cpp.o,$(notdir $(GRTCL_SHOW_CONFIG_CPP_FILES)))

# Things to build the files
GRT_GEN_CUDA_OBJS = $(GRT_GENERATE_TABLE_CU_OBJS) $(GRT_GENERATE_TABLE_CPP_OBJS) \
		$(GRT_TABLE_HEADER_CPP_OBJS) $(GRT_TABLE_SEARCH_CPP_OBJS) $(GRT_COMMON_CPP_OBJS) \
		$(GRT_GEN_CPP_OBJS) $(GRT_CUDA_CPP_OBJS)

GRTCL_GEN_CUDA_OBJS = $(GRTCL_GENERATE_TABLE_CPP_OBJS) \
		$(GRT_TABLE_HEADER_CPP_OBJS) $(GRT_TABLE_SEARCH_CPP_OBJS) $(GRT_COMMON_CPP_OBJS) \
		$(GRTCL_GEN_CPP_OBJS) $(GRTCL_OPENCL_CPP_OBJS) 

ifeq "$(STATIC_BOOST)" "0"
	ARGTABLE2_LINK_LIB = -largtable2
else
	ifneq ($(DARWIN),)
	    # Darwin libs path
	    ARGTABLE2_LINK_LIB = ./libs/darwin_64/libargtable2.a
	else
	    # Linux libs path
	    ARGTABLE2_LINK_LIB = ./libs/linux_64/libargtable2.a
	endif
endif

ifeq "$(STATIC_BOOST)" "0"
	LIBCURL_LINK_LIB = -lcurl
else
	ifneq ($(DARWIN),)
	    # Darwin libs path
	    LIBCURL_LINK_LIB = ./libs/darwin_64/libcurl.a
	else
	    # Linux libs path (for now)
	    LIBCURL_LINK_LIB = ./libs/linux_64/libcurl.a -lrt
	endif
endif

ifeq "$(STATIC_BOOST)" "0"
	LIBBOOSTRANDOM_LINK_LIB = -lboost_random
	LIBBOOSTSYSTEM_LINK_LIB = -lboost_system
	LIBBOOSTFILESYSTEM_LINK_LIB = -lboost_filesystem
else
	ifneq ($(DARWIN),)
	    # Darwin libs path
	    LIBBOOSTRANDOM_LINK_LIB = ./libs/darwin_64/libboost_random.a
	    LIBBOOSTSYSTEM_LINK_LIB = ./libs/darwin_64/libboost_system.a
	    LIBBOOSTFILESYSTEM_LINK_LIB = ./libs/darwin_64/libboost_filesystem.a
	else
	    # Linux libs path (for now)
	    LIBBOOSTRANDOM_LINK_LIB = ./libs/linux_64/libboost_random.a
	    LIBBOOSTSYSTEM_LINK_LIB = ./libs/linux_64/libboost_system.a
	    LIBBOOSTFILESYSTEM_LINK_LIB = ./libs/linux_64/libboost_filesystem.a
	endif
endif

NCURSES_LINK_LIB = -lncurses

GRT_ANALYZE_OBJS = $(GRT_ANALYZE_CPP_OBJS) $(GRT_TABLE_HEADER_CPP_OBJS) \
		$(GRT_TABLE_SEARCH_CPP_OBJS) $(GRT_COMMON_CPP_OBJS)

GRT_CONVERT_OBJS = $(GRT_CONVERT_CPP_OBJS) $(GRT_TABLE_HEADER_CPP_OBJS) \
		$(GRT_TABLE_SEARCH_CPP_OBJS) $(GRT_COMMON_CPP_OBJS)

GRT_BULK_CONVERT_OBJS = $(GRT_BULK_CONVERT_CPP_OBJS) $(GRT_TABLE_HEADER_CPP_OBJS) \
		$(GRT_TABLE_SEARCH_CPP_OBJS) $(GRT_COMMON_CPP_OBJS)

GRT_CRACK_CUDA_OBJS = $(GRT_CANDIDATE_HASH_CU_OBJS) $(GRT_CANDIDATE_HASH_CPP_OBJS) \
		$(GRT_REGENERATE_CHAIN_CU_OBJS) $(GRT_REGENERATE_CHAIN_CPP_OBJS) \
		$(GRT_TABLE_HEADER_CPP_OBJS) $(GRT_TABLE_SEARCH_CPP_OBJS) $(GRT_COMMON_CPP_OBJS) \
		$(GRT_CRACK_CPP_OBJS) $(GRT_CUDA_CPP_OBJS)

GRTCL_CRACK_CUDA_OBJS = $(GRTCL_CANDIDATE_HASH_CPP_OBJS) \
		$(GRTCL_REGENERATE_CHAIN_CPP_OBJS) \
		$(GRT_TABLE_HEADER_CPP_OBJS) $(GRT_TABLE_SEARCH_CPP_OBJS) $(GRT_COMMON_CPP_OBJS) \
		$(GRTCL_CRACK_CPP_OBJS) $(GRTCL_OPENCL_CPP_OBJS)

GRT_INDEX_OBJS = $(GRT_INDEX_CPP_OBJS) $(GRT_TABLE_HEADER_CPP_OBJS) \
		$(GRT_TABLE_SEARCH_CPP_OBJS) $(GRT_COMMON_CPP_OBJS)

GRT_MERGE_OBJS = $(GRT_MERGE_CPP_OBJS) $(GRT_TABLE_HEADER_CPP_OBJS) \
		$(GRT_TABLE_SEARCH_CPP_OBJS) $(GRT_COMMON_CPP_OBJS)

GRT_MAKE_TESTFILE_OBJS = $(GRT_MAKE_TESTFILE_CPP_OBJS) $(GRT_TABLE_HEADER_CPP_OBJS) \
		$(GRT_TABLE_SEARCH_CPP_OBJS) $(GRT_COMMON_CPP_OBJS) $(GRT_CHAINRUNNER_CPP_OBJS)

GRT_VERIFY_OBJS = $(GRT_VERIFY_CPP_OBJS) $(GRT_TABLE_HEADER_CPP_OBJS) \
		$(GRT_TABLE_SEARCH_CPP_OBJS) $(GRT_COMMON_CPP_OBJS) $(GRT_CHAINRUNNER_CPP_OBJS)

GRT_SEARCH_TABLE_OBJS = $(GRT_SEARCH_TABLE_CPP_OBJS) $(GRT_TABLE_HEADER_CPP_OBJS) \
		$(GRT_TABLE_SEARCH_CPP_OBJS) $(GRT_COMMON_CPP_OBJS)


GRTCL_SHOW_CONFIG = $(GRTCL_SHOW_CONFIG_CPP_OBJS) $(GRTCL_OPENCL_CPP_OBJS)

# Multiforcer build stuff
CUDA_MULTIFORCER_CU_FILES = CHHashTypePlainMD5.cu CHHashTypePlainNTLM.cu CHHashTypePlainSHA1.cu \
  CHHashTypePlainMD4.cu CHHashTypeMSSQL.cu CHHashTypePlainMySQL323.cu CHHashTypeSaltedMD5PassSalt.cu \
  CHHashTypeSaltedSSHA.cu CHHashTypeSaltedMD5SaltPass.cu CHHashTypePlainMD5Single.cu \
  CHHashTypePlainDoubleMD5.cu CHHashTypePlainMD5ofSHA1.cu CHHashTypePlainSHA1ofMD5.cu \
  CHHashTypePlainTripleMD5.cu CHHashTypePlainDuplicatedMD5.cu CHHashTypePlainDuplicatedNTLM.cu \
  CHHashTypePlainLM.cu CHHashTypePlainSHA256.cu
CUDA_MULTIFORCER_CU_OBJS = $(patsubst %.cu,$(BUILDIR)/%.cu.o,$(notdir $(CUDA_MULTIFORCER_CU_FILES)))

CUDA_MULTIFORCER_CPP_FILES = CHCudaUtils.cpp CHCommandLineData.cpp CHWorkunitRobust.cpp \
  CHWorkunitNetwork.cpp CHHashes.cpp CHMain.cpp CHCharsetSingle.cpp CHCharsetMulti.cpp \
  CHHashFilePlain32.cpp CHCommon.cpp CHDisplayNcurses.cpp CHHashType.cpp CHHashTypePlain.cpp \
  CHHashTypePlainMD5.cpp CHHashTypePlainNTLM.cpp CHHashTypePlainSHA1.cpp CHHashTypePlainMD4.cpp \
  CHHashFileMSSQL.cpp CHHashTypeMSSQL.cpp CHDisplayDebug.cpp CHHashTypeMSSQL_CPU.cpp \
  CHHashTypePlainMySQL323.cpp CHHashFileSalted32.cpp CHHashFilePlainSHA.cpp CHHashTypeSalted.cpp \
  CHHashTypeSaltedMD5PassSalt.cpp b64.cpp CHHashFileSaltedSSHA.cpp CHHashTypeSaltedSSHA.cpp \
  CHHashTypeSaltedMD5SaltPass.cpp CHHashTypePlainMD5Single.cpp CHNetworkServer.cpp \
  CHNetworkClient.cpp CHHashTypePlainDoubleMD5.cpp CHHashTypePlainMD5ofSHA1.cpp \
  CHHashTypePlainSHA1ofMD5.cpp CHHashTypePlainTripleMD5.cpp CHHashTypePlainDuplicatedMD5.cpp \
  CHHashTypePlainDuplicatedNTLM.cpp CHHashTypePlainLM.cpp CHHashFileLM.cpp \
  CHHashTypePlainSHA256.cpp CHDisplayDaemon.cpp
CUDA_MULTIFORCER_CPP_OBJS = $(patsubst %.cpp,$(BUILDIR)/%.cpp.o,$(notdir $(CUDA_MULTIFORCER_CPP_FILES)))

NEW_MULTIFORCER_CPP_FILES = MFNMain.cpp MFNHashType.cpp MFNHashTypePlain.cpp \
  MFNHashTypePlainCUDA.cpp MFNHashTypePlainCUDA_MD5.cpp MFNCommandLineData.cpp \
  CHWorkunitRobust.cpp CUDA_Common.cpp MFNMultiforcerClassFactory.cpp \
  CHWorkunitNetwork.cpp CHNetworkClient.cpp CHHashFileVPlain.cpp CHCharsetNew.cpp \
  CHDisplayDebug.cpp CHDisplayNcurses.cpp CHDisplayDaemon.cpp CHCudaUtils.cpp \
  CHHiresTimer.cpp MFNHashTypePlainOpenCL.cpp MFNHashTypePlainOpenCL_MD5.cpp \
  GRTOpenCL.cpp GRTCLUtils.cpp MFNHashClassLauncher.cpp MFNHashTypePlainCPU.cpp \
  MFNHashTypePlainCPU_MD5.cpp MFNDisplayDebug.cpp MFNDisplay.cpp MFNHashIdentifiers.cpp \
  MFNHashTypePlainCUDA_NTLM.cpp MFNHashTypePlainCUDA_LM.cpp CHHashFileVLM.cpp \
  CHHashFileV.cpp MFNHashTypePlainCPU_NTLM.cpp CHHashFileVPlain.pb.cpp \
  CHHashFileVSalted.pb.cpp MFNHashTypePlainOpenCL_NTLM.cpp MFNHashTypePlainCUDA_DoubleMD5.cpp
NEW_MULTIFORCER_CPP_OBJS = $(patsubst %.cpp,$(BUILDIR)/%.cpp.o,$(notdir $(NEW_MULTIFORCER_CPP_FILES)))

NEW_MULTIFORCER_CU_FILES = MFNHashTypePlainCUDA_MD5.cu MFNHashTypePlainCUDA_NTLM.cu \
  MFNHashTypePlainCUDA_LM.cu MFNHashTypePlainCUDA_DoubleMD5.cu
NEW_MULTIFORCER_CU_OBJS = $(patsubst %.cu,$(BUILDIR)/%.cu.o,$(notdir $(NEW_MULTIFORCER_CU_FILES)))

ifeq "$(STATIC_BOOST)" "1"
    ifneq ($(DARWIN),)
        # Darwin build path
	CUDA_MULTIFORCER_LINK_FLAGS = -lncurses ./libs/darwin_64/libargtable2.a ./libs/darwin_64/libboost_thread.a ./libs/darwin_64/libboost_system.a
    else
        # Linux uses lib64
	CUDA_MULTIFORCER_LINK_FLAGS = -lncurses ./libs/linux_64/libargtable2.a ./libs/linux_64/libboost_thread.a ./libs/linux_64/libboost_system.a
    endif
else
	CUDA_MULTIFORCER_LINK_FLAGS = -lncurses -largtable2 -lboost_thread -lboost_system
endif


SUBDIRS = src


## RULES

$(BUILDIR)/%.c.o : $(SRCDIR)%.c $(C_DEPS)
	$(VERBOSE)$(CC) $(CFLAGS) -o $@ -c $<

$(BUILDIR)/%.cpp.o : $(SRCDIR)%.cpp $(C_DEPS)
	$(VERBOSE)$(CXX) $(CXXFLAGS) -o $@ -c $<

# Default arch includes gencode for sm_10, sm_20, and other archs from GENCODE_ARCH declared in the makefile
$(BUILDIR)/%.cu.o : $(SRCDIR)%.cu $(CU_DEPS)
	$(VERBOSE)$(NVCC) $(GENCODE_SM10) $(GENCODE_ARCH) $(GENCODE_SM20) $(NVCCFLAGS) $(SMVERSIONFLAGS) -o $@ -c $<


all : builddir $(TARGETDIR)/GRTGen-CUDA $(TARGETDIR)/GRTAnalyze \
	$(TARGETDIR)/GRTConvert $(TARGETDIR)/GRTCrack-CUDA $(TARGETDIR)/GRTIndex \
	$(TARGETDIR)/GRTMerge $(TARGETDIR)/GRTMakeTestFile $(TARGETDIR)/GRTVerify \
	$(TARGETDIR)/GRTGen-OpenCL $(TARGETDIR)/GRTCrack-OpenCL $(TARGETDIR)/ShowConfig-OpenCL \
	$(TARGETDIR)/Cryptohaze-Multiforcer $(TARGETDIR)/GRTSearchTables \
	$(TARGETDIR)/GRTBulkConvert

grt : builddir $(TARGETDIR)/GRTGen-CUDA $(TARGETDIR)/GRTAnalyze \
	$(TARGETDIR)/GRTConvert $(TARGETDIR)/GRTCrack-CUDA $(TARGETDIR)/GRTIndex \
	$(TARGETDIR)/GRTMerge $(TARGETDIR)/GRTMakeTestFile $(TARGETDIR)/GRTVerify \
	$(TARGETDIR)/GRTGen-OpenCL $(TARGETDIR)/GRTCrack-OpenCL $(TARGETDIR)/ShowConfig-OpenCL \
	$(TARGETDIR)/GRTSearchTables $(TARGETDIR)/GRTBulkConvert


multiforcer : builddir $(TARGETDIR)/Cryptohaze-Multiforcer


$(TARGETDIR)/GRTGen-CUDA : srcdir $(GRT_GEN_CUDA_OBJS)
	$(VERBOSE)$(LINK) -o $(TARGETDIR)/GRTGen-CUDA $(GRT_GEN_CUDA_OBJS) $(LIB_CUDA) $(ARGTABLE2_LINK_LIB) -lpthread $(LIBCURL_LINK_LIB) $(LIBBOOSTRANDOM_LINK_LIB)

$(TARGETDIR)/GRTGen-OpenCL : srcdir $(GRTCL_GEN_CUDA_OBJS) $(TARGETDIR)/kernels
	$(VERBOSE)$(LINK) -o $(TARGETDIR)/GRTGen-OpenCL $(GRTCL_GEN_CUDA_OBJS) $(LIB_OPENCL) $(ARGTABLE2_LINK_LIB) -lpthread $(LIBCURL_LINK_LIB) $(LIBBOOSTRANDOM_LINK_LIB)
	
$(TARGETDIR)/GRTAnalyze : srcdir $(GRT_ANALYZE_OBJS)
	$(VERBOSE)$(LINK) -o $(TARGETDIR)/GRTAnalyze $(GRT_ANALYZE_OBJS) -lpthread $(LIBCURL_LINK_LIB) $(LIBBOOSTRANDOM_LINK_LIB)

$(TARGETDIR)/GRTConvert : srcdir $(GRT_CONVERT_OBJS)
	$(VERBOSE)$(LINK) -o $(TARGETDIR)/GRTConvert $(GRT_CONVERT_OBJS) -lpthread $(LIBCURL_LINK_LIB) $(LIBBOOSTRANDOM_LINK_LIB)

$(TARGETDIR)/GRTBulkConvert : srcdir $(GRT_BULK_CONVERT_OBJS)
	$(VERBOSE)$(LINK) -o $(TARGETDIR)/GRTBulkConvert $(GRT_BULK_CONVERT_OBJS) $(ARGTABLE2_LINK_LIB) $(LIBCURL_LINK_LIB) $(LIBBOOSTRANDOM_LINK_LIB) $(LIBBOOSTSYSTEM_LINK_LIB) $(LIBBOOSTFILESYSTEM_LINK_LIB)

$(TARGETDIR)/GRTCrack-CUDA : srcdir $(GRT_CRACK_CUDA_OBJS)
	$(VERBOSE)$(LINK) -o $(TARGETDIR)/GRTCrack-CUDA $(GRT_CRACK_CUDA_OBJS) $(LIB_CUDA) $(ARGTABLE2_LINK_LIB) $(NCURSES_LINK_LIB) $(LIBCURL_LINK_LIB) $(LIBBOOSTRANDOM_LINK_LIB) $(LIBBOOSTSYSTEM_LINK_LIB) $(LIBBOOSTFILESYSTEM_LINK_LIB)

$(TARGETDIR)/GRTCrack-OpenCL : srcdir $(GRTCL_CRACK_CUDA_OBJS)
	$(VERBOSE)$(LINK) -o $(TARGETDIR)/GRTCrack-OpenCL $(GRTCL_CRACK_CUDA_OBJS) $(LIB_OPENCL) $(ARGTABLE2_LINK_LIB) $(NCURSES_LINK_LIB) -lpthread $(LIBCURL_LINK_LIB) $(LIBBOOSTRANDOM_LINK_LIB) $(LIBBOOSTSYSTEM_LINK_LIB) $(LIBBOOSTFILESYSTEM_LINK_LIB)

$(TARGETDIR)/GRTIndex : srcdir $(GRT_INDEX_OBJS)
	$(VERBOSE)$(LINK) -o $(TARGETDIR)/GRTIndex $(GRT_INDEX_OBJS) -lpthread $(ARGTABLE2_LINK_LIB) $(LIBCURL_LINK_LIB) $(LIBBOOSTRANDOM_LINK_LIB)

$(TARGETDIR)/GRTMerge : srcdir $(GRT_MERGE_OBJS)
	$(VERBOSE)$(LINK) -o $(TARGETDIR)/GRTMerge $(GRT_MERGE_OBJS) -lpthread $(ARGTABLE2_LINK_LIB) $(LIBCURL_LINK_LIB) $(LIBBOOSTRANDOM_LINK_LIB) $(LIBBOOSTSYSTEM_LINK_LIB) $(LIBBOOSTFILESYSTEM_LINK_LIB)

$(TARGETDIR)/GRTMakeTestFile : srcdir $(GRT_MAKE_TESTFILE_OBJS)
	$(VERBOSE)$(LINK) -o $(TARGETDIR)/GRTMakeTestFile $(GRT_MAKE_TESTFILE_OBJS) -lpthread $(LIBCURL_LINK_LIB) $(LIBBOOSTRANDOM_LINK_LIB)

$(TARGETDIR)/GRTVerify : srcdir $(GRT_VERIFY_OBJS)
	$(VERBOSE)$(LINK) -o $(TARGETDIR)/GRTVerify $(GRT_VERIFY_OBJS) -lpthread $(LIBCURL_LINK_LIB) $(LIBBOOSTRANDOM_LINK_LIB)

$(TARGETDIR)/GRTSearchTables : srcdir $(GRT_SEARCH_TABLE_OBJS)
	$(VERBOSE)$(LINK) -o $(TARGETDIR)/GRTSearchTables $(GRT_SEARCH_TABLE_OBJS) -lpthread $(LIBCURL_LINK_LIB) $(LIBBOOSTRANDOM_LINK_LIB)


$(TARGETDIR)/ShowConfig-OpenCL : srcdir $(GRTCL_SHOW_CONFIG)
	$(VERBOSE)$(LINK) -o $(TARGETDIR)/ShowConfig-OpenCL $(GRTCL_SHOW_CONFIG) $(LIB_OPENCL)

$(TARGETDIR)/Cryptohaze-Multiforcer : srcdir $(CUDA_MULTIFORCER_CU_OBJS) $(CUDA_MULTIFORCER_CPP_OBJS)
	$(VERBOSE)$(LINK) -o $(TARGETDIR)/Cryptohaze-Multiforcer $(CUDA_MULTIFORCER_CU_OBJS) $(CUDA_MULTIFORCER_CPP_OBJS) $(LIB_CUDA) $(CUDA_MULTIFORCER_LINK_FLAGS) -lpthread

$(TARGETDIR)/New-Multiforcer : srcdir $(NEW_MULTIFORCER_CPP_OBJS) $(NEW_MULTIFORCER_CU_OBJS)
	$(VERBOSE)$(LINK) -o $(TARGETDIR)/New-Multiforcer $(NEW_MULTIFORCER_CU_OBJS) $(NEW_MULTIFORCER_CPP_OBJS) $(LIB_CUDA) $(CUDA_MULTIFORCER_LINK_FLAGS) $(LIB_OPENCL) -lpthread -lprotobuf
	
$(TARGETDIR)/kernels :
	mkdir -p $(TARGETDIR)/kernels
	cp src/GRT_OpenCL_device/* $(TARGETDIR)/kernels
	cp inc/GRT_OpenCL_device/* $(TARGETDIR)/kernels

#srcdir:
#	make -C src

.PHONY: srcdir $(SUBDIRS)

srcdir: $(SUBDIRS)
     
$(SUBDIRS):
	$(MAKE) -C $@

builddir:
	$(VERBOSE)mkdir -p $(BUILDIR)
	$(VERBOSE)mkdir -p $(TARGETDIR)
clean : 
	$(VERBOSE)rm -f *.stub.c *.gpu *.cu.cpp *.i *.ii
	$(VERBOSE)rm -f *.cubin *.ptx *.fatbin.c *.hash
	$(VERBOSE)rm -f *.cudafe1.c *.cudafe2.c *.cudafe1.cpp *.cudafe2.cpp
	$(VERBOSE)rm -rf $(BUILDIR)/*
	$(VERBOSE)rm -rf $(TARGETDIR)/*

cleancpp :
	$(VERBOSE)rm -rf $(BUILDIR)/*.cpp.o
	$(VERBOSE)rm -rf $(TARGETDIR)/*


clobber : clean
	$(VERBOSE)rm -rf $(ROOTOBJDIR)


