INCLUDE_ROOT := ../../

include ../../Makefile.inc

CU_OBJECTS := $(patsubst %.cu,../../$(OBJDIR)/%.cu.o,$(wildcard *.cu))


all: ../../objs $(CU_OBJECTS)

# Default arch includes gencode for sm_10, sm_20, and other archs from GENCODE_ARCH declared in the makefile
../../$(OBJDIR)/%.cu.o : $(SRCDIR)%.cu $(CU_DEPS)
	$(VERBOSE)$(NVCC) $(GENCODE_SM10) $(GENCODE_ARCH) $(GENCODE_SM20) $(NVCCFLAGS) $(SMVERSIONFLAGS) -o $@ -c $<

../../objs:
	mkdir -p ../../objs
