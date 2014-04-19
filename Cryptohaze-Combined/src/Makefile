include ../Makefile.inc


SUBDIRS = GRT_CUDA_device GRT_CUDA_host GRT_Common CH_Common OpenCL_Common GRT_OpenCL_host CUDA_Common Multiforcer_CUDA_host Multiforcer_CUDA_device Multiforcer_Common MFN_Common MFN_CPU_host MFN_CUDA_device MFN_CUDA_host MFN_OpenCL_device MFN_OpenCL_host CH_HashFiles

.PHONY: subdirs $(SUBDIRS)
     
subdirs: $(SUBDIRS)
     
$(SUBDIRS):
	$(MAKE) -C $@
