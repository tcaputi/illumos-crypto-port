obj-m := illumos-crypto.o

KERNELVERSION = $(shell uname -r)
KDIR := /lib/modules/$(KERNELVERSION)/build
PWD := $(shell pwd)
SPL_DIR := /media/sf_projects/zfs_crypto/spl
EXTRA_CFLAGS := -g -include $(SPL_DIR)/spl_config.h -D_KERNEL
EXTRA_AFLAGS := -D_ASM

illumos-crypto-y := module/illumos-crypto.o

illumos-crypto-y += module/api/kcf_cipher.o
illumos-crypto-y += module/api/kcf_digest.o
illumos-crypto-y += module/api/kcf_mac.o
illumos-crypto-y += module/api/kcf_miscapi.o
illumos-crypto-y += module/api/kcf_ctxops.o

illumos-crypto-y += module/core/kcf_callprov.o
illumos-crypto-y += module/core/kcf_prov_tabs.o
illumos-crypto-y += module/core/kcf_sched.o
illumos-crypto-y += module/core/kcf_mech_tabs.o
illumos-crypto-y += module/core/kcf_prov_lib.o

illumos-crypto-y += module/spi/kcf_spi.o

illumos-crypto-y += module/io/aes.o
illumos-crypto-y += module/io/sha2_mod.o

illumos-crypto-y += module/os/modhash.o
illumos-crypto-y += module/os/bitmap_arch.o
illumos-crypto-y += module/os/modconf.o

illumos-crypto-y += algs/modes/cbc.o
illumos-crypto-y += algs/modes/ccm.o
illumos-crypto-y += algs/modes/ctr.o
illumos-crypto-y += algs/modes/ecb.o
illumos-crypto-y += algs/modes/gcm.o
illumos-crypto-y += algs/modes/modes.o

illumos-crypto-y += algs/aes/aes_impl.o
illumos-crypto-y += algs/aes/amd64/aeskey.o
illumos-crypto-y += algs/aes/amd64/aes_amd64.o
illumos-crypto-y += algs/sha2/sha2.o

ccflags-y := -I$(src)/include
ccflags-y += -I$(src)/algs/
ccflags-y += -I$(SPL_DIR)/include

asflags-y := -include $(SPL_DIR)/spl_config.h
asflags-y += -I$(src)/include/
asflags-y += -I$(src)/include/arch/intel
asflags-y += -I$(SPL_DIR)/include

default:
	@# Make the exported SPL symbols available to these modules.
	@# They may be in the root of SPL_OBJ when building against
	@# installed devel headers, or they may be in the module
	@# subdirectory when building against the spl source tree.
	@if [ -f $(SPL_DIR)/Module.symvers ]; then \
		/bin/cp $(SPL_DIR)/Module.symvers .; \
	elif [ -f $(SPL_DIR)/module/Module.symvers ]; then \
		/bin/cp $(SPL_DIR)/module/Module.symvers .; \
	else \
		echo -e "\n" \
		"*** Missing spl symbols ensure you have built the spl:\n" \
		"*** - /media/sf_projects/zfs_crypto/spl//Module.symvers, or\n" \
		"*** - /media/sf_projects/zfs_crypto/spl//module/Module.symvers\n"; \
		exit 1; \
	fi
	
	$(MAKE) -I/usr/include -C $(KDIR) SUBDIRS=$(PWD) modules
	
clean:
	$(MAKE) -I/usr/include -C $(KDIR) SUBDIRS=$(PWD) clean
