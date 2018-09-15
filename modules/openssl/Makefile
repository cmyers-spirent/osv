#
# openssl module Makefile
#
# Headers from newer versions of openssl are not compatible with included libraries
#
# Adding misc.bin directly to include path is problematic because it also brings in boost,
# but included boost libraries/includes have issues resolving symbols.
#
# This script creates symlinks so that only openssl libraries can be exposed to
# other modules
#
src = $(shell readlink -f ../..)

ifndef ARCH
	ARCH = x64
endif

ifndef mode
	mode = release
endif

ifndef OSV_BUILD_PATH
	OSV_BUILD_PATH = $(src)/build/$(mode).$(ARCH)
endif

gen_include_dir = $(OSV_BUILD_PATH)/gen/include
miscbase = $(src)/external/$(ARCH)/misc.bin
libs-dir = $(miscbase)/usr/lib64

quiet = $(if $V, $1, @echo " $2"; $1)
very-quiet = $(if $V, $1, @$1)

make_link = \
	$(call very-quiet, ( [ -L $2 ] && [ "`readlink $2`" = "$1" ] ) || ln -sf $1 $2)

module: all

all:
	$(call make_link, $(miscbase)/usr/include/openssl, $(gen_include_dir)/openssl)
	$(call make_link, $(miscbase)/usr/include/et, $(gen_include_dir)/et)
	$(call make_link, $(miscbase)/usr/include/krb5, $(gen_include_dir)/krb5)
	$(call make_link, $(miscbase)/usr/include/krb5.h, $(gen_include_dir)/krb5.h)

clean:
	$(call very-quiet, $(RM) -f $(gen_include_dir)/openssl)
	$(call very-quiet, $(RM) -f $(gen_include_dir)/et)
	$(call very-quiet, $(RM) -f $(gen_include_dir)/krb5)
	$(call very-quiet, $(RM) -f $(gen_include_dir)/krb5.h)

.PHONY:

.SECONDARY:
