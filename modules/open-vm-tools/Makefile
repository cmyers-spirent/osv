# Build environment
base = $(shell readlink -f ../..)
miscbase = $(base)/external/$(ARCH)/misc.bin
INCLUDES = \
	-isystem $(miscbase)/usr/include \
	-I$(miscbase)/usr/include/glib-2.0 \
	-I$(miscbase)/usr/lib64/glib-2.0/include
LIBS = -L$(miscbase)/usr/lib64
CFLAGS = -Os -fPIC -Wall
CONF_FLAGS = --without-x --without-pam --without-procps --without-dnet \
	--without-icu --without-kernel-modules --prefix=/usr

# Build directories
OUT=$(CURDIR)/install
SRC=$(CURDIR)/src

OVT_VERSION=9f1ee2293b9a7d97b4c39c42a862d3c64192ee97
OVT_BRANCH=stable-9.4.x
OVT_REPO=https://github.com/vmware/open-vm-tools.git

ifndef ARCH
ARCH = x64
endif

module: directories $(OUT)/usr/bin/vmtoolsd.so plugins

###
# Prerequisites
###
.PHONY: directories
directories:
	@mkdir -p $(OUT)

###
# vmtools build magic
###
$(SRC):
	git clone $(OVT_REPO) --branch $(OVT_BRANCH) --single-branch $(SRC)

$(SRC)/patch: $(SRC) glib.patch
	cd $(SRC) && patch -p1 < ../glib.patch
	@touch $(SRC)/patch

$(SRC)/open-vm-tools/configure: $(SRC)/patch $(SRC)/open-vm-tools/configure.ac
	cd $(SRC)/open-vm-tools && autoreconf -i

$(SRC)/open-vm-tools/Makefile: $(SRC)/open-vm-tools/configure
	cd $(SRC)/open-vm-tools && \
		PKG_CONFIG_PATH=$(miscbase)/usr/lib64/pkgconfig \
		PATH=$(PATH):$(miscbase)/usr/bin \
		./configure $(CONF_FLAGS) CFLAGS="$(CFLAGS)" CPPFLAGS="$(INCLUDES)"  LDFLAGS="$(LIBS)"

$(SRC)/open-vm-tools/lib/lock/libLock.la: $(SRC)/open-vm-tools/Makefile
	cd $(SRC)/open-vm-tools/lib && \
		PATH=$(PATH):$(miscbase)/usr/bin make DESTDIR=$(OUT) install

$(OUT)/usr/lib/libvmtools.so: $(SRC)/open-vm-tools/lib/lock/libLock.la
	cd $(SRC)/open-vm-tools/libvmtools && \
		PATH=$(PATH):$(miscbase)/usr/bin make DESTDIR=$(OUT) install

$(OUT)/usr/bin/vmtoolsd.so: $(OUT)/usr/lib/libvmtools.so
	cd $(SRC)/open-vm-tools/services/vmtoolsd && \
		PATH=$(PATH):$(miscbase)/usr/bin make \
			DESTDIR=$(OUT) \
			LDFLAGS="-Wc,-shared $(LIBS)" \
			install
	@mv $(OUT)/usr/bin/vmtoolsd $(OUT)/usr/bin/vmtoolsd.so

plugins: $(OUT)/usr/lib/libvmtools.so
	cd $(SRC)/open-vm-tools/services/plugins/guestInfo && \
		PATH=$(PATH):$(miscbase)/usr/bin make \
			DESTDIR=$(OUT) install

.PHONY: clean
clean:
	cd $(SRC)/open-vm-tools && make clean
	rm -rf $(OUT)

.PHONY: distclean
distclean:
	rm -rf $(SRC) $(OUT)
	rm -f configure patch
