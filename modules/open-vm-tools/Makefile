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

module: all

all: directories $(SRC)/plugins $(SRC)/vmtoolsd

###
# Prerequisites
###
.PHONY: directories
directories:
	@mkdir -p $(OUT)

###
# vmtools build magic
###
$(SRC)/download:
	git clone $(OVT_REPO) --branch $(OVT_BRANCH) --single-branch $(SRC)
	@touch $(SRC)/download

$(SRC)/patch: $(SRC)/download glib.patch
	cd $(SRC) && patch -p1 < ../glib.patch
	@touch $(SRC)/patch

$(SRC)/configure: $(SRC)/patch
	cd $(SRC)/open-vm-tools && autoreconf -i
	@touch $(SRC)/configure

$(SRC)/open-vm-tools/Makefile: $(SRC)/configure
	cd $(SRC)/open-vm-tools && \
		PKG_CONFIG_PATH=$(miscbase)/usr/lib64/pkgconfig \
		PATH=$(PATH):$(miscbase)/usr/bin \
		./configure $(CONF_FLAGS) CFLAGS="$(CFLAGS)" CPPFLAGS="$(INCLUDES)"  LDFLAGS="$(LIBS)"

$(SRC)/libs: $(SRC)/open-vm-tools/Makefile
	cd $(SRC)/open-vm-tools/lib && \
		PATH=$(PATH):$(miscbase)/usr/bin make DESTDIR=$(OUT) install
	cd $(SRC)/open-vm-tools/libvmtools && \
		PATH=$(PATH):$(miscbase)/usr/bin make DESTDIR=$(OUT) install
	cd $(SRC)/open-vm-tools/libhgfs && \
		PATH=$(PATH):$(miscbase)/usr/bin make DESTDIR=$(OUT) install
	@touch $(SRC)/libs

$(SRC)/plugins: $(SRC)/open-vm-tools/Makefile $(SRC)/libs
	cd $(SRC)/open-vm-tools/services/plugins && \
		PATH=$(PATH):$(miscbase)/usr/bin make DESTDIR=$(OUT) install
	@touch $(SRC)/plugins

$(SRC)/vmtoolsd: $(SRC)/open-vm-tools/Makefile $(SRC)/libs
	cd $(SRC)/open-vm-tools/services/vmtoolsd && \
		PATH=$(PATH):$(miscbase)/usr/bin make \
			DESTDIR=$(OUT) LDFLAGS="-Wc,-shared $(LIBS)" install
	@touch $(SRC)/vmtoolsd

.PHONY: clean
clean:
	cd $(SRC)/open-vm-tools && make clean
	rm -rf $(SRC)/install $(SRC)/libs $(SRC)/plugins $(SRC)/vmtoolsd
	rm -rf $(OUT)

.PHONY: distclean
distclean:
	rm -rf $(SRC) $(OUT)
	rm -f configure patch
