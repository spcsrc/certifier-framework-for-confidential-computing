ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
CFLAGS += -O0 -ggdb3
else
GRAMINE_LOG_LEVEL = error
CFLAGS += -O2
endif

CFLAGS += -fPIE
LDFLAGS += -pie

RA_TYPE ?= none
RA_CLIENT_SPID ?=
RA_CLIENT_LINKABLE ?= 0

GPP=g++

.PHONY: all
all: lib

.PHONY: lib
lib: ssl/graminelib.crt mbedtls/.mbedtls_configured graminelib

############################# SSL DATA DEPENDENCY #############################

# SSL data: key and x.509 self-signed certificate
ssl/graminelib.crt: ssl/ca_config.conf
	openssl genrsa -out ssl/ca.key 2048
	openssl req -x509 -new -nodes -key ssl/ca.key -sha256 -days 1024 -out ssl/ca.crt -config ssl/ca_config.conf
	openssl genrsa -out ssl/graminelib.key 2048
	openssl req -new -key ssl/graminelib.key -out ssl/graminelib.csr -config ssl/ca_config.conf
	openssl x509 -req -days 360 -in ssl/graminelib.csr -CA ssl/ca.crt -CAkey ssl/ca.key -CAcreateserial -out ssl/graminelib.crt

######################### GRAMINE/SGX VARIABLES ###############################
GRAMINE_SRC_PATH = ../../../gramine/gramine
SGX_INCLUDE = -I$(GRAMINE_SRC_PATH)/pal/src/host/linux-sgx -I$(GRAMINE_SRC_PATH)/tools/sgx/ra-tls
SGX_LDFLAGS = -Wl,--enable-new-dtags $(shell pkg-config --libs sgx_util)

############################# MBEDTLS DEPENDENCY ##############################

# This download is done to get headers in include/, because we currently fail to provide the headers
# (`pkg-config --cflags mbedtls_gramine` in the below CFLAGS line returns a non-existing directory).
# TODO: install mbedtls_gramine headers during Gramine install, and use them in below CFLAGS line.

MBEDTLS_VERSION ?= 3.2.1
MBEDTLS_SRC ?= mbedtls-$(MBEDTLS_VERSION).tar.gz
MBEDTLS_URI ?= \
	https://github.com/ARMmbed/mbedtls/archive \
	https://packages.gramineproject.io/distfiles
MBEDTLS_HASH ?= 5850089672560eeaca03dc36678ee8573bb48ef6e38c94f5ce349af60c16da33

ifeq ($(DEBUG),1)
MBED_BUILD_TYPE=Debug
else
MBED_BUILD_TYPE=Release
endif

$(MBEDTLS_SRC):
	$(GRAMINE_SRC_PATH)/CI-Examples/common_tools/download --output $@ $(foreach mirror,$(MBEDTLS_URI),--url $(mirror)/$(MBEDTLS_SRC)) --sha256 $(MBEDTLS_HASH)

.SECONDARY: mbedtls/.mbedtls_downloaded
mbedtls/.mbedtls_downloaded: $(MBEDTLS_SRC)
	tar --touch -xzf $(MBEDTLS_SRC)
	mv mbedtls-mbedtls-$(MBEDTLS_VERSION) mbedtls
	touch $@

.SECONDARY: mbedtls/.mbedtls_configured
mbedtls/.mbedtls_configured: mbedtls/.mbedtls_downloaded
	cd mbedtls && ./scripts/config.pl set MBEDTLS_CMAC_C MBEDTLS_ERROR_C
	touch $@

########################### CLIENT EXECUTABLES ################################

# TODO: use `$(shell pkg-config --cflags mbedtls_gramine)` instead of local mbedtls includes
CFLAGS += -I./mbedtls/include $(SGX_INCLUDE)
LDFLAGS += -ldl -Wl,--enable-new-dtags $(shell pkg-config --libs mbedtls_gramine) -L/usrl/local/lib -L./ $(SGX_LDFLAGS)

graminelib: graminelib.c mbedtls/.mbedtls_configured
	$(GPP) $< $(CFLAGS) $(LDFLAGS) -fPIC -shared -o graminelib.so

########################### CLIENT (DCAP) MANIFEST ############################

graminelib.manifest: graminelib.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dra_type=$(RA_TYPE) \
		-Dra_client_spid=$(RA_CLIENT_SPID) \
		-Dra_client_linkable=$(RA_CLIENT_LINKABLE) \
		$< >$@

graminelib.manifest.sgx graminelib.sig: sgx_sign_graminelib
	@:

.INTERMEDIATE: sgx_sign_graminelib
sgx_sign_graminelib: graminelib.manifest graminelib
	gramine-sgx-sign \
		--manifest $< \
		--output $<.sgx

graminelib.token: graminelib.sig
	gramine-sgx-get-token --output $@ --sig $<

################################## CLEANUP ####################################

.PHONY: clean
clean:
	$(RM) -r \
		*.token *.sig *.manifest.sgx *.manifest graminelib *.so *.so.* OUTPUT

.PHONY: distclean
distclean: clean
	$(RM) -r mbedtls/ *.tar.gz ssl/ca.* ssl/graminelib.*
