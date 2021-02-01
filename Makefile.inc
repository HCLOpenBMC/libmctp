LIBMCTP_DIR ?= libmctp/
LIBMCTP_OBJS = core.o alloc.o log.o
LIBMCTP_BINDINGS ?= serial astlpc

LIBMCTP_OBJS += $(LIBMCTP_BINDINGS:%=%.o)

LIBMCTP = $(LIBMCTP_DIR) -l:libmctp.a -l:libnl-genl-3.so.200 -l:libnl-3.so.200

$(LIBMCTP): $(LIBMCTP_OBJS:%=$(LIBMCTP_DIR)%)
