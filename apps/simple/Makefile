# Makefile for simple app
ROOT_PATH=../..
include $(ROOT_PATH)/build/shared.mk

simple_src = simple.cc
simple_obj = $(simple_src:.cc=.o)

librt_libs = $(ROOT_PATH)/bindings/cc/librt++.a
INC += -I$(ROOT_PATH)/bindings/cc

RUNTIME_LIBS := $(RUNTIME_LIBS) -lnuma

all: simple

simple: $(simple_obj) $(librt_libs) $(RUNTIME_DEPS)
	$(LDXX) -o $@ $(LDFLAGS) $(simple_obj) \
	$(librt_libs) $(RUNTIME_LIBS)

src = $(simple_src)
obj = $(src:.cc=.o)
dep = $(obj:.o=.d)

ifneq ($(MAKECMDGOALS),clean)
-include $(dep)
endif

%.d: %.cc
	@$(CXX) $(CXXFLAGS) $< -MM -MT $(@:.d=.o) >$@
%.o: %.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f $(obj) $(dep) simple
