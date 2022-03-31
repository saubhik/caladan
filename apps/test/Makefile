# Makefile for simple app
ROOT_PATH=../..
include $(ROOT_PATH)/build/shared.mk

test_atomic_src = test_atomic.cc
test_atomic_obj = $(test_atomic_src:.cc=.o)

test_memory_order_src = test_memory_order.cc
test_memory_order_obj = $(test_memory_order_src:.cc=.o)

test_udp_src = test_udp.cc
test_udp_obj = $(test_udp_src:.cc=.o)

librt_libs = $(ROOT_PATH)/bindings/cc/librt++.a
INC += -I$(ROOT_PATH)/bindings/cc

RUNTIME_LIBS := $(RUNTIME_LIBS) -lnuma

all: test_atomic test_memory_order test_udp

test_atomic: $(test_atomic_obj) $(librt_libs) $(RUNTIME_DEPS)
	$(LDXX) -o $@ $(LDFLAGS) $(test_atomic_obj) \
	$(librt_libs) $(RUNTIME_LIBS)

test_memory_order: $(test_memory_order_obj) $(librt_libs) $(RUNTIME_DEPS)
	$(LDXX) -o $@ $(LDFLAGS) $(test_memory_order_obj) \
	$(librt_libs) $(RUNTIME_LIBS)

test_udp: $(test_udp_obj) $(librt_libs) $(RUNTIME_DEPS)
	$(LDXX) -o $@ $(LDFLAGS) $(test_udp_obj) \
	$(librt_libs) $(RUNTIME_LIBS)

src = $(test_atomic_src) $(test_memory_order_src) $(test_udp)
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
	rm -f $(obj) $(dep) test_atomic test_memory_order test_udp
