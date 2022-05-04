ROOT_PATH=.
include $(ROOT_PATH)/build/shared.mk

DPDK_PATH = dpdk
CHECKFLAGS = -D__CHECKER__ -Waddress-space

ifneq ($(TCP_RX_STATS),)
CFLAGS += -DTCP_RX_STATS
endif

# libbase.a - the base library
base_src = $(wildcard base/*.c)
base_obj = $(base_src:.c=.o)

# libnet.a - a packet/networking utility library
net_src = $(wildcard net/*.c)
net_obj = $(net_src:.c=.o)

# libfizzwrapper.a - a shim for encryption (fizz)
fizz_c_src = $(wildcard fizzwrapper/*.c)
fizz_c_obj = $(fizz_c_src:.c=.o)
fizz_cpp_src = $(wildcard fizzwrapper/*.cpp)
fizz_cpp_obj = $(fizz_cpp_src:.cpp=.o)
fizz_obj = $(fizz_cpp_obj)
fizz_obj += $(fizz_c_obj)

# iokernel - a soft-NIC service
iokernel_src = $(wildcard iokernel/*.c)
iokernel_obj = $(iokernel_src:.c=.o)
$(iokernel_obj): INC += -I$(DPDK_PATH)/build/include

# runtime - a user-level threading and networking library
runtime_src = $(wildcard runtime/*.c) $(wildcard runtime/net/*.c)
runtime_src += $(wildcard runtime/net/directpath/*.c)
runtime_src += $(wildcard runtime/net/directpath/mlx5/*.c)
runtime_src += $(wildcard runtime/rpc/*.c)
runtime_asm = $(wildcard runtime/*.S)
runtime_obj = $(runtime_src:.c=.o) $(runtime_asm:.S=.o)

# test cases
test_src = $(wildcard tests/*.c)
test_obj = $(test_src:.c=.o)
test_targets = $(basename $(test_src))

# pcm lib
PCM_DEPS = $(ROOT_PATH)/deps/pcm/libPCM.a
PCM_LIBS = -lm -lstdc++

# dpdk libs
DPDK_LIBS= -L$(DPDK_PATH)/build/lib
DPDK_LIBS += -Wl,-whole-archive -lrte_pmd_e1000 -Wl,-no-whole-archive
DPDK_LIBS += -Wl,-whole-archive -lrte_pmd_ixgbe -Wl,-no-whole-archive
DPDK_LIBS += -Wl,-whole-archive -lrte_mempool_ring -Wl,-no-whole-archive
DPDK_LIBS += -Wl,-whole-archive -lrte_pmd_tap -Wl,-no-whole-archive
DPDK_LIBS += -ldpdk
DPDK_LIBS += -lrte_eal
DPDK_LIBS += -lrte_ethdev
DPDK_LIBS += -lrte_hash
DPDK_LIBS += -lrte_mbuf
DPDK_LIBS += -lrte_mempool
DPDK_LIBS += -lrte_mempool_stack
DPDK_LIBS += -lrte_ring
# additional libs for running with Mellanox NICs
ifeq ($(CONFIG_MLX5),y)
DPDK_LIBS += $(MLX5_LIBS) -lrte_pmd_mlx5
$(iokernel_obj): INC += $(MLX5_INC)
else
ifeq ($(CONFIG_MLX4),y)
DPDK_LIBS += -lrte_pmd_mlx4 -libverbs -lmlx4
endif
endif

# fizzwrapper libs
FIZZWRAPPER_LIBS  = -lfizz
FIZZWRAPPER_LIBS += -lfolly
FIZZWRAPPER_LIBS += -lsodium
FIZZWRAPPER_LIBS += -lglog
FIZZWRAPPER_LIBS += -lgflags
FIZZWRAPPER_LIBS += -lfmt
FIZZWRAPPER_LIBS += -liberty
FIZZWRAPPER_LIBS += -levent
FIZZWRAPPER_LIBS += -lboost_context
FIZZWRAPPER_LIBS += -lcrypto
FIZZWRAPPER_LIBS += -ldouble-conversion
FIZZWRAPPER_LIBS += -lmvfst_bufutil
FIZZWRAPPER_LIBS += -lmvfst_cc_algo
FIZZWRAPPER_LIBS += -lmvfst_client
FIZZWRAPPER_LIBS += -lmvfst_codec
FIZZWRAPPER_LIBS += -lmvfst_codec_decode
FIZZWRAPPER_LIBS += -lmvfst_codec_packet_number_cipher
FIZZWRAPPER_LIBS += -lmvfst_codec_pktbuilder
FIZZWRAPPER_LIBS += -lmvfst_codec_pktrebuilder
FIZZWRAPPER_LIBS += -lmvfst_codec_types
FIZZWRAPPER_LIBS += -lmvfst_constants
FIZZWRAPPER_LIBS += -lmvfst_d6d_state_functions
FIZZWRAPPER_LIBS += -lmvfst_d6d_types
FIZZWRAPPER_LIBS += -lmvfst_exception
FIZZWRAPPER_LIBS += -lmvfst_fizz_client
FIZZWRAPPER_LIBS += -lmvfst_fizz_handshake
FIZZWRAPPER_LIBS += -lmvfst_flowcontrol
FIZZWRAPPER_LIBS += -lmvfst_handshake
FIZZWRAPPER_LIBS += -lmvfst_happyeyeballs
FIZZWRAPPER_LIBS += -lmvfst_looper
FIZZWRAPPER_LIBS += -lmvfst_loss
FIZZWRAPPER_LIBS += -lmvfst_qlogger
FIZZWRAPPER_LIBS += -lmvfst_server
FIZZWRAPPER_LIBS += -lmvfst_socketutil
FIZZWRAPPER_LIBS += -lmvfst_state_ack_handler
FIZZWRAPPER_LIBS += -lmvfst_state_functions
FIZZWRAPPER_LIBS += -lmvfst_state_machine
FIZZWRAPPER_LIBS += -lmvfst_state_pacing_functions
FIZZWRAPPER_LIBS += -lmvfst_state_simple_frame_functions
FIZZWRAPPER_LIBS += -lmvfst_state_stream
FIZZWRAPPER_LIBS += -lmvfst_state_stream_functions
FIZZWRAPPER_LIBS += -lmvfst_transport
FIZZWRAPPER_LIBS += -lmvfst_transport_knobs
FIZZWRAPPER_LIBS += -lstdc++
FIZZWRAPPER_LIBS += -ldl

# must be first
all:
	$(MAKE) libs

libs: libbase.a libnet.a libruntime.a

tests: $(test_targets)

libbase.a: $(base_obj)
	$(AR) rcs $@ $^

libnet.a: $(net_obj)
	$(AR) rcs $@ $^

libruntime.a: $(runtime_obj)
	$(AR) rcs $@ $^

libfizzwrapper.a: $(fizz_obj)
	$(AR) rcs $@ $^

iokerneld: $(iokernel_obj) libbase.a libnet.a libruntime.a libfizzwrapper.a base/base.ld $(PCM_DEPS)
	$(LDXX) $(LDFLAGS) $(CXXFLAGS) -o $@ $(iokernel_obj) \
	libfizzwrapper.a -Wl,--start-group $(FIZZWRAPPER_LIBS) \
	./bindings/cc/librt++.a libruntime.a libnet.a libbase.a \
	$(DPDK_LIBS) \
	$(PCM_DEPS) $(PCM_LIBS) \
	-lpthread -lnuma -ldl

$(test_targets): $(test_obj) libbase.a libruntime.a libnet.a libfizzwrapper.a base/base.ld
	$(LD) $(LDFLAGS) -o $@ $@.o $(RUNTIME_LIBS) \
	libfizzwrapper.a -Wl,--start-group $(FIZZWRAPPER_LIBS) \
	./bindings/cc/librt++.a libruntime.a libnet.a libbase.a

# general build rules for all targets
src = $(base_src) $(net_src) $(runtime_src) $(iokernel_src) $(fizz_c_src) $(test_src)
cppsrc = $(fizz_cpp_src)
asm = $(runtime_asm)
obj = $(src:.c=.o) $(cppsrc:.cpp=.o) $(asm:.S=.o)
dep = $(obj:.o=.d)

ifneq ($(MAKECMDGOALS),clean)
-include $(dep)   # include all dep files in the makefile
endif

# rule to generate a dep file by using the C preprocessor
# (see man cpp for details on the -MM and -MT options)
%.d: %.c
	@$(CC) $(CFLAGS) $< -MM -MT $(@:.d=.o) >$@
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
%.d: %.S
	@$(CC) $(CFLAGS) $< -MM -MT $(@:.d=.o) >$@
%.o: %.S
	$(CC) $(CFLAGS) -c $< -o $@
%.d: %.cpp
	@$(CXX) $(CXXFLAGS) $< -MM -MT $(@:.d=.o) >$@
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# prints sparse checker tool output
sparse: $(src)
	$(foreach f,$^,$(SPARSE) $(filter-out -std=gnu11, $(CFLAGS)) $(CHECKFLAGS) $(f);)

.PHONY: submodules
submodules:
	$(ROOT_PATH)/build/init_submodules.sh

.PHONY: clean
clean:
	rm -f $(obj) $(dep) libbase.a libnet.a libruntime.a libfizzwrapper.a \
	iokerneld $(test_targets)
