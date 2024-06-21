from idaapi import *
from unicorn import *
from unicorn.arm_const import *

datadiv_decode_funcs = []
def find_datadiv_decode():
    sel_obj = get_segm_by_sel(selector_by_name(".init_array"))
    init_array_start = sel_obj.startEA
    init_array_end = sel_obj.endEA
    for i in range(init_array_start, init_array_end, 8):
        func_addr = get_qword(i)
        if ".datadiv_decode" in get_func_name(func_addr):
            datadiv_decode_funcs.append({"start": func_addr, "end": get_func_attr(func_addr, FUNCATTR_END)})

def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))

CODE_ADDRESS = 0
CODE_SIZE = 1024*1024*2
text_start = 0x6dcac
text_size = 0x18763c

em = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
em.mem_map(CODE_ADDRESS, CODE_SIZE)
code = get_bytes(text_start, text_size)

# setup stack
em.reg_write(UC_ARM_REG_SP, CODE_ADDRESS + 0x200000)
# write machine code
em.mem_write(CODE_ADDRESS, code)
# hook block
em.hook_add(UC_HOOK_CODE, hook_block)

# start emulate
find_datadiv_decode()
for datadiv_decode_func in datadiv_decode_funcs:
    em.emu_start(datadiv_decode_func["start"], datadiv_decode_func["end"])

em.mem_unmap(CODE_ADDRESS, CODE_SIZE)