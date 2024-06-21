from idaapi import *
import idc
from unicorn import *
from unicorn.arm64_const import *
import capstone

bbtype = {0: "fcb_normal", 1: "fcb_indjump", 2: "fcb_ret", 3: "fcb_cndret",
              4: "fcb_noret", 5: "fcb_enoret", 6: "fcb_extern", 7: "fcb_error"}
def format_bb(bb):
    return("ID: %d, Start: 0x%x, End: 0x%x, Last instruction: 0x%x, Size: %d, "
           "Type: %s" % (bb.id, bb.startEA, bb.endEA, idc.PrevHead(bb.endEA),
                         (bb.endEA - bb.startEA), bbtype[bb.type]))

def disassemble(code, addr):
    cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    for i in cs.disasm(code, addr):
        return i

def reg_stou(reg_name):
    if reg_name == 'wzr':
        return reg_name
    elif reg_name[0] == 'w':
        return UC_ARM64_REG_W0+int(reg_name[1:])
    else:
        return reg_name

def get_context(uc):
    regs = []
    for i in range(31):
        idx = UC_ARM64_REG_X0+i
        regs.append(uc.reg_read(idx))

    regs.append(uc.reg_read(UC_ARM64_REG_SP))
    return regs

def set_context(uc, regs):
    if regs == None:
        return
    for i in range(31):
        idx = UC_ARM64_REG_X0 + i
        uc.reg_write(idx, regs[i])
    uc.reg_write(UC_ARM64_REG_SP,regs[31])

def hook_block(uc, address, size, user_data):
    global rel_bb_cnt, queue, dist_addr
    if address in relevant_blocks_start:
        print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address+func_start, size))
        # 找下一个真实块
        rel_bb_cnt += 1
        if rel_bb_cnt == 2:
            # retn 块不再加到队列里
            if not address in retn_blocks_start:
                context = get_context(uc)
                queue.append((address, context))

            dist_addr = address
            uc.emu_stop()


def hook_code(mu, address, size, user_data):
    global has_branch, another_branch
    instruction = mu.mem_read(address, size)
    instruction_str = disassemble(instruction, address)

    # print('# Tracing instruction at 0x%x, instruction size = 0x%x, instruction = %s' % (address+func_start, size, instruction_str))

    # 跳过函数调用
    if instruction_str.mnemonic == 'bl' or instruction_str.mnemonic == 'blx':
        pc = mu.reg_read(UC_ARM64_REG_PC)
        mu.reg_write(UC_ARM64_REG_PC, pc+4)
        mu.reg_write(UC_ARM64_REG_X0, 0)
    # 分支
    elif instruction_str.mnemonic == 'csel':
        # print(instruction_str.op_str)
        regs = [reg_stou(x) for x in instruction_str.op_str.split(', ')]
        if regs[1] != 'wzr':
            v1 = mu.reg_read(regs[1])
        else:
            v1 = 0
        if regs[2] != 'wzr':
            v2 = mu.reg_read(regs[2])
        else:
            v2 = 0

        condition = regs[3]
        if another_branch:
            mu.reg_write(regs[0], v2)
            has_branch = False
            another_branch = False
        else:
            mu.reg_write(regs[0], v1)
            has_branch = True
            another_branch = True

        pc = mu.reg_read(UC_ARM64_REG_PC)
        mu.reg_write(UC_ARM64_REG_PC, pc+4)
    elif instruction_str.mnemonic == 'ret':
        mu.emu_stop()

def get_relevant_successors(address):
    succs = []
    for bb in relevant_blocks:
        if bb.startEA == address:
            for succ in bb.succs():
                if succ.startEA-func_start in relevant_blocks_start:
                    succs.append(hex(succ.startEA))
            
            return succs

def patch_cfg(flow):
    pass

func_addr = 0x1D5F5C
f_blocks = FlowChart(get_func(func_addr), flags=FC_PREDS)
func_start = get_func(func_addr).startEA
func_end = get_func(func_addr).endEA
relevant_blocks = []
relevant_blocks_start = []
control_blocks = []
retn_blocks = []
retn_blocks_start = []
prev_block = None

rel_bb_cnt = 0
has_branch = False
another_branch = False
dist_addr = None

for block in f_blocks:
    start = block.startEA
    end = block.endEA
    succ_count = 0
    # 识别 retn 块
    if bbtype[block.type] == 'fcb_ret' or bbtype[block.type] == 'fcb_noret':
        retn_blocks.append(block)
        retn_blocks_start.append(block.startEA-func_start)

    # 识别控制块
    if end-start == 8:
        if print_insn_mnem(start) == 'CMP' and print_insn_mnem(idc.PrevHead(end)).startswith('B'):
            # print(format_bb(block))
            control_blocks.append(block)
        else:
            relevant_blocks.append(block)
            relevant_blocks_start.append(block.startEA-func_start)
    else:
        relevant_blocks.append(block)
        relevant_blocks_start.append(block.startEA-func_start)

# 通过模拟执行得到真实块的下一个真实块地址
flow = {}

CODE_ADDRESS = 0
CODE_SIZE = 1024*1024*5
code = get_bytes(func_start, func_end-func_start)
em = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
em.mem_map(CODE_ADDRESS, CODE_SIZE)
# setup stack
em.reg_write(UC_ARM64_REG_SP, CODE_ADDRESS + 0x200000)
# write machine code
em.mem_write(CODE_ADDRESS, code)

em.hook_add(UC_HOOK_CODE, hook_code)
em.hook_add(UC_HOOK_BLOCK, hook_block)
# try:
#     em.emu_start(CODE_ADDRESS, CODE_ADDRESS+func_end-func_start)
# except UcError as e:
#     pc = em.reg_read(UC_ARM64_REG_PC)
#     print("ERROR: %s  pc:%x" % (e,pc))

# print(flow)

queue= [(relevant_blocks_start[0], None)]
while len(queue) != 0:
    rel_bb_cnt = 0
    item = queue.pop()
    start = item[0]
    context = item[1]
    set_context(em, context)

    # 真实块的后继块都是真实块那就不需要模拟执行确定执行顺序
    bb_succs = get_relevant_successors(start+func_start)
    if len(bb_succs) >= 2:
        flow[hex(start+func_start)] = bb_succs
        continue

    # 跳过已经模拟执行过的块
    if flow.get(hex(start+func_start)) is None:
        flow[hex(start+func_start)] = []
    else:
        continue

    try:
        em.emu_start(CODE_ADDRESS+start, 0x10000)
    except UcError as e:
        pc = em.reg_read(UC_ARM64_REG_PC)
        print("ERROR: %s  pc:%x" % (e,pc))

    flow[hex(func_start+start)].append(hex(dist_addr+func_start))
    # 处理分支
    set_context(em, context)
    if has_branch:
        rel_bb_cnt = 0
        try:
            em.emu_start(CODE_ADDRESS+start, 0x10000)
        except UcError as e:
            pc = em.reg_read(UC_ARM64_REG_PC)
            print("ERROR: %s  pc:%x" % (e,pc))

        if hex(dist_addr+func_start) not in flow[hex(func_start+start)]:
            flow[hex(func_start+start)].append(hex(dist_addr+func_start))

print(flow)
em.mem_unmap(CODE_ADDRESS, CODE_SIZE)