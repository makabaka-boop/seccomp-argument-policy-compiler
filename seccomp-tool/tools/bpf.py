"""Classic BPF (cBPF) instruction model for seccomp filters.

Seccomp classic filters are arrays of ``struct sock_filter``::

    struct sock_filter {            /* Filter block */
        __u16  code;                /* Actual filter code */
        __u8   jt;                  /* Jump true  (8-bit, 0..255)   */
        __u8   jf;                  /* Jump false (8-bit, 0..255)   */
        __u32  k;                   /* Generic multiuse field       */
    };

Only the opcodes reachable from our emitted programs are modelled here.
"""

import struct

# ---------------------------------------------------------------------------
# Instruction classes (BPF_CLASS)
# ---------------------------------------------------------------------------
BPF_LD = 0x00
BPF_JMP = 0x05
BPF_RET = 0x06
BPF_ALU = 0x04
BPF_MISC = 0x07

# ld size / mode modifiers
BPF_W = 0x00
BPF_ABS = 0x20

# alu / jmp operations
BPF_ADD = 0x00
BPF_AND = 0x50
BPF_JA = 0x00
BPF_JEQ = 0x10
BPF_JGE = 0x30
BPF_JGT = 0x20
BPF_JSET = 0x40
BPF_K = 0x00
BPF_X = 0x08
BPF_TAX = 0x00
BPF_TXA = 0x80

# Addressing "source": 32-bit immediate k vs index register X
LD_ABS_W = BPF_LD | BPF_W | BPF_ABS          # 0x20
JMP_JA = BPF_JMP | BPF_JA                    # 0x05
JMP_JEQ_K = BPF_JMP | BPF_JEQ | BPF_K        # 0x15
JMP_JGT_K = BPF_JMP | BPF_JGT | BPF_K        # 0x25
JMP_JGE_K = BPF_JMP | BPF_JGE | BPF_K        # 0x35
ALU_AND_K = BPF_ALU | BPF_AND | BPF_K        # 0x54
ALU_ADD_X = BPF_ALU | BPF_ADD | BPF_X        # 0x0b
MISC_TAX = BPF_MISC | BPF_TAX                # 0x07
MISC_TXA = BPF_MISC | BPF_TXA                # 0x87
RET_K = BPF_RET | BPF_K                      # 0x06


class Insn:
    __slots__ = ("code", "jt", "jf", "k", "note",
                 "_jt_label", "_jf_label", "_target")

    def __init__(self, code, jt=0, jf=0, k=0, note=""):
        self.code = code
        self.jt = jt
        self.jf = jf
        self.k = k & 0xFFFFFFFF
        self._jt_label = None
        self._jf_label = None
        self._target = None
        # note: ("rule", rule_index) / ("expr", path) / ("arch",) ... for mapping
        self.note = note

    def packed(self):
        return struct.pack("<HBBI", self.code, self.jt & 0xFF, self.jf & 0xFF,
                           self.k)


# seccomp_data field offsets (struct seccomp_data, <linux/seccomp.h>)
OFF_NR = 0
OFF_ARCH = 4
OFF_INSTRUCTION_POINTER = 8
OFF_ARGS = 16          # args[0] .. args[5], each u64
SECCOM_DATA_SIZE = 64

# seccomp return values
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_KILL_THREAD = 0x00000000
SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_ERRNO = 0x00050000

MAX_FILTER_INSNS = 4096   # BPF_MAXINSNS (classic, user copies)
MAX_SHORT_JUMP = 255      # jt/jf are u8
