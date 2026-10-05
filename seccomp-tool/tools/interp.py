"""Minimal classic-BPF interpreter for seccomp programs (verification aid).

It loads the *raw* filter file produced by the compiler (or any byte string
of struct sock_filter records) and executes it against synthetic
``struct seccomp_data``::

    int nr;          __u32 arch;       __u64 instruction_pointer;
    __u64 args[6];

Only opcodes legal in seccomp filters are accepted. All loads are bounds
checked against the 64-byte seccomp_data image; register A is 32-bit and
seccomp args are read as two 32-bit words (the compiler never truncates the
full u64 itself -- it compares both words).
"""

import struct

BPF_CLASS_MASK = 0x07
BPF_LD, BPF_JMP, BPF_RET, BPF_ALU, BPF_MISC = 0x00, 0x05, 0x06, 0x04, 0x07
BPF_W, BPF_ABS, BPF_K, BPF_X = 0x00, 0x20, 0x00, 0x08
BPF_JA, BPF_JEQ, BPF_JGT, BPF_JGE, BPF_JSET = 0x00, 0x10, 0x20, 0x30, 0x40
BPF_AND, BPF_ADD = 0x50, 0x00

SECCOMP_DATA_LEN = 64
MAX_STEPS = 1_000_000


class BPFError(RuntimeError):
    pass


def load_program(blob):
    if len(blob) % 8:
        raise BPFError("filter size not a multiple of 8")
    return [struct.unpack_from("<HBBI", blob, i)
            for i in range(0, len(blob), 8)]


def pack_seccomp_data(nr, arch, args, ip=0):
    if len(args) != 6:
        raise ValueError("need exactly 6 args")
    return struct.pack("<IIQ6Q", nr & 0xFFFFFFFF, arch & 0xFFFFFFFF,
                       ip & 0xFFFFFFFFFFFFFFFF,
                       *[a & 0xFFFFFFFFFFFFFFFF for a in args])


def run(program, data, max_steps=MAX_STEPS):
    if len(data) != SECCOMP_DATA_LEN:
        raise BPFError("seccomp_data must be 64 bytes")
    a = 0
    x = 0
    pc = 0
    steps = 0
    n = len(program)
    while True:
        steps += 1
        if steps > max_steps:
            raise BPFError("step limit exceeded (non-terminating program?)")
        if pc >= n:
            raise BPFError("ran off end at pc=%d" % pc)
        code, jt, jf, k = program[pc]
        cls = code & BPF_CLASS_MASK
        if cls == BPF_LD:
            if code != (BPF_LD | BPF_W | BPF_ABS):
                raise BPFError("pc=%d unsupported LD 0x%02x" % (pc, code))
            if k + 4 > SECCOMP_DATA_LEN:
                raise BPFError("pc=%d LD out of bounds [%d]" % (pc, k))
            a = struct.unpack_from("<I", data, k)[0]
            pc += 1
        elif cls == BPF_JMP:
            op = code & 0xF0
            src = code & 0x08
            if code == (BPF_JMP | BPF_JA):
                pc += 1 + k
                continue
            if src != BPF_K:
                raise BPFError("pc=%d X-source jumps unsupported" % pc)
            if op == BPF_JEQ:
                pc += 1 + (jt if a == k else jf)
            elif op == BPF_JGT:
                pc += 1 + (jt if a > k else jf)
            elif op == BPF_JGE:
                pc += 1 + (jt if a >= k else jf)
            elif op == BPF_JSET:
                pc += 1 + (jt if (a & k) else jf)
            else:
                raise BPFError("pc=%d unsupported JMP op 0x%02x" % (pc, op))
        elif cls == BPF_RET:
            if code != (BPF_RET | BPF_K):
                raise BPFError("pc=%d only RET #k permitted" % pc)
            return k
        elif cls == BPF_ALU:
            op = code & 0xF0
            src = code & 0x08
            operand = x if src == BPF_X else k
            if op == BPF_AND:
                a &= operand
            elif op == BPF_ADD:
                a = (a + operand) & 0xFFFFFFFF
            else:
                raise BPFError("pc=%d unsupported ALU op 0x%02x" % (pc, op))
            pc += 1
        elif cls == BPF_MISC:
            if code == (BPF_MISC | 0x00):       # TAX
                x = a
            elif code == (BPF_MISC | 0x80):     # TXA
                a = x
            else:
                raise BPFError("pc=%d unsupported MISC 0x%02x" % pc)
            pc += 1
        else:
            raise BPFError("pc=%d illegal class 0x%02x" % (pc, cls))
