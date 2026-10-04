# seccompc — Linux x86-64 seccomp 策略编译器与探针

不依赖 libseccomp，把 JSON 策略编译成可装载的 classic BPF seccomp 过滤器，
并配套最小 C 探针在**隔离子进程**中装载同一过滤器、执行固定无副作用探针，
核对真实内核返回值与 errno。目标是策略编译正确性，不是通用沙箱启动器。

## 文件

| 文件 | 说明 |
|---|---|
| `seccompc.py` | 编译器 CLI：编译 / 自测 / 生成探针计划 / 核对结果 |
| `probe.c` | 最小 C 探针（父进程保持无过滤，仅子进程装载过滤器） |
| `policies/*.json` | 测试策略（跨 2^32 区间、取反嵌套、首匹配遮蔽、长跳转） |
| `gen_longjump_policy.py` | 生成长跳转测试策略 |
| `run_tests.sh` | x86-64 宿主机一键端到端测试 |
| `vm_test.py` | 非 x86-64 宿主机（如 aarch64）的 qemu 客户机验证脚手架 |

## 策略格式

```json
{
  "default": {"action": "errno", "errno": 13},
  "rules": [
    {"name": "可选名字", "syscall": 39,
     "condition": {"and": [
        {"in_range": {"arg": 0, "lo": "4294967290", "hi": "4294967300"}},
        {"not": {"eq": {"arg": 1, "value": "0"}}}]},
     "action": {"action": "allow"}}
  ]
}
```

- 规则**按顺序**匹配，首个命中（syscall 号相等且条件成立）的规则决定结果；
  未命中执行 `default`（缺省为 `errno 13`）。
- 条件：`{"eq": {"arg": N, "value": "十进制字符串"}}`（无符号 64 位相等）、
  `{"in_range": {"arg": N, "lo": "..", "hi": ".."}}`（闭区间）、
  `{"and": [...]}`、`{"or": [...]}`、`{"not": ...}`；`arg` 为 0..5。
- 参数常量一律使用**十进制字符串**（可表达完整 u64）；每条规则最多
  **30 个比较条件**（eq/in_range 叶子）。
- 动作：`{"action": "allow"}` 或 `{"action": "errno", "errno": E}`（1..4095）。

## 用法

```bash
# 编译：输出原始过滤器、指令清单、规则来源映射
python3 seccompc.py compile policies/range64.json --outdir out/range64
#   out/range64/filter.bpf   原始 struct sock_filter 数组（可直接装载）
#   out/range64/listing.txt  指令清单（含跳转目标与规则归属）
#   out/range64/map.json     规则 -> 指令区间映射

# 自测：独立策略求值器 vs cBPF 解释器，对照合成 seccomp_data
python3 seccompc.py selftest policies/range64.json --filter out/range64/filter.bpf

# 端到端（x86-64 宿主机）：编译 + 自测 + 真实内核探针核对
bash run_tests.sh
```

## 生成的过滤器保证

- **先查 arch**：`seccomp_data.arch != AUDIT_ARCH_X86_64` 一律
  `SECCOMP_RET_KILL_PROCESS`；
- **拒绝 x32 编号位**：`nr & 0x40000000` 置位即 kill（策略层面也拒绝
  携带该位的 syscall 号）；
- **完整 64 位参数比较**：每个参数按高/低 32 位字分别比较，绝不截断成
  低 32 位（`eq 4294967296` 不会被参数 `0` 命中）；
- **不把指针值当指针内容**：seccomp classic BPF 只能读 `seccomp_data`，
  指针参数只按数值比较，不存在解引用；
- **短条件跳转距离限制**：超过 8 位（255 条）偏移的条件跳转自动改写为
  反条件 + 32 位 `JA` 蹦床，不动点迭代直到全部落入范围；
- **所有路径落到合法返回指令**：静态校验器检查跳转越界、RET 动作合法性
  （ALLOW / ERRNO / KILL_PROCESS）、无不可达指令、末条为 RET。

## 验证方法

1. **求值器 ↔ 解释器对照**：`selftest` 对每个策略合成数百个
   `seccomp_data`（叶子边界值、±1、2^32 邻域、u64 极值、截断陷阱、随机
   组合、错误 arch、x32 置位），逐一比较独立求值器与 cBPF 解释器（执行的
   是写出的 filter.bpf 文件本身）的结果。
2. **真实内核探针**：`probe` 父进程读取过滤器与探针计划后 fork；
   **仅子进程** `PR_SET_NO_NEW_PRIVS` + `PR_SET_SECCOMP` 装载过滤器
   （父进程永不装载），执行固定无副作用探针（期望 ALLOW 的用例只用
   getpid/getuid 等无参数无副作用调用；期望 ERRNO 的用例内核根本不会
   执行），结果经管道（fd 3，策略须显式放行 `write` 与 `exit_group`）
   回传父进程，最后与求值器期望逐条核对返回值与 errno。
3. 测试策略覆盖：跨越 2^32 的闭区间、u64 顶端区间、取反嵌套
   （NOT/NOT-NOT/NOT-AND/三重 NOT）、首匹配遮蔽（含被遮蔽的不可达
   规则）、以及单规则 30 路 OR 区间（编译出 ~690 条指令，强制 20 处
   长跳转改写）。

## 非 x86-64 宿主机

在 aarch64 等宿主机上，编译器与软件自测可原生运行；真实内核探针可
通过 `vm_test.py` 在 qemu-system-x86_64 客户机（静态探针作 /init，
结果经串口回传）中完成，见脚本头部注释。在本仓库的开发机上还做了
负向验证：aarch64 内核装载 x86-64 过滤器后，arch 检查如期 SIGSYS
杀死子进程。
