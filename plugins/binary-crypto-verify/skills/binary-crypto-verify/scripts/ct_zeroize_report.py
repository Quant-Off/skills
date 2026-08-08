# Ghidra headless post-script: constant-time and zeroization instruction inventory.
#
# Classifies every instruction in the selected functions into the four buckets
# that matter for crypto verification, and emits a worklist for manual triage.
#
# THIS SCRIPT HAS NO DATA FLOW ANALYSIS. It reports every conditional branch,
# zero-store, division, and register-indexed load regardless of whether a secret
# is involved. Its output is a worklist, never a verdict.
#
# Usage (Ghidra 10+/11+, Jython 2.7):
#   analyzeHeadless <proj-dir> <proj-name> -import <binary> \
#     -scriptPath <dir-of-this-file> \
#     -postScript ct_zeroize_report.py [options]
#
# Options:
#   --functions a,b,c   Only these functions (substring match). Default: crypto-ish heuristic.
#   --all               Every function in the program. Overrides --functions.
#   --json <path>       Write the machine-readable report here.
#   --decompile         Include decompiled C for each function (slow, verbose).
#   --max-funcs N       Safety cap on analyzed functions (default 40).
#
# @category Crypto
# @runtime Jython

import json
import re

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

# Instructions whose latency is operand-dependent on common cores.
VARIABLE_LATENCY = set([
    "div", "idiv", "divl", "divq", "divw", "divb",
    "udiv", "sdiv", "fdiv", "divss", "divsd", "divps", "divpd",
    "sqrtss", "sqrtsd",
])

# Branchless conditional moves. Their presence is usually the DESIRED lowering
# of a constant-time select, so they are reported separately from branches.
COND_MOVES = set([
    "cmove", "cmovne", "cmovz", "cmovnz", "cmova", "cmovae", "cmovb", "cmovbe",
    "cmovg", "cmovge", "cmovl", "cmovle", "cmovs", "cmovns", "cmovo", "cmovno",
    "csel", "csinc", "csinv", "csneg", "cset", "csetm", "cinc", "cneg",
])

# Unconditional control flow, excluded from the branch bucket.
UNCONDITIONAL = set(["jmp", "b", "bl", "blr", "br", "call", "ret", "retn", "leave"])

# Bulk-memory helpers that may implement a wipe.
WIPE_CALLEES = re.compile(
    r"(explicit_bzero|memset_s|__memset_chk|SecureZeroMemory|OPENSSL_cleanse"
    r"|sodium_memzero|zeroize|bzero|memset)", re.I)

# Functions worth analyzing when the caller gave no explicit list.
CRYPTO_HINT = re.compile(
    r"(crypt|cipher|aes|chacha|poly1305|salsa|sha|hmac|hkdf|kdf|pbkdf|argon|scrypt"
    r"|sign|verify|ecdsa|eddsa|ed25519|x25519|curve|rsa|dh\b|kem|kyber|dilithium"
    r"|key|secret|priv|nonce|seed|zeroize|cleanse|wipe|mac\b|tag\b|auth)", re.I)


def parse_args(raw):
    opts = {
        "functions": [],
        "all": False,
        "json": None,
        "decompile": False,
        "max_funcs": 40,
    }
    i = 0
    while i < len(raw):
        a = raw[i]
        if a == "--functions" and i + 1 < len(raw):
            opts["functions"] = [s.strip() for s in raw[i + 1].split(",") if s.strip()]
            i += 2
        elif a == "--json" and i + 1 < len(raw):
            opts["json"] = raw[i + 1]
            i += 2
        elif a == "--max-funcs" and i + 1 < len(raw):
            try:
                opts["max_funcs"] = int(raw[i + 1])
            except ValueError:
                pass
            i += 2
        elif a == "--all":
            opts["all"] = True
            i += 1
        elif a == "--decompile":
            opts["decompile"] = True
            i += 1
        else:
            i += 1
    return opts


def writes_zero(ins):
    """True if the instruction plausibly stores a zero to memory."""
    mnem = ins.getMnemonicString().lower()
    text = ins.toString().lower()

    # aarch64: the zero register is the canonical wipe source.
    if mnem in ("str", "stp", "stur", "sturh", "sturb", "strh", "strb"):
        return ("xzr" in text or "wzr" in text)

    # x86-64: immediate-zero store, or a store from a register the compiler
    # zeroed. Only the immediate form is detectable without data flow.
    if mnem.startswith("mov") or mnem in ("movups", "movaps", "movdqa", "movdqu", "movnti"):
        if ins.getNumOperands() < 2:
            return False
        # Destination must be memory.
        try:
            from ghidra.program.model.lang import OperandType
            if not OperandType.isAddress(ins.getOperandType(0)) and \
               "[" not in ins.getDefaultOperandRepresentation(0):
                return False
        except Exception:
            if "[" not in text:
                return False
        try:
            scalar = ins.getScalar(1)
            if scalar is not None and scalar.getValue() == 0:
                return True
        except Exception:
            pass
        # xmm stores from a register that was zeroed by pxor/xorps are common;
        # flag them as candidates for manual confirmation.
        return mnem in ("movups", "movaps", "movdqa", "movdqu")

    # rep stosb / stosq with a zeroed accumulator.
    if "stos" in mnem:
        return True

    return False


def indexed_by_register(ins):
    """True if a memory operand uses a register as an index (possible secret-dependent load)."""
    text = ins.getDefaultOperandRepresentation(0) if ins.getNumOperands() else ""
    for i in range(ins.getNumOperands()):
        try:
            rep = ins.getDefaultOperandRepresentation(i)
        except Exception:
            continue
        # x86: [base + index*scale], aarch64: [base, xN, lsl #k]
        if re.search(r"\[[^\]]*[+,]\s*[a-z]\w*\s*(\*\s*[1248])?", rep, re.I):
            if re.search(r"(rip|pc)\b", rep, re.I):
                continue  # RIP-relative is a constant address
            return True
    return text and False


def classify(func, listing):
    """Bucket every instruction in the function body."""
    out = {
        "branches": [],
        "cond_moves": [],
        "zero_stores": [],
        "variable_latency": [],
        "indexed_loads": [],
        "wipe_calls": [],
        "instruction_count": 0,
    }
    for ins in listing.getInstructions(func.getBody(), True):
        out["instruction_count"] += 1
        mnem = ins.getMnemonicString().lower()
        rec = {"addr": str(ins.getAddress()), "insn": ins.toString()}

        if mnem in COND_MOVES:
            out["cond_moves"].append(rec)
        elif mnem in UNCONDITIONAL:
            # A call may still be a wipe helper.
            flows = []
            try:
                flows = [str(r.getToAddress()) for r in ins.getReferencesFrom()]
            except Exception:
                pass
            if WIPE_CALLEES.search(ins.toString()):
                out["wipe_calls"].append(rec)
        elif ins.getFlowType().isConditional():
            out["branches"].append(rec)

        if mnem in VARIABLE_LATENCY:
            out["variable_latency"].append(rec)
        if writes_zero(ins):
            out["zero_stores"].append(rec)
        if indexed_by_register(ins):
            out["indexed_loads"].append(rec)
        if WIPE_CALLEES.search(ins.toString()) and rec not in out["wipe_calls"]:
            out["wipe_calls"].append(rec)

    return out


def select_functions(program, opts):
    fm = program.getFunctionManager()
    every = list(fm.getFunctions(True))
    if opts["all"]:
        chosen = every
    elif opts["functions"]:
        chosen = []
        for fn in every:
            name = fn.getName()
            for want in opts["functions"]:
                if want.lower() in name.lower():
                    chosen.append(fn)
                    break
    else:
        chosen = [fn for fn in every if CRYPTO_HINT.search(fn.getName())]
    return chosen


def main():
    program = currentProgram  # noqa: F821 (Ghidra injects this)
    opts = parse_args(list(getScriptArgs()))  # noqa: F821

    listing = program.getListing()
    lang = program.getLanguage()
    meta = {
        "program": program.getName(),
        "arch": str(lang.getProcessor()),
        "endian": "big" if lang.isBigEndian() else "little",
        "pointer_bits": program.getDefaultPointerSize() * 8,
        "compiler": str(program.getCompilerSpec().getCompilerSpecID()),
    }

    chosen = select_functions(program, opts)
    truncated = False
    if len(chosen) > opts["max_funcs"]:
        truncated = True
        chosen = chosen[:opts["max_funcs"]]

    decompiler = None
    if opts["decompile"]:
        decompiler = DecompInterface()
        decompiler.openProgram(program)
    monitor = ConsoleTaskMonitor()

    report = {"meta": meta, "functions": [], "truncated": truncated}

    print("== ct_zeroize_report ==")
    print("program=%s arch=%s compiler=%s" % (meta["program"], meta["arch"], meta["compiler"]))
    if not chosen:
        print("NO FUNCTIONS MATCHED. Pass --functions <names> or --all.")

    for fn in chosen:
        buckets = classify(fn, listing)
        entry = {
            "name": fn.getName(),
            "entry": str(fn.getEntryPoint()),
            "size": fn.getBody().getNumAddresses(),
        }
        entry.update(buckets)

        if decompiler is not None:
            try:
                res = decompiler.decompileFunction(fn, 60, monitor)
                if res.decompileCompleted():
                    entry["decompiled"] = res.getDecompiledFunction().getC()
            except Exception as exc:
                entry["decompile_error"] = str(exc)

        report["functions"].append(entry)

        print("")
        print("-- %s @ %s  (%d instructions)" % (entry["name"], entry["entry"], buckets["instruction_count"]))
        print("   conditional branches : %d" % len(buckets["branches"]))
        print("   conditional moves    : %d" % len(buckets["cond_moves"]))
        print("   zero stores          : %d" % len(buckets["zero_stores"]))
        print("   wipe helper calls    : %d" % len(buckets["wipe_calls"]))
        print("   variable latency     : %d" % len(buckets["variable_latency"]))
        print("   register-indexed mem : %d" % len(buckets["indexed_loads"]))

        if not buckets["zero_stores"] and not buckets["wipe_calls"]:
            print("   NOTE: no wipe evidence in this function. If the source wipes a")
            print("         secret here, dead-store elimination is the likely cause.")

        for label in ("zero_stores", "wipe_calls", "variable_latency", "indexed_loads", "branches"):
            for rec in buckets[label][:25]:
                print("   %-16s %s  %s" % (label, rec["addr"], rec["insn"]))
            if len(buckets[label]) > 25:
                print("   %-16s ... %d more (see --json output)" % (label, len(buckets[label]) - 25))

    if truncated:
        print("")
        print("WARNING: function list truncated to %d. Raise --max-funcs to cover the rest."
              % opts["max_funcs"])

    print("")
    print("Every item above is a WORKLIST ENTRY, not a finding. Trace each operand")
    print("to a named secret before reporting. Untraceable items must be recorded")
    print("as inspected and dismissed, not silently dropped.")

    if opts["json"]:
        try:
            with open(opts["json"], "w") as handle:
                json.dump(report, handle, indent=2, sort_keys=True)
            print("wrote %s" % opts["json"])
        except Exception as exc:
            print("failed to write JSON report: %s" % exc)

    if decompiler is not None:
        decompiler.dispose()


main()
