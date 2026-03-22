# BinShield Ghidra Decompilation Script
# Runs inside Ghidra headless via analyzeHeadless -postScript.
# Jython 2.7 compatible -- no f-strings, no type hints, print as statement.
#
# Outputs a single JSON object to a file specified by the BINSHIELD_OUTPUT
# environment variable (falls back to stdout).

import json
import os
import sys

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.listing import Function


def get_all_functions(program):
    """Return all functions in the program, sorted by size descending."""
    fm = program.getFunctionManager()
    funcs = []
    it = fm.getFunctions(True)
    while it.hasNext():
        funcs.append(it.next())
    funcs.sort(key=lambda f: f.getBody().getNumAddresses(), reverse=True)
    return funcs


def decompile_functions(program, functions, max_functions=60, max_chars=120000):
    """Decompile the top functions by size, returning pseudo-C source."""
    decomp = DecompInterface()
    options = DecompileOptions()
    decomp.setOptions(options)
    decomp.openProgram(program)
    monitor = ConsoleTaskMonitor()

    sources = []
    total_chars = 0

    for func in functions[:max_functions]:
        result = decomp.decompileFunction(func, 30, monitor)
        if result is None or result.depiledFunction() is None:
            # Try with getDecompiledFunction for different Ghidra versions
            try:
                decomp_func = result.getDecompiledFunction() if result else None
            except Exception:
                decomp_func = None
            if decomp_func is None:
                continue
            code = decomp_func.getC()
        else:
            code = result.getDecompiledFunction().getC()

        if code:
            if total_chars + len(code) > max_chars:
                remaining = max_chars - total_chars
                if remaining > 200:
                    sources.append(code[:remaining] + "\n// ... truncated")
                break
            sources.append(code)
            total_chars += len(code)

    decomp.dispose()
    return "\n\n".join(sources)


def get_imports(program):
    """Extract imported symbol names."""
    st = program.getSymbolTable()
    imports = []
    it = st.getExternalSymbols()
    while it.hasNext():
        sym = it.next()
        name = sym.getName()
        if name and name not in imports:
            imports.append(name)
    return imports


def get_strings(program, max_strings=500):
    """Extract defined string data from the program."""
    listing = program.getListing()
    strings = []
    data_it = listing.getDefinedData(True)
    while data_it.hasNext():
        d = data_it.next()
        dt = d.getDataType()
        if dt is not None and "string" in dt.getName().lower():
            val = d.getValue()
            if val is not None:
                s = str(val).strip()
                if 3 <= len(s) <= 2000:
                    strings.append(s)
                    if len(strings) >= max_strings:
                        break
    return strings


def get_call_targets(program, functions):
    """Collect unique call target names across all functions."""
    targets = set()
    for func in functions:
        called = func.getCalledFunctions(None)
        if called:
            for cf in called:
                name = cf.getName()
                if name:
                    targets.add(name)
    return list(targets)


def compute_confidence(program, functions, pseudo_source):
    """Heuristic confidence score based on analysis quality."""
    if not functions:
        return 0.1

    score = 0.5

    # More functions decompiled -> higher confidence
    decompiled_ratio = min(len(pseudo_source) / max(1, len(functions) * 100), 1.0)
    score += decompiled_ratio * 0.2

    # Recognized format boosts confidence
    exe_format = program.getExecutableFormat()
    if exe_format and exe_format.lower() in ("elf", "pe", "mach-o", "macho"):
        score += 0.15

    # Having imports is a good sign
    st = program.getSymbolTable()
    ext_count = 0
    it = st.getExternalSymbols()
    while it.hasNext():
        it.next()
        ext_count += 1
        if ext_count > 5:
            break
    if ext_count > 5:
        score += 0.1

    return round(min(score, 0.98), 2)


def main():
    program = currentProgram  # noqa: F821 -- injected by Ghidra
    if program is None:
        print("ERROR: No program loaded")
        sys.exit(1)

    functions = get_all_functions(program)
    pseudo_source = decompile_functions(program, functions)
    imports = get_imports(program)
    strings = get_strings(program)
    call_targets = get_call_targets(program, functions)
    confidence = compute_confidence(program, functions, pseudo_source)

    result = {
        "pseudoSource": pseudo_source if pseudo_source else "// No functions could be decompiled",
        "imports": imports,
        "strings": strings,
        "functionCount": len(functions),
        "callTargets": call_targets,
        "confidence": confidence,
    }

    output_path = os.environ.get("BINSHIELD_OUTPUT", "")
    payload = json.dumps(result)

    if output_path:
        with open(output_path, "w") as f:
            f.write(payload)
        print("BINSHIELD_RESULT_WRITTEN:" + output_path)
    else:
        print("BINSHIELD_JSON_START")
        print(payload)
        print("BINSHIELD_JSON_END")


main()
