#!/usr/bin/env python3
"""
Mothra Prefetch Tool — Download trace data for offline analysis.

Downloads all data Mothra needs for transaction timeless debugging and saves
it in the CacheManager format. Copy the output directory to the target
machine's temp directory to enable offline analysis.

Usage:
    python mothra_prefetch.py <tx_hash> <rpc_url> [output_dir]

Examples:
    # Save to default directory (./eth-trace-cache)
    python mothra_prefetch.py 0xabc123... https://rpc.ankr.com/eth

    # Save to specific directory
    python mothra_prefetch.py 0xabc123... https://rpc.ankr.com/eth /path/to/output

    # Then copy to the offline machine's temp directory:
    #   Linux/macOS:  cp -r eth-trace-cache /tmp/eth-trace-cache
    #   Windows:      xcopy eth-trace-cache %TEMP%\\eth-trace-cache /E /I

Cache directory structure (matches Mothra's CacheManager):
    eth-trace-cache/
        call-traces/<txhash>.cache          — debug_traceTransaction (callTracer)
        instruction-traces/<txhash>.cache   — debug_traceTransaction (structLog)
        bytecode/<address>.cache            — eth_getCode (hex, no 0x prefix)
"""

import json
import os
import sys
import urllib.request
import urllib.error


def rpc_call(rpc_url, method, params):
    """Make a JSON-RPC call and return the raw JSON response string."""
    payload = json.dumps({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1,
    }).encode("utf-8")

    req = urllib.request.Request(
        rpc_url,
        data=payload,
        headers={"Content-Type": "application/json"},
    )

    try:
        with urllib.request.urlopen(req, timeout=600) as resp:
            return resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {e.code}: {body}") from e


def sanitize(value):
    """Remove 0x prefix and lowercase."""
    s = value.lower()
    if s.startswith("0x"):
        s = s[2:]
    return s


def extract_addresses(call_obj, addresses):
    """Recursively extract contract addresses from a callTracer result."""
    to = call_obj.get("to", "")
    if to and to != "0x":
        addresses.add(sanitize(to))

    from_addr = call_obj.get("from", "")
    if from_addr and from_addr != "0x":
        addresses.add(sanitize(from_addr))

    for child in call_obj.get("calls", []):
        extract_addresses(child, addresses)


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    tx_hash = sys.argv[1]
    rpc_url = sys.argv[2]
    output_dir = sys.argv[3] if len(sys.argv) > 3 else "eth-trace-cache"

    # Ensure 0x prefix for RPC calls
    if not tx_hash.startswith("0x"):
        tx_hash = "0x" + tx_hash

    tx_key = sanitize(tx_hash)

    # Create cache directories
    call_trace_dir = os.path.join(output_dir, "call-traces")
    instruction_trace_dir = os.path.join(output_dir, "instruction-traces")
    bytecode_dir = os.path.join(output_dir, "bytecode")
    os.makedirs(call_trace_dir, exist_ok=True)
    os.makedirs(instruction_trace_dir, exist_ok=True)
    os.makedirs(bytecode_dir, exist_ok=True)

    # --- 1. Fetch call trace ---
    call_trace_file = os.path.join(call_trace_dir, tx_key + ".cache")
    if os.path.exists(call_trace_file):
        print(f"[1/3] Call trace already cached: {call_trace_file}")
        with open(call_trace_file, "r") as f:
            call_trace_json = f.read()
    else:
        print(f"[1/3] Fetching call trace (debug_traceTransaction + callTracer)...")
        call_trace_json = rpc_call(rpc_url, "debug_traceTransaction", [
            tx_hash,
            {"tracer": "callTracer"},
        ])
        with open(call_trace_file, "w") as f:
            f.write(call_trace_json)
        print(f"      Saved to {call_trace_file}")

    # --- 2. Fetch instruction trace ---
    instr_trace_file = os.path.join(instruction_trace_dir, tx_key + ".cache")
    if os.path.exists(instr_trace_file):
        print(f"[2/3] Instruction trace already cached: {instr_trace_file}")
    else:
        print(f"[2/3] Fetching instruction trace (debug_traceTransaction + structLog)...")
        print(f"      This may take a while for complex transactions...")
        instr_trace_json = rpc_call(rpc_url, "debug_traceTransaction", [
            tx_hash,
            {
                "disableStorage": False,
                "disableMemory": False,
                "disableStack": False,
                "enableMemory": True,
                "enableReturnData": True,
            },
        ])
        with open(instr_trace_file, "w") as f:
            f.write(instr_trace_json)
        print(f"      Saved to {instr_trace_file}")

    # --- 3. Extract contract addresses and fetch bytecode ---
    print(f"[3/3] Fetching contract bytecode...")

    call_trace_data = json.loads(call_trace_json)
    result = call_trace_data.get("result", call_trace_data)

    addresses = set()
    extract_addresses(result, addresses)
    print(f"      Found {len(addresses)} contract address(es)")

    fetched = 0
    cached = 0
    skipped = 0

    for addr in sorted(addresses):
        bytecode_file = os.path.join(bytecode_dir, addr + ".cache")

        if os.path.exists(bytecode_file):
            cached += 1
            continue

        try:
            addr_with_prefix = "0x" + addr
            resp_json = rpc_call(rpc_url, "eth_getCode", [addr_with_prefix, "latest"])
            resp = json.loads(resp_json)
            bytecode = resp.get("result", "0x")

            if bytecode.startswith("0x"):
                bytecode = bytecode[2:]

            if bytecode and bytecode != "":
                with open(bytecode_file, "w") as f:
                    f.write(bytecode)
                fetched += 1
                size = len(bytecode) // 2
                print(f"      Fetched 0x{addr} ({size} bytes)")
            else:
                skipped += 1
                print(f"      Skipped 0x{addr} (EOA or precompile)")

        except Exception as e:
            skipped += 1
            print(f"      Error fetching 0x{addr}: {e}")

    print()
    print("=" * 60)
    print(f"Done! Cache saved to: {output_dir}")
    print(f"  Call trace:        1 file")
    print(f"  Instruction trace: 1 file")
    print(f"  Bytecode:          {fetched} fetched, {cached} cached, {skipped} skipped")
    print()
    print("To use on an offline machine, copy the directory to:")
    print(f"  Linux/macOS:  cp -r {output_dir} /tmp/eth-trace-cache")
    print(f"  Windows:      xcopy {output_dir} %TEMP%\\eth-trace-cache /E /I")
    print()


if __name__ == "__main__":
    main()
