# -*- coding: utf-8 -*-
#@category Mothra

"""
Highlights EVM instructions from StructLogs until the first CALL opcode.
Compatible with PyGhidra (no emoji, no f-string, no GhidraScript subclass).
"""

from java.awt import Color
from ghidra.program.model.address import AddressSet
from ghidra.program.util import ProgramSelection
from ghidra.app.events import ProgramHighlightPluginEvent

def getContractForAddress(pc, contract_table, default_space):
    """Find which contract a program counter belongs to"""
    if contract_table is None:
        return None
    
    addr = default_space.getAddress(pc)
    addr_offset = addr.getOffset()
    
    contract_iter = contract_table.iterator()
    while contract_iter.hasNext():
        record = contract_iter.next()
        base_offset = record.getLongValue(1)
        contract_addr = record.getString(0)
        
        if base_offset <= addr_offset < base_offset + 0x10000:
            return {
                'address': contract_addr,
                'offset': base_offset
            }
    return None

prog = currentProgram
tool = state.getTool()
db = prog.getDBHandle()
addr_factory = prog.getAddressFactory()
default_space = addr_factory.getDefaultAddressSpace()

contract_table = db.getTable("ContractInfo")
struct_logs_table = db.getTable("StructLogs")

if struct_logs_table is None:
    print("StructLogs table not found.")
else:
    highlight_set = AddressSet()
    logs_iter = struct_logs_table.iterator()

    while logs_iter.hasNext():
        record = logs_iter.next()
        pc = record.getIntValue(0)
        opcode = record.getString(1)
        addr = default_space.getAddress(pc)
        highlight_set.add(addr)
        
        if opcode in ["CALL", "STATICCALL", "DELEGATECALL", "CALLCODE"]:
            print("Stopping at CALL (pc={})".format(pc))
            break

    selection = ProgramSelection(highlight_set)
    event = ProgramHighlightPluginEvent("StructLog Highlight", selection, prog)
    tool.firePluginEvent(event)

    print("Highlighted {} instruction(s).".format(highlight_set.getNumAddresses()))
