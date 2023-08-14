from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.block import SimpleBlockModel
from ghidra.util.task import TaskMonitor
from ghidra.program.model.listing import Instruction
import json

args = getScriptArgs()
if len(args) < 1:
    exit(1)
out_filename = args[0]

program = getCurrentProgram()
bbm = SimpleBlockModel(program)
valid_symbols = {}
functions = {}

st = program.getSymbolTable()
for symbol in st.getAllSymbols(True):
    
    if symbol.getSymbolType() == SymbolType.LABEL and symbol.getAddress().isMemoryAddress() and symbol.hasReferences():
        if isinstance(symbol.getObject(), Instruction):
            continue

        for reference in symbol.getReferences(): 
            block = bbm.getCodeBlocksContaining(reference.getFromAddress(), TaskMonitor.DUMMY)[0]
            if block.getNumDestinations(TaskMonitor.DUMMY) or block.getNumSources(TaskMonitor.DUMMY):
                break
        else:
            continue
    
        valid_symbols[symbol.getName()] = symbol.getAddress().getUnsignedOffset()

fm = program.getFunctionManager()
funcs = fm.getFunctions(True)
for func in funcs: 
    functions[func.getName()] = func.getEntryPoint().getUnsignedOffset()


json.dump((valid_symbols, functions), open(out_filename, "w"))
