#Add labels to data where tls relocations is located.
#@author Jiajie Chen
#@category ELF Relocations
#@keybinding 
#@menupath 
#@toolbar 
#@runtime Jython

from ghidra.framework.cmd import CompoundCmd
from ghidra.app.cmd.label import AddLabelCmd
from ghidra.program.model.symbol import SourceType

cp = currentProgram
print(cp)
relocations = cp.getRelocationTable()
print(relocations)

cmd = CompoundCmd("Add labels to tls relocations")
for rel in relocations.getRelocations():
    if rel.getType() == 0x12:
        # R_X86_64_TPOFF64
        addr = rel.getAddress()
        print("Found R_X86_64_TPOFF64 relocation @ 0x{}".format(addr))
        cmd.add(AddLabelCmd(addr, "TLS_{}".format(addr), SourceType.USER_DEFINED))

cmd.applyTo(cp)
