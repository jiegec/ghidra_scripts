#Add labels to data and change mutabilitiy to volatile where initial-exec tls
#relocations is located.
#@author Jiajie Chen
#@category ELF Relocations
#@keybinding 
#@menupath 
#@toolbar 
#@runtime Jython

from ghidra.framework.cmd import CompoundCmd
from ghidra.app.cmd.label import AddLabelCmd
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import MutabilitySettingsDefinition

cp = currentProgram
relocations = cp.getRelocationTable()

cmd = CompoundCmd("Add labels to tls relocations")
for rel in relocations.getRelocations():
    if rel.getType() == 0x12:
        # R_X86_64_TPOFF64
        addr = rel.getAddress()
        print("Found R_X86_64_TPOFF64 relocation @ 0x{}".format(addr))
        cmd.add(AddLabelCmd(addr, "TLS_{}".format(addr), SourceType.USER_DEFINED))

        # mark data as volatile
        # https://github.com/NationalSecurityAgency/ghidra/issues/7966
        data = cp.getListing().getDataAt(addr)
        if data is not None:
            settings = data.getDataType().getSettingsDefinitions()
            for definition in settings:
                if isinstance(definition, MutabilitySettingsDefinition):
                    definition.setChoice(data, MutabilitySettingsDefinition.VOLATILE)

cmd.applyTo(cp)
