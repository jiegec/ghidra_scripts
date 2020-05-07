import re
from ghidra.program.model.data import DataTypeConflictHandler
from ghidra.program.model.data import EndianSettingsDefinition
from ghidra.program.model.data import DataUtilities
from ghidra.app.util.cparser.C import CParser

# https://reverseengineering.stackexchange.com/questions/23330/ghidra-python-create-struct-with-big-endian-field
def create_datatype(txt):
    data_type_manager = currentProgram.getDataTypeManager()
    parser = CParser(data_type_manager)
    parsed_datatype = parser.parse(txt)
    datatype = data_type_manager.addDataType(parsed_datatype, DataTypeConflictHandler.DEFAULT_HANDLER)
    return datatype

if __name__ == '__main__':

    # https://opensource.apple.com/source/objc4/objc4-237/runtime/objc-class.h.auto.html
    create_datatype("""
    struct objc_class {
        uint64_t metaclass;
        uint64_t superclass;
        uint64_t cache;
        uint64_t vtable;
        uint64_t data;
    };
    """)
    objc_class = currentProgram.getDataTypeManager().findDataType("/objc_class")

    create_datatype("""
    struct objc_method {
        uint64_t method_name;
        uint64_t method_type;
        uint64_t method_imp;
    };
    """)
    objc_method= currentProgram.getDataTypeManager().findDataType("/objc_method")

    create_datatype("""
    struct objc_method_list {
        uint32_t obsolete;
        uint32_t method_count;
    };
    """)
    objc_method_list = currentProgram.getDataTypeManager().findDataType("/objc_method_list")

    create_datatype("""
    struct objc_data {
        uint32_t flags;
        uint32_t instance_start;
        uint32_t instance_size;
        uint32_t reserved;
        uint64_t ivar_layout;
        uint64_t name;
        uint64_t method_list;
        uint64_t base_protocols;
        uint64_t ivars;
        uint64_t weak_ivar_layout;
        uint64_t base_properties;
    };
    """)
    objc_data = currentProgram.getDataTypeManager().findDataType("/objc_data")

    cp = currentProgram

    # iterate method names
    method_names = {}
    for seg in cp.memory.blocks:
        if seg.name == '__objc_methname':
            print('found section {} @ {}, collecting method names'.format(seg.name, seg.start))
            codeUnits = cp.getListing().getCodeUnits(seg.start, True)
            while codeUnits.hasNext():
                cu = codeUnits.next()
                if cu and cu.address < seg.end:
                    method_names[cu.address] = cu.value
                else:
                    break

    # iterate selectors
    for seg in cp.memory.blocks:
        if seg.name == '__objc_selrefs':
            print('found section {} @ {}, adding labels for selectors'.format(seg.name, seg.start))
            codeUnits = cp.getListing().getCodeUnits(seg.start, True)
            while codeUnits.hasNext():
                cu = codeUnits.next()
                if cu and cu.address < seg.end:
                    real_addr = cu.address.getNewAddress(cu.getLong(0) & 0x7ffffffffffff)
                    if real_addr in method_names:
                        createLabel(cu.address, '@selector({})'.format(method_names[real_addr]), True)
                else:
                    break

    # iterate cstrings
    strings = {}
    for seg in cp.memory.blocks:
        if seg.name == '__cstring':
            print('found section {} @ {}, collecting for strings'.format(seg.name, seg.start))
            codeUnits = cp.getListing().getCodeUnits(seg.start, True)
            while codeUnits.hasNext():
                cu = codeUnits.next()
                if cu and cu.address < seg.end:
                    strings[cu.address] = cu.value
                else:
                    break

    # iterate cfstrings
    for seg in cp.memory.blocks:
        if seg.name == '__cfstring':
            print('found section {} @ {}, adding labels for strings'.format(seg.name, seg.start))
            codeUnits = cp.getListing().getCodeUnits(seg.start, True)
            while codeUnits.hasNext():
                cu = codeUnits.next()
                if cu and cu.address < seg.end:
                    real_addr = cu.address.getNewAddress(cu.getLong(16) & 0x0fffffffffffff)
                    string = getDataAt(real_addr).getValue()
                    string = re.sub(r'[^0-9a-zA-Z:@%]','_', string)
                    createLabel(cu.address, '@cfstring({})'.format(string), True)
                else:
                    break

    # iterate classes
    for seg in cp.memory.blocks:
        if seg.name == '__objc_classlist':
            print('found section {} @ {}, adding labels for classes'.format(seg.name, seg.start))
            codeUnits = cp.getListing().getCodeUnits(seg.start, True)
            while codeUnits.hasNext():
                cu = codeUnits.next()
                if cu and cu.address < seg.end:
                    # define obj_class struct
                    class_addr = cu.address.getNewAddress(cu.getValue().getOffset() & 0x7ffffffffffff)
                    DataUtilities.createData(currentProgram, class_addr, objc_class, 0, False, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA)

                    # find metaclass
                    data = getDataAt(class_addr)
                    metaclass_addr = cu.address.getNewAddress(data.getLong(0) & 0x7ffffffffffff)
                    # define obj_class struct
                    DataUtilities.createData(currentProgram, metaclass_addr, objc_class, 0, False, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA)
                    metaclass = getDataAt(metaclass_addr)

                    # find data
                    data_addr = cu.address.getNewAddress(data.getLong(32) & 0x7ffffffffffff)
                    # define obj_data struct
                    DataUtilities.createData(currentProgram, data_addr, objc_data, 0, False, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA)
                    name_addr = cu.address.getNewAddress(getDataAt(data_addr).getLong(24) & 0x0ffffffffffff)

                    # find method list
                    method_list_addr_raw = getDataAt(data_addr).getLong(32) & 0x0ffffffffffff
                    method_list_addr = cu.address.getNewAddress(method_list_addr_raw)
                    if method_list_addr_raw != 0:
                        # define objc_method_list struct
                        method_count = getDataAt(method_list_addr).getInt(4)
                        DataUtilities.createData(currentProgram, method_list_addr, objc_method_list, 0, False, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA)

                        # define objc_method struct
                        for i in range(method_count):
                            method_addr = method_list_addr_raw + 8 + 24 * i
                            DataUtilities.createData(currentProgram, cu.address.getNewAddress(method_addr), objc_method, 0, False, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA)
                    
                    # create label
                    if getDataAt(name_addr):
                        createLabel(cu.address, '{}'.format(getDataAt(name_addr).getValue()), True)
                        createLabel(class_addr, '{}_class'.format(getDataAt(name_addr).getValue()), True)
                        createLabel(data_addr, '{}_data'.format(getDataAt(name_addr).getValue()), True)
                        if method_list_addr_raw != 0:
                            createLabel(method_list_addr, '{}_method_list'.format(getDataAt(name_addr).getValue()), True)
                    print('{} @ {}: {} {} {} {} {} {} {}'.format(cu.address, cu.value, metaclass_addr, metaclass, data_addr, name_addr, getDataAt(name_addr), method_list_addr, method_count))
                else:
                    break
