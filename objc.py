import re
from ghidra.program.model.data import DataTypeConflictHandler
from ghidra.program.model.data import EndianSettingsDefinition
from ghidra.program.model.data import DataUtilities
from ghidra.program.model.symbol import SourceType
from ghidra.app.util.cparser.C import CParser

# https://reverseengineering.stackexchange.com/questions/23330/ghidra-python-create-struct-with-big-endian-field


def create_datatype(txt):
    data_type_manager = currentProgram.getDataTypeManager()
    parser = CParser(data_type_manager)
    parsed_datatype = parser.parse(txt)
    datatype = data_type_manager.addDataType(
        parsed_datatype, DataTypeConflictHandler.DEFAULT_HANDLER)
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
    struct objc_method {
        uint64_t method_name: 48;
        uint64_t ignore1: 16;
        uint64_t method_type: 48;
        uint64_t ignore2: 16;
        uint64_t method_imp: 48;
        uint64_t ignore3: 16;
    };
    struct objc_method_list {
        uint32_t obsolete;
        uint32_t method_count;
    };
    struct objc_data {
        uint32_t flags;
        uint32_t instance_start;
        uint32_t instance_size;
        uint32_t reserved;
        uint64_t ivar_layout;
        uint64_t name: 48;
        uint64_t ignore1: 16;
        uint64_t method_list: 48;
        uint64_t ignore2: 16;
        uint64_t base_protocols: 48;
        uint64_t ignore3: 16;
        uint64_t ivars: 48;
        uint64_t ignore4: 16;
        uint64_t weak_ivar_layout;
        uint64_t base_properties: 48;
        uint64_t ignore5: 16;
    };
    struct objc_ivars_list {
        uint32_t entry_size;
        uint32_t ivars_count;
    };
    struct objc_ivar {
        uint64_t offset: 48;
        uint64_t ignore1: 16;
        uint64_t name: 48;
        uint64_t ignore2: 16;
        uint64_t type: 48;
        uint64_t ignore3: 16;
        uint32_t flag;
        uint32_t size;
    };
    struct objc_property_list {
        uint32_t flag;
        uint32_t property_count;
    };
    struct objc_property {
        uint64_t name: 48;
        uint64_t ignore1: 16;
        uint64_t attribute: 48;
        uint64_t ignore2: 16;
    };
    """)

    objc_class = currentProgram.getDataTypeManager().findDataType("/objc_class")
    objc_data = currentProgram.getDataTypeManager().findDataType("/objc_data")

    objc_method = currentProgram.getDataTypeManager().findDataType("/objc_method")
    objc_method_list = currentProgram.getDataTypeManager().findDataType("/objc_method_list")

    objc_ivars_list = currentProgram.getDataTypeManager().findDataType("/objc_ivars_list")
    objc_ivar = currentProgram.getDataTypeManager().findDataType("/objc_ivar")

    objc_property_list = currentProgram.getDataTypeManager().findDataType("/objc_property_list")
    objc_property = currentProgram.getDataTypeManager().findDataType("/objc_property")

    cp = currentProgram

    # iterate method names
    method_names = {}
    for seg in cp.memory.blocks:
        if seg.name == '__objc_methname':
            print('found section {} @ {}, collecting method names'.format(
                seg.name, seg.start))
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
            print('found section {} @ {}, adding labels for selectors'.format(
                seg.name, seg.start))
            codeUnits = cp.getListing().getCodeUnits(seg.start, True)
            while codeUnits.hasNext():
                cu = codeUnits.next()
                if cu and cu.address < seg.end:
                    real_addr = cu.address.getNewAddress(
                        cu.getLong(0) & 0x7ffffffffffff)
                    if real_addr in method_names:
                        createLabel(cu.address, '@selector({})'.format(
                            method_names[real_addr]), True)
                else:
                    break

    # iterate cstrings
    strings = {}
    for seg in cp.memory.blocks:
        if seg.name == '__cstring':
            print('found section {} @ {}, collecting for strings'.format(
                seg.name, seg.start))
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
            print('found section {} @ {}, adding labels for strings'.format(
                seg.name, seg.start))
            codeUnits = cp.getListing().getCodeUnits(seg.start, True)
            while codeUnits.hasNext():
                cu = codeUnits.next()
                if cu and cu.address < seg.end:
                    real_addr = cu.address.getNewAddress(
                        cu.getLong(16) & 0x0fffffffffffff)
                    string = getDataAt(real_addr).getValue()
                    string = re.sub(r'[^0-9a-zA-Z:@%]', '_', string)
                    createLabel(
                        cu.address, '@cfstring({})'.format(string), True)
                else:
                    break

    # iterate classes
    classes = set()
    for seg in cp.memory.blocks:
        if seg.name == '__objc_classlist':
            print('found section {} @ {}, adding labels for classes'.format(
                seg.name, seg.start))
            codeUnits = cp.getListing().getCodeUnits(seg.start, True)
            while codeUnits.hasNext():
                cu = codeUnits.next()
                if cu and cu.address < seg.end:
                    # define obj_class struct
                    class_addr = cu.address.getNewAddress(
                        cu.getValue().getOffset() & 0x7ffffffffffff)
                    classes.add(class_addr)

                    # find metaclass
                    data = getDataAt(class_addr)
                    metaclass_addr = cu.address.getNewAddress(
                        data.getLong(0) & 0x7ffffffffffff)
                    while metaclass_addr not in classes and metaclass_addr.getOffset() >= 0x100000000:

                        # recursive
                        data = getDataAt(metaclass_addr)
                        metaclass_addr = cu.address.getNewAddress(
                            data.getLong(0) & 0x7ffffffffffff)

                else:
                    break

    # analyze classes
    for class_addr in classes:
        data = getDataAt(class_addr)
        DataUtilities.createData(currentProgram, class_addr, objc_class,
                                 0, False, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA)


        # find data
        data_addr = cu.address.getNewAddress(
            data.getLong(32) & 0x7ffffffffffff)
        # define obj_data struct
        DataUtilities.createData(currentProgram, data_addr, objc_data,
                                 0, False, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA)
        name_addr = cu.address.getNewAddress(
            getDataAt(data_addr).getLong(24) & 0x0ffffffffffff)
        class_name = getDataAt(name_addr).getValue()

        # find method list
        method_list_addr_raw = getDataAt(
            data_addr).getLong(32) & 0x0ffffffffffff
        method_list_addr = cu.address.getNewAddress(
            method_list_addr_raw)
        if method_list_addr_raw != 0:
            # define objc_method_list struct
            DataUtilities.createData(currentProgram, method_list_addr, objc_method_list,
                                     0, False, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA)

            method_count = getDataAt(method_list_addr).getInt(4)

            # define objc_method struct
            for i in range(method_count):
                method_addr = cu.address.getNewAddress(
                    method_list_addr_raw + 8 + 24 * i)
                DataUtilities.createData(
                    currentProgram, method_addr, objc_method, 0, False, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA)
                method_name_addr = cu.address.getNewAddress(
                    getDataAt(method_addr).getLong(0) & 0x7fffffffffff)
                method_name = getDataAt(method_name_addr)
                createLabel(method_addr, '{}::{}'.format(
                    class_name, method_name.getValue()), True)

                # get imp addr
                imp_addr = cu.address.getNewAddress(
                    (getDataAt(method_addr).getLong(16) & 0xfffffffffff) + 0x100000000)
                imp = getFunctionAt(imp_addr)
                name = '{}::{}'.format(
                        class_name, method_name.getValue())
                if imp:
                    imp.setName(name, SourceType.ANALYSIS)
                else:
                    print('adding function {} at {}'.format(name, imp_addr))
                    disassemble(imp_addr)
                    createFunction(imp_addr, name)

        # find ivars
        ivars_addr_raw = getDataAt(
            data_addr).getLong(48) & 0x0ffffffffffff
        ivars_addr = cu.address.getNewAddress(
            ivars_addr_raw)
        if ivars_addr_raw != 0:
            # define objc_ivars_list struct
            DataUtilities.createData(currentProgram, ivars_addr, objc_ivars_list,
                                     0, False, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA)
            ivars_count = getDataAt(ivars_addr).getInt(4)

            # define objc_ivar struct
            for i in range(ivars_count):
                ivar_addr = cu.address.getNewAddress(
                    ivars_addr_raw + 8 + 32 * i)
                DataUtilities.createData(
                    currentProgram, ivar_addr, objc_ivar, 0, False, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA)

        # find propertys
        property_list_addr_raw = getDataAt(
            data_addr).getLong(64) & 0x0ffffffffffff
        property_list_addr = cu.address.getNewAddress(
            property_list_addr_raw)
        if property_list_addr_raw != 0:
            # define objc_property_list struct
            DataUtilities.createData(currentProgram, property_list_addr, objc_property_list,
                                     0, False, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA)
            property_count = getDataAt(property_list_addr).getInt(4)

            # define objc_property struct
            for i in range(property_count):
                property_addr = cu.address.getNewAddress(
                    property_list_addr_raw + 8 + 16 * i)
                DataUtilities.createData(
                    currentProgram, property_addr, objc_property, 0, False, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA)

        # create label
        createLabel(cu.address, '{}'.format(class_name), True)
        createLabel(
            class_addr, '{}_class'.format(class_name), True)
        createLabel(data_addr, '{}_data'.format(class_name), True)
        if method_list_addr_raw != 0:
            createLabel(method_list_addr, '{}_method_list'.format(
                getDataAt(name_addr).getValue()), True)
