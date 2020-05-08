import re
from ghidra.program.model.data import DataTypeConflictHandler
from ghidra.program.model.data import DataUtilities
from ghidra.program.model.symbol import SourceType
from ghidra.app.util.cparser.C import CParser

# Referenced from:
# https://reverseengineering.stackexchange.com/questions/23330/ghidra-python-create-struct-with-big-endian-field
# https://github.com/PAGalaxyLab/ghidra_scripts/blob/master/AnalyzeOCMsgSend.py

def create_data_type(txt):
    data_type_manager = currentProgram.getDataTypeManager()
    parser = CParser(data_type_manager)
    parsed_datatype = parser.parse(txt)
    datatype = data_type_manager.addDataType(
        parsed_datatype, DataTypeConflictHandler.DEFAULT_HANDLER)
    return datatype


def getDataType(name):
    return currentProgram.getDataTypeManager().findDataType(name)


def to_address(addr):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addr)


def set_data(addr, ty):
    DataUtilities.createData(
        currentProgram, addr, ty, 0, False, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA)

def parse_method_list(method_list_addr_raw, class_name):
    if not (min_addr.getOffset() < method_list_addr_raw and method_list_addr_raw < max_addr.getOffset()):
        return

    method_list_addr = cu.address.getNewAddress(
        method_list_addr_raw)
    if method_list_addr_raw != 0:
        # define objc_method_list struct
        set_data(method_list_addr, objc_method_list)

        method_count = getDataAt(method_list_addr).getInt(4)

        # define objc_method struct
        for i in range(method_count):
            method_addr = to_address(
                method_list_addr_raw + 8 + 24 * i)
            set_data(method_addr, objc_method)
            method_name_addr = to_address(
                getDataAt(method_addr).getLong(0) & mask)
            method_name = getDataAt(method_name_addr)
            createLabel(method_addr, 'method_{}::{}'.format(
                class_name, method_name.getValue()), True)

            # get imp addr
            imp_addr = to_address(
                (getDataAt(method_addr).getLong(16) & mask) + text_section_addr)
            if min_addr < imp_addr and imp_addr < max_addr:
                imp = getFunctionAt(imp_addr)
                name = 'method_{}::{}'.format(
                    class_name, method_name.getValue())
                if imp:
                    imp.setName(name, SourceType.ANALYSIS)
                else:
                    print('adding function {} at {}'.format(name, imp_addr))
                    disassemble(imp_addr)
                    createFunction(imp_addr, name)

        createLabel(method_list_addr, 'method_list_{}'.format(
            class_name), True)


if __name__ == '__main__':

    # https://opensource.apple.com/source/objc4/objc4-237/runtime/objc-class.h.auto.html
    create_data_type("""
    struct objc_class {
        uint64_t metaclass: 48;
        uint64_t ignore1: 16;
        uint64_t superclass: 48;
        uint64_t ignore2: 16;
        uint64_t cache: 48;
        uint64_t ignore3: 16;
        uint64_t vtable: 48;
        uint64_t ignore4: 16;
        uint64_t data: 48;
        uint64_t ignore5: 16;
    };
    """)
    create_data_type("""
    struct objc_method {
        uint64_t method_name: 48;
        uint64_t ignore1: 16;
        uint64_t method_type: 48;
        uint64_t ignore2: 16;
        uint64_t method_imp: 48;
        uint64_t ignore3: 16;
    };
    """)
    create_data_type("""
    struct objc_method_list {
        uint32_t obsolete;
        uint32_t method_count;
    };
    """)
    create_data_type("""
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
    """)
    create_data_type("""
    struct objc_ivars_list {
        uint32_t entry_size;
        uint32_t ivars_count;
    };
    """)
    create_data_type("""
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
    """)
    create_data_type("""
    struct objc_property_list {
        uint32_t flag;
        uint32_t property_count;
    };
    """)
    create_data_type("""
    struct objc_property {
        uint64_t name: 48;
        uint64_t ignore1: 16;
        uint64_t attribute: 48;
        uint64_t ignore2: 16;
    };
    """)
    create_data_type("""
    struct objc_class_ref {
        uint64_t ref: 48;
        uint64_t ignore1: 16;
    };
    """)
    create_data_type("""
    struct objc_ref {
        uint64_t ref: 48;
        uint64_t ignore1: 16;
    };
    """)
    create_data_type("""
    struct objc_cfstring {
        uint64_t isa: 48;
        uint64_t ignore1: 16;
        uint64_t flags;
        uint64_t content: 48;
        uint64_t ignore2: 16;
        uint64_t len;
    };
    """)
    create_data_type("""
    struct objc_protocol {
        uint64_t isa: 48;
        uint64_t ignore1: 16;
        uint64_t name: 48;
        uint64_t ignore2: 16;
        uint64_t protocols: 48;
        uint64_t ignore3: 16;
        uint64_t instance_methods: 48;
        uint64_t ignore4: 16;
        uint64_t class_methods: 48;
        uint64_t ignore5: 16;
        uint64_t optional_instance_methods: 48;
        uint64_t ignore6: 16;
        uint64_t optional_class_methods: 48;
        uint64_t ignore7: 16;
        uint64_t instance_properties: 48;
        uint64_t ignore8: 16;
        uint32_t size;
        uint32_t flags;
        uint64_t extended_method_types: 48;
        uint64_t ignore10: 16;
        uint64_t demangled_name: 48;
        uint64_t ignore11: 16;
        uint64_t class_properties: 48;
        uint64_t ignore12: 16;
    };
    """)
    create_data_type("""
    struct objc_protocol_list {
        uint32_t protocol_count;
    };
    """)

    objc_class = getDataType("/objc_class")
    objc_data = getDataType("/objc_data")

    objc_method = getDataType("/objc_method")
    objc_method_list = getDataType("/objc_method_list")

    objc_ivars_list = getDataType("/objc_ivars_list")
    objc_ivar = getDataType("/objc_ivar")

    objc_property_list = getDataType("/objc_property_list")
    objc_property = getDataType("/objc_property")

    objc_protocol = getDataType("/objc_protocol")
    objc_protocol_list = getDataType("/objc_protocol_list")

    objc_ref = getDataType("/objc_ref")
    objc_cfstring = getDataType("/objc_cfstring")
    uint32_t = getDataType("/dword")

    cp = currentProgram
    # 48 bits
    mask = 0xffffffffffff

    min_addr = min([seg.start for seg in cp.memory.blocks])
    max_addr = max([seg.end for seg in cp.memory.blocks])
    print('addr range from {} to {}'.format(min_addr, max_addr))

    # find __TEXT section
    for seg in cp.memory.blocks:
        if seg.name == '__TEXT':
            text_section_addr = seg.start.getOffset()

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
    print('found {} methods'.format(len(method_names)))

    # iterate selectors
    for seg in cp.memory.blocks:
        if seg.name == '__objc_selrefs':
            print('found section {} @ {}, adding labels for selectors'.format(
                seg.name, seg.start))
            codeUnits = cp.getListing().getCodeUnits(seg.start, True)
            while codeUnits.hasNext():
                cu = codeUnits.next()
                if cu and cu.address < seg.end:
                    real_addr = to_address(
                        cu.getLong(0) & mask)
                    if real_addr in method_names:
                        # define obj_ref struct
                        set_data(cu.address, objc_ref)

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
    print('found {} strings'.format(len(strings)))

    # iterate cfstrings
    for seg in cp.memory.blocks:
        if seg.name == '__cfstring':
            print('found section {} @ {}, adding labels for strings'.format(
                seg.name, seg.start))
            codeUnits = cp.getListing().getCodeUnits(seg.start, True)
            while codeUnits.hasNext():
                cu = codeUnits.next()
                if cu and cu.address < seg.end:
                    real_addr = to_address(
                        cu.getLong(16) & mask)
                    string = getDataAt(real_addr).getValue()
                    string = re.sub(r'[^0-9a-zA-Z:@%;.,]', '_', string)
                    createLabel(
                        cu.address, 'cfstring_{}'.format(string), True)
                    set_data(cu.address, objc_cfstring)
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
                    # define obj_ref struct
                    set_data(cu.address, objc_ref)

                    # define obj_class struct
                    class_addr = to_address(
                        cu.getLong(0) & mask)
                    set_data(class_addr, objc_class)
                    classes.add(class_addr)

                    # find metaclass
                    data = getDataAt(class_addr)
                    metaclass_addr = to_address(
                        data.getLong(0) & mask)
                    while metaclass_addr not in classes and metaclass_addr >= min_addr:

                        # recursive
                        set_data(metaclass_addr, objc_class)
                        classes.add(metaclass_addr)
                        data = getDataAt(metaclass_addr)
                        metaclass_addr = to_address(
                            data.getLong(0) & mask)

                else:
                    break

    # analyze classes
    for class_addr in classes:
        print('class at {}'.format(class_addr))
        data = getDataAt(class_addr)
        set_data(class_addr, objc_class)

        # find data
        data_addr = to_address(
            data.getLong(32) & mask)
        # define obj_data struct
        set_data(data_addr, objc_data)
        name_addr = to_address(
            getDataAt(data_addr).getLong(24) & mask)
        class_name = getDataAt(name_addr).getValue()

        # find method list
        method_list_addr_raw = getDataAt(
            data_addr).getLong(32) & mask
        parse_method_list(method_list_addr_raw, class_name)

        # find base protocols list
        base_protocols_addr_raw = getDataAt(
            data_addr).getLong(40) & mask
        if base_protocols_addr_raw != 0:
            base_protocols_addr = to_address(
                base_protocols_addr_raw)
            # define objc_protocol_list struct
            set_data(base_protocols_addr, objc_protocol_list)

            protocol_count = getDataAt(base_protocols_addr).getInt(0)

            # define objc_ref struct
            for i in range(protocol_count):
                protocol_ref_addr = to_address(
                    base_protocols_addr_raw + 4 + 4 * i)
                set_data(protocol_ref_addr, objc_ref)

        # find ivars
        ivars_addr_raw = getDataAt(
            data_addr).getLong(48) & mask
        ivars_addr = to_address(
            ivars_addr_raw)
        if ivars_addr_raw != 0:
            # define objc_ivars_list struct
            set_data(ivars_addr, objc_ivars_list)
            ivars_count = getDataAt(ivars_addr).getInt(4)

            # define objc_ivar struct
            for i in range(ivars_count):
                ivar_addr = to_address(
                    ivars_addr_raw + 8 + 32 * i)
                set_data(ivar_addr, objc_ivar)

                # get ivar name
                ivar_name_addr = to_address(
                    getDataAt(ivar_addr).getLong(8) & mask)
                ivar_name = getDataAt(ivar_name_addr).getValue()
                createLabel(ivar_addr, 'ivar_{}::{}'.format(
                    getDataAt(name_addr).getValue(), ivar_name), True)

        # find property_list
        property_list_addr_raw = getDataAt(
            data_addr).getLong(64) & mask
        property_list_addr = to_address(
            property_list_addr_raw)
        if property_list_addr_raw != 0:
            # define objc_property_list struct
            set_data(property_list_addr, objc_property_list)
            property_count = getDataAt(property_list_addr).getInt(4)

            # define objc_property struct
            for i in range(property_count):
                property_addr = to_address(
                    property_list_addr_raw + 8 + 16 * i)
                set_data(property_addr, objc_property)

                # get property name
                property_name_addr = to_address(
                    getDataAt(property_addr).getLong(0) & mask)
                property_name = getDataAt(property_name_addr).getValue()
                createLabel(property_addr, 'property_{}::{}'.format(
                    getDataAt(name_addr).getValue(), property_name), True)

        # create label
        createLabel(cu.address, 'class_{}'.format(class_name), True)
        createLabel(
            class_addr, 'class_{}'.format(class_name), True)
        createLabel(data_addr, 'data_{}'.format(class_name), True)

    # iterate class refs
    for seg in cp.memory.blocks:
        if seg.name == '__objc_classrefs':
            print('found section {} @ {}, adding labels for class refs'.format(
                seg.name, seg.start))
            codeUnits = cp.getListing().getCodeUnits(seg.start, True)
            while codeUnits.hasNext():
                cu = codeUnits.next()
                if cu and cu.address < seg.end:
                    # define obj_ref struct
                    set_data(cu.address, objc_ref)

                    # find class
                    class_addr_raw = cu.getLong(0) & mask
                    class_obj = getDataAt(to_address(class_addr_raw))
                    if class_obj:
                        createLabel(cu.address, 'ref_{}'.format(
                            class_obj.getLabel()), True)

                else:
                    break

    # iterate protocol lists
    for seg in cp.memory.blocks:
        if seg.name == '__objc_protolist':
            print('found section {} @ {}, adding labels for protocol lists'.format(
                seg.name, seg.start))
            codeUnits = cp.getListing().getCodeUnits(seg.start, True)
            while codeUnits.hasNext():
                cu = codeUnits.next()
                if cu and cu.address < seg.end:
                    # define obj_ref struct
                    set_data(cu.address, objc_ref)

                    # parse protocol
                    protocol_addr = to_address(cu.getLong(0) & mask)
                    set_data(protocol_addr, objc_protocol)
                    name_addr = to_address(
                        getDataAt(protocol_addr).getLong(8) & mask)
                    protocol_name = getDataAt(name_addr).getValue()
                    createLabel(protocol_addr, 'protocol_{}'.format(
                        protocol_name), True)

                    # parse instance method list
                    parse_method_list(
                        getDataAt(protocol_addr).getLong(24) & mask, protocol_name)

                    # parse class method list
                    parse_method_list(
                        getDataAt(protocol_addr).getLong(32) & mask, protocol_name)

                    # parse optional instance method list
                    parse_method_list(
                        getDataAt(protocol_addr).getLong(40) & mask, protocol_name)

                    # parse optional class method list
                    parse_method_list(
                        getDataAt(protocol_addr).getLong(48) & mask, protocol_name)

                else:
                    break

    # iterate protocol refs
    for seg in cp.memory.blocks:
        if seg.name == '__objc_protorefs':
            print('found section {} @ {}, adding labels for protocol refs'.format(
                seg.name, seg.start))
            codeUnits = cp.getListing().getCodeUnits(seg.start, True)
            while codeUnits.hasNext():
                cu = codeUnits.next()
                if cu and cu.address < seg.end:
                    # define obj_ref struct
                    set_data(cu.address, objc_ref)

                    # find protocol
                    protocol_addr_raw = cu.getLong(0) & mask
                    protocol_obj = getDataAt(to_address(protocol_addr_raw))
                    if protocol_obj:
                        createLabel(cu.address, 'ref_{}'.format(
                            protocol_obj.getLabel()), True)

                else:
                    break

    # iterate super refs
    for seg in cp.memory.blocks:
        if seg.name == '__objc_superrefs':
            print('found section {} @ {}, adding labels for super refs'.format(
                seg.name, seg.start))
            codeUnits = cp.getListing().getCodeUnits(seg.start, True)
            while codeUnits.hasNext():
                cu = codeUnits.next()
                if cu and cu.address < seg.end:
                    # define obj_ref struct
                    set_data(cu.address, objc_ref)

                    # find class
                    class_addr_raw = cu.getLong(0) & mask
                    class_obj = getDataAt(to_address(class_addr_raw))
                    if class_obj:
                        createLabel(cu.address, 'super_ref_{}'.format(
                            class_obj.getLabel()), True)

                else:
                    break

    # iterate ivar offsets
    for seg in cp.memory.blocks:
        if seg.name == '__objc_ivar':
            print('found section {} @ {}, adding labels for ivar offsets'.format(
                seg.name, seg.start))
            codeUnits = cp.getListing().getCodeUnits(seg.start, True)
            while codeUnits.hasNext():
                cu = codeUnits.next()
                if cu and cu.address < seg.end:
                    # define uint32_t struct
                    set_data(cu.address, uint32_t)
                else:
                    break
