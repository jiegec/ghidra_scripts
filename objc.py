import re

if __name__ == '__main__':
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
                    print('found symbol {} = {}'.format(cu.address, cu.value))
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
                    print('{} @ {}: {} = {}'.format(cu.value, cu.address, real_addr, string))
                    createLabel(cu.address, '@cfstring({})'.format(string), True)
                else:
                    break
