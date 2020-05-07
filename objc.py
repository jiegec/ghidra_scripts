if __name__ == '__main__':
    cp = currentProgram
    method_names = {}

    # iterate method names
    for seg in cp.memory.blocks:
        if seg.name == '__objc_methname':
            print('found section {} @ {}'.format(seg.name, seg.start))
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
            print('found section {} @ {}'.format(seg.name, seg.start))
            codeUnits = cp.getListing().getCodeUnits(seg.start, True)
            while codeUnits.hasNext():
                cu = codeUnits.next()
                if cu and cu.address < seg.end:
                    real_addr = cu.address.getNewAddress(cu.getLong(0) & 0x7ffffffffffff)
                    if real_addr in method_names:
                        print('found selector {} = {} -> {}: {}'.format(cu.address, cu.value, real_addr, method_names[real_addr]))
                        createLabel(cu.address, '@selector({})'.format(method_names[real_addr]), True)
                else:
                    break
