import lief

if __name__ == '__main__':
    binary = lief.parse("./source")
    hook = lief.parse("./patch_overflow.o")
    textseg = None
    dataseg = None
    for seg in hook.segments:
        for sec in seg.sections:
            if sec.name == '.text':
                textseg = seg
            elif sec.name == '.data':
                dataseg = seg
    new_textseg = binary.add(textseg)
    new_dataseg = binary.add(dataseg)
    myscanf = hook.get_symbol("patch_scanf")
    print(myscanf)
    myscanf_addr = new_textseg.virtual_address + myscanf.value - textseg.physical_address
    print(hex(myscanf_addr))
    # for i in binary.imported_symbols:
    #     print(i)
    binary.patch_pltgot("__isoc99_scanf", myscanf_addr)
    binary.write("source_patch_overflow")