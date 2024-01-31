import lief

if __name__ == '__main__':
    binary = lief.parse("./stackVuln")
    hook = lief.parse("./hook.o")
    textseg = None
    for seg in hook.segments:
        for sec in seg.sections:
            if sec.name == '.text':
                textseg = seg
    new_textseg = binary.add(textseg)
    binary.write("patched_1")