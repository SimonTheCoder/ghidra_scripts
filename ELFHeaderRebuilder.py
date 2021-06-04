#Rebuild ELFHeader obj from memory of currentProgram.
#By SimonTheCoder
#@category ELF

import ghidra.app.util.bin.MemoryByteProvider as MemoryByteProvider
from ghidra.app.util.bin.format.elf import ElfHeader
import generic.continues.RethrowContinuesFactory as RethrowContinuesFactory

from __main__ import *

def getELFHeader():
    if currentProgram.getExecutableFormat().find("ELF1") <0:
        print "for ELF only!"
        return None
    mp = MemoryByteProvider(currentProgram.getMemory(), currentProgram.getMinAddress())
    header = ElfHeader.createElfHeader(RethrowContinuesFactory.INSTANCE, mp)
    return header


if __name__ == "__main__":
    print getELFHeader()