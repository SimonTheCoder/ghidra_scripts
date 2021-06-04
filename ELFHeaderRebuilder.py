#Rebuild ELFHeader obj from memory of currentProgram.
#By SimonTheCoder
#@category SimonTheCoder

import ghidra.app.util.bin.MemoryByteProvider as MemoryByteProvider
from ghidra.app.util.bin.format.elf import ElfHeader
import generic.continues.RethrowContinuesFactory as RethrowContinuesFactory
import ghidra.app.util.bin.format.elf.ElfException as ElfException
import ghidra.app.util.bin.ByteArrayProvider as ByteArrayProvider


from __main__ import *

def getELFHeader():
    if currentProgram.getExecutableFormat().find("ELF") <0:
        print "for ELF only!"
        return None
    #mp = MemoryByteProvider(currentProgram.getMemory(), currentProgram.getMinAddress())
    mp = MemoryByteProvider(currentProgram.getMemory(), currentProgram.getImageBase())
    header = None
    try:
        header = ElfHeader.createElfHeader(RethrowContinuesFactory.INSTANCE, mp)
    except ElfException as error:
        print "No correct ELF found @ImageBase. Try to get ELF from original file."
        try:
            fd = open( str(getProgramFile()),"rb")
            bap = ByteArrayProvider(fd.read(0x100000)) #I think 1M is enough for ELF Header.
            fd.close()
            header = ElfHeader.createElfHeader(RethrowContinuesFactory.INSTANCE, bap)
        except IOError as error:
            print "Original file not found!. ELFHeader create failed."    
            header = None
        except ElfException as error:
            print "Can not find ELF in original file."
            header = None    
    if header is None:
        print "Let's find it manually..."
        return  getELFHeaderManually()       
    return header

def getELFHeaderManually():
    if currentProgram.getExecutableFormat().find("ELF") <0:
        print "for ELF only!"
        return None
    memory = currentProgram.getMemory()
    mp = MemoryByteProvider(currentProgram.getMemory(), askAddress("Select ELF Section","ELF(ADDRESS should be '0'):"))
    header = None
    try:
        header = ElfHeader.createElfHeader(RethrowContinuesFactory.INSTANCE, mp)
    except ElfException as error:
        print "No correct ELF found @SelectAddress. Try to get ELF from original file."
        return None
    return header

if __name__ == "__main__":
    print getELFHeader()