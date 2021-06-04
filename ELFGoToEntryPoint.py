#Goto entry point of current ELF.
#By SimonTheCoder
#@category ELF

import ELFHeaderRebuilder

header = ELFHeaderRebuilder.getELFHeader()
#header = ELFHeaderRebuilder.getELFHeaderManually()

#goTo(parseAddress(hex(header.e_entry())[:-1]))
goTo(toAddr(header.e_entry()))