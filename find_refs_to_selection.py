#Ghidra script to find all refs to currentSelection
#By SimonTheCoder
#@category SimonTheCoder
#@menupath Search.Find find refs to selected range

for addr in currentSelection:
    print(type(addr))
    start = addr.getMinAddress()
    end = addr.getMaxAddress()

    for check_addr in addr.iterator():
        #print(type(check_addr))
        refs = getReferencesTo(check_addr)
        refs_len = len(refs)
        if refs_len > 0:
            print("References to @ %s : %d" %(check_addr, refs_len)) # "@ %s " will make the address clickable in console.
            
