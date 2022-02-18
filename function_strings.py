#Script to print strings used by given function.
#By SimonTheCoder
#@category SimonTheCoder

from __main__ import *

def get_range_strings(begin,end):

    l = currentProgram.getListing()
    res_strings = dict()
    
    # ins_iter = l.getInstructions(begin,True) # True for Forward
    
    

    # for ins in ins_iter:
    #     pcode = ins.getPcode()

    #     #try to find REG = COPY const XXXX pcode.
    #     if len(pcode) != 1:    #only support x86 a64?
    #         continue

    data_iter = l.getDefinedData(True)
    for data in data_iter:

        if type(data.getDataType()) == ghidra.program.model.data.StringDataType:
            to_iter = data.getReferenceIteratorTo()

            for ref in to_iter:
                from_addr = ref.getFromAddress()
                if begin <= from_addr and  from_addr <= end: 
                    res_strings[from_addr] = data.getValue()

    return res_strings    

def get_function_strings(func):
    return get_range_strings(func.getBody().getMinAddress(),func.getBody().getMaxAddress())


if __name__ == "__main__":
    f = getFunctionContaining(currentAddress)
    print "==================================="
    print "function:", f
    for (k,v) in get_function_strings(f).items():
        print("%x:%s" % (k.getOffset(),v))