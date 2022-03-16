#Find register defination in current function.
#By SimonTheCoder
#@category SimonTheCoder
#@menupath Search.Find reg definition


#we are in ghidra script context
if "currentProgram" in vars():
    import binascii
    import tempfile
    import json
    import os

    import ghidra.program.model.address.AddressSet as AddressSet


    find_config = dict()

    #get cpu arch
    target_arch = "%s" % currentProgram.getLanguage().getProcessor()  
    if target_arch == "x86":  
        if currentProgram.getLanguage().getLanguageDescription().getSize() == 64:
            target_arch = "x86_64"
    
    #TODO: add ARM thumb support

    find_config["arch"] = target_arch

    #get selected function position
    #because a complex binary can cause CFG generating takeing lot of time, 
    # we only load the current function info angr.
    func = getFunctionContaining(currentAddress) 
    find_config["load_address"] = func.getBody().getMinAddress().offset
    find_config["function_body"] =  binascii.b2a_hex(
        getBytes(
            func.getBody().getMinAddress(),
            func.getBody().getNumAddresses()
        )
    )

    #get observe address
    find_config["observation_point"] = currentAddress.offset

    register = currentProgram.getRegister(askString("Register","Wich register to find:"))

    if register is None:
        print("Bad register!!!")
        exit(1)

    find_config["register"] = register.getName()

    fn = tempfile.mktemp(suffix=".json",prefix="find_def.")
    print("gen config file: %s" % (fn))
    with open(fn,"w") as fno:
        json.dump(find_config,fno)

    script_path = getSourceFile().getAbsolutePath()

    print("call angr:")
    call_angr = os.popen("python3 %s %s" % (script_path, fn))
    print(call_angr.read())
    print("===================================")
    with open(fn,"r") as fno:
        config = json.load(fno)
    
    addressSet = AddressSet()
    for addr in config["def_infos"]:
        addressSet.add(toAddr(addr))
    createHighlight(addressSet)

else:
    #we are in normal python context
    import sys
    import json

    print("Enter angr part.")
    if len(sys.argv) != 2:
        print("Bad args.")
        exit(1)

    print("loading config: %s" % sys.argv[1])
    with open(sys.argv[1],"r") as f:    
        config = json.load(f)

    import angr
    import angr.analyses.reaching_definitions.dep_graph as dep_graph

    import binascii

    
    #create angr project obj
    binary = binascii.a2b_hex(config["function_body"])
    prj = angr.project.load_shellcode(
        binary,
        config["arch"],
        load_address=config["load_address"])

    #analyses CFG
    bin_cfg = prj.analyses.CFG(resolve_indirect_jumps=True, 
                               cross_references=True, 
                               force_complete_scan=False, 
                               normalize=True, 
                               symbols=True)

    target_func = bin_cfg.functions.get_by_addr(config["load_address"])

    observation_point = ("insn", config["observation_point"], 0)

    rd = prj.analyses.ReachingDefinitions(subject=target_func, 
                                          func_graph=target_func.graph,
                                          cc = target_func.calling_convention,
                                          observation_points= [observation_point],
                                          dep_graph = dep_graph.DepGraph()
                                          )

    reg_vex_offset, reg_vex_size = prj.arch.registers[config["register"].lower()]
    print("Finding reg: %s  index: %d  size: %d" % (config["register"].lower(), reg_vex_offset, reg_vex_size))

    obv_res = rd.observed_results[observation_point]

    reg_def = obv_res.register_definitions.load(reg_vex_offset, reg_vex_size)
    print(reg_def.values)

    def_infos = []
    for i in reg_def.values:
        print("Value:",reg_def.values[i])
        for bv in reg_def.values[i]:
            for def_info in list(obv_res.extract_defs(bv)):
                print(def_info)
                def_infos.append(def_info.codeloc.ins_addr)
    # def_info = list(obv_res.extract_defs(reg_def.one_value()))[0]
    # print(def_info)
    config["def_infos"]=def_infos
    with open(sys.argv[1],"w") as f:     
        json.dump(config, f)

