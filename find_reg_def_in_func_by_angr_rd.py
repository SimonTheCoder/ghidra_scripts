#Find register defination in current function.
#By SimonTheCoder
#@category SimonTheCoder
#@menupath Search.Find reg definition

DEBUG = True
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
    
    #ARM thumb support
    instruction = getInstructionAt(currentAddress)
    if target_arch=="ARM" and instruction.getLength() == 2:
        target_arch = "arm_thumb"

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

    #atom_string = askString("Register,MEM","Wich register or MEM to find(MEM format:MEM,addr,size):")
    atom_string = askString("Register","Wich register:")

    if atom_string.startswith("MEM"):
        register = atom_string
    else:
        register = currentProgram.getRegister(atom_string)
        if register is not None:
            register = register.getName()

    if register is None:
        #print("Bad register or MEM format!!!")
        print("Bad register !!!")
        exit(1)

    find_config["register"] = register

    fn = tempfile.mktemp(suffix=".json",prefix="find_def.")
    print("gen config file: %s" % (fn))
    with open(fn,"w") as fno:
        json.dump(find_config,fno)

    script_path = getSourceFile().getAbsolutePath()

    print("call angr:")

    if DEBUG:
        import utils
        utils.open_in_ipython(script_path, fn)
    else:
        call_angr = os.popen("python3 %s %s" % (script_path, fn))
        print(call_angr.read())
    print("===================================")
    with open(fn,"r") as fno:
        config = json.load(fno)
    
    addressSet = AddressSet()
    for [addr,value] in config["def_infos"]:
        #print(addr,value)
        if addr == None:
            continue
        addressSet.add(toAddr(addr))
        print("@ %x :%s" % (addr, value))
        setEOLComment(toAddr(addr), value)
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
    # import angr.analyses.reaching_definitions.rd_state as rd_state
    from angr.knowledge_plugins.key_definitions.atoms import Register, Tmp, MemoryLocation
    import binascii
    import claripy

    #create angr project obj
    binary = binascii.a2b_hex(config["function_body"])

    arch = config["arch"]

    if arch == "arm_thumb":
        prj = angr.project.load_shellcode(
            binary,
            "ARM",
            start_offset=config["load_address"],
            load_address=config["load_address"],
            thumb=True)
    else:                                
        prj = angr.project.load_shellcode(
            binary,
            config["arch"],
            start_offset=config["load_address"],
            load_address=config["load_address"],thumb=False)

    #analyses CFG
    bin_cfg = prj.analyses.CFG(resolve_indirect_jumps=True, 
                               cross_references=True, 
                               force_complete_scan=False, 
                               normalize=True, 
                               symbols=True)
    # bin_cfg = prj.analyses.CFGEmulated(resolve_indirect_jumps=True,
    #                                  normalize=True)                           

    target_func = bin_cfg.functions.get_by_addr(config["load_address"]+ (1 if arch == "arm_thumb" else 0))

    # init_state = rd_state.ReachingDefinitionsState(arch=prj.arch, subject = target_func)
    # bv_sp_init = claripy.BVS("SP_init_base",prj.arch.bits)
    # stack_pointer_name = prj.arch.register_names[prj.arch.sp_offset]
    #setattr(init_state.regs,stack_pointer_name,bv_sp_init)
    # bv_sp_init = init_state.get_sp()

    observation_point = ("insn", config["observation_point"] + (1 if arch == "arm_thumb" else 0), 0) #0: OP_BEFORE

    rd = prj.analyses.ReachingDefinitions(subject=target_func, 
                                          func_graph=target_func.graph,
                                          cc = target_func.calling_convention,
                                          observation_points= [observation_point],
                                          observe_all = True,
                                          dep_graph = dep_graph.DepGraph(),
                                          #init_state = init_state
                                          )

    target_atom = None
    reg_name = config["register"]
    if reg_name.startswith("MEM"):
        print("Target MEM is:",reg_name)
        mem_magic,target_mem_addr,mem_size = reg_name.split(",")
        if target_mem_addr.startswith("0x"):
            target_mem_addr = int(target_mem_addr,16)
        else:
            target_mem_addr = int(target_mem_addr)
        if mem_size.startswith("0x"):
            mem_size = int(mem_size,16)
        else:
            mem_size = int(mem_size)

        target_atom = MemoryLocation(bv_sp_init+target_mem_addr,mem_size)

    else:
        reg_vex_offset, reg_vex_size = prj.arch.registers[config["register"].lower()]
        print("Finding reg: %s  index: %d  size: %d" % (config["register"].lower(), reg_vex_offset, reg_vex_size))
        target_atom = Register(reg_vex_offset, reg_vex_size)

    obv_res = rd.observed_results[observation_point]

    # reg_def = obv_res.register_definitions.load(reg_vex_offset, reg_vex_size)
    # print(reg_def.values)
    # def_info_list = []
    # def_infos = []

    # def get_predecessors_rc(di):
    #     for i in rd.dep_graph.predecessors(di):
    #         print("r ",i)
    #         def_infos.append(i.codeloc.ins_addr)
    #         get_predecessors_rc(i)

    # for i in reg_def.values:
    #     print("Value:",reg_def.values[i])
    #     for bv in reg_def.values[i]:
    #         print("BV:",bv)
    #         for def_info in list(obv_res.extract_defs(bv)):
    #             print(def_info)
    #             def_infos.append(def_info.codeloc.ins_addr)
    #             def_info_list.append(def_info)
    #             get_predecessors_rc(def_info)


    defs_iter = obv_res.get_definitions(target_atom)
    def_info_list = []
    def_infos = []

    def_printed = set()
    def get_predecessors_rc(di):
        for i in rd.dep_graph.predecessors(di):
            if i in def_printed:
                print("cycle found!  def:",i)
                continue
            else:
                def_printed.add(i)
            print("r ",i)
            if i.codeloc.ins_addr is not None:
                liveDefs = rd.get_reaching_definitions_by_insn(i.codeloc.ins_addr, 1) # OP_AFTER
                if liveDefs.get_value_from_atom(i.atom) is None:
                    continue
                print("data:",list(liveDefs.get_value_from_atom(i.atom).values()))
                def_infos.append([i.codeloc.ins_addr,i.atom.__repr__()+list(liveDefs.get_value_from_atom(i.atom).values()).__repr__()])
            get_predecessors_rc(i)
            #import ipdb;ipdb.set_trace()
    def make_def_human_readale(project):
        #pring def pretty
        #angr.knowledge_plugins.key_definitions.atoms.Register
        def Register__repr__(self):
            return "<Reg %s<%d>>" % (project.arch.register_names[self.reg_offset], self.size)
        angr.knowledge_plugins.key_definitions.atoms.Register.__repr__ = Register__repr__

        def CodeLocation__repr__(self):
            if self.block_addr is None:
                return '<%s>' % self.sim_procedure

            if self.stmt_idx is None:
                s = "<%s%#x(-)" % (
                    ("%#x " % self.ins_addr) if self.ins_addr else "",
                    self.block_addr,
                )
            else:
                s = "<%s%#x[%d]" % (
                    ("%#x id=" % self.ins_addr) if self.ins_addr else "",
                    self.block_addr,
                    self.stmt_idx,
                )

            if self.context is None:
                s += " contextless"
            else:
                dl = []
                for i in self.context:
                    d_string = "%s(%s)" % (project.kb.functions.floor_func(i).name,hex(i))
                    dl.append(d_string)
                s += " context: [%s]" % (",".join(dl),)

            ss = [ ]
            if self.info:
                for k, v in self.info.items():
                    if v != tuple() and v is not None:
                        ss.append("%s=%s" % (k, v))
                if ss:
                    s += " with %s" % ", ".join(ss)
            s += ">"

            return s
        angr.code_location.CodeLocation.__repr__ = CodeLocation__repr__
    make_def_human_readale(prj)
    for i in defs_iter:
        print("def:",i)
        print("data:",list(obv_res.get_value_from_atom(target_atom).values()))
        def_infos.append([i.codeloc.ins_addr,i.atom.__repr__()+list(obv_res.get_value_from_atom(target_atom).values()).__repr__()])
        def_info_list.append(i)
        get_predecessors_rc(i)

    # def_info = list(obv_res.extract_defs(reg_def.one_value()))[0]
    # print(def_info)
    config["def_infos"]=def_infos
    with open(sys.argv[1],"w") as f:     
        json.dump(config, f)

    print("Close this window to return to Ghidra.")

