#Script to print some angr example scripts to console.
#By SimonTheCoder
#@category SimonTheCoder


import re
import java.lang.System as System

cmd_string_rawbin = """prj = angr.Project("%s", main_opts={'backend': 'blob', 'arch': '%s', 'base_addr': %s} , load_options={"auto_load_libs": False})"""  
cmd_string_with_format = """prj = angr.Project("%s", load_options={"auto_load_libs": False})"""
cmd_string = None

target_path = currentProgram.getExecutablePath()

if System.getProperty("os.name").find("Windows") != -1 :
    target_path = target_path[1:]
    target_path = target_path.replace("/", r"\\")

format_re = re.match(r'.*\((ELF|PE)\)',currentProgram.getExecutableFormat()) #Why MACH-O not included? Because I hate Apple products.
if format_re is not None:
    target_loader_backend = format_re.groups()[0].lower()
    cmd_string = cmd_string_with_format % target_path
else:
    target_arch = currentProgram.getLanguage().getProcessor()
    target_base_addr = hex(currentProgram.minAddress.offset).replace("L","")
    cmd_string = cmd_string_rawbin % (target_path, target_arch, target_base_addr)

print("##########Create angr prj##########")
print(cmd_string)

cmd_string_blank_state = """s = prj.factory.blank_state(addr=%s)"""
print("###########Create angr blank state##########")
print(cmd_string_blank_state % (hex(currentAddress.offset).replace("L","")))

cmd_string_sigmgr = """simgr = p.factory.simulation_manager(s)
simgr.use_technique(angr.exploration_techniques.Explorer(find=%s, avoid=%s))
simgr.run()"""
print("###########Create angr sim manager##########")
print(cmd_string_sigmgr % (hex(currentAddress.offset).replace("L",""),"0x00000000"))

cmd_string_print_regs = """found_state = simgr.found[0]
for reg in prj.arch.default_symbolic_registers:
    print(reg,": ",getattr(found_state.regs,reg))
"""
print("###########print angr state regs##########")
print(cmd_string_print_regs)
