#from __main__ import *

def hello():
    print("Hello! There.")
    print("__name__",__name__)
    import sys
    print(sys.argv)
# import sys
# print("__name__",__name__)
# print("===",sys.argv)


def open_in_ipython(script_path, args_string):
    import os
    #import subprocess

    os_name = os.name
    use_system = True
    #seems we are in jython context.
    if os_name == "java":
        os_name = os_name.getshadow()
    print(os_name)
    start_string = ""
    if os_name == "nt":
        start_string = "start /wait cmd /c ipython3 %s -i -- %s" %(script_path, args_string)
        #start_string = "start cmd /c ipython3 %s -i -- %s" %(script_path, args_string)
    else:
        start_string = "gnome-terminal -- ipython3 %s -i -- %s" %(script_path, args_string)

    if use_system:
        ret = os.system(start_string)
        print(ret)
    else:
        # p = subprocess.Popen("start /wait cmd /k ipython3 ./angr_util.py -i -- hahahaha",shell=True,stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        # w = input()
        # p.wait()
        ret = os.popen(start_string)
        print(ret.read())

    #print("it's over.")