#Script to compute the cyclomatic complexity of all functions. And output as CSV format to given file.
#By SimonTheCoder
#@category Functions

import ghidra.program.util.CyclomaticComplexity as CyclomaticComplexity
cyclomaticComplexity = CyclomaticComplexity()

output_file = askFile("Choose output file","OK")

if output_file.exists():
    yesOrNo = askYesNo("Overwrite?", "File exsit, OVERWRITE it?")

    if not yesOrNo:
        exit(1)
else:
    output_file.createNewFile()
ofd = open(str(output_file),"w")

print "Start resolving...\n"
fcount = 0
for f in currentProgram.getFunctionManager().getFunctions(True):
    if monitor.isCancelled() :
        break
    ofd.write("\"%s\",%d\n" % (f.getName(),cyclomaticComplexity.calculateCyclomaticComplexity(f, monitor)))
    fcount = fcount + 1
    print ".",
print "\nOK"
#close(ofd)
ofd.close()

popup("All done.\n Function processed:%d" % (fcount))