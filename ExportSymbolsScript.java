
//Counts the symbols in the current program and prints the total.
//@category Symbol

import java.io.File;

import java.io.FileOutputStream;
import java.io.IOException;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;

public class ExportSymbolsScript extends GhidraScript {

    /**
     * @see ghidra.app.script.GhidraScript#run()
     */
    @Override
    public void run() {
        try {
            File directory = askDirectory("Directory", "Choose directory:");
            monitor.setMessage("Finding symbols...");
            SymbolTable st = state.getCurrentProgram().getSymbolTable();
            SymbolIterator iter = st.getSymbolIterator(true);
            int count = 0;
            StringBuilder sb = new StringBuilder();
            sb.append("#!/bin/bash\n");
            sb.append("# Create for U by SimonTheCoder.\n");
            sb.append("# Feel free to modify this script.\n");
            sb.append("# You may need to chmod +x on this script to run it.\n");
            sb.append("# BACKUP YOUR BINARY BEFORE RUN.\n");
            sb.append("# To add symbols to your bin, run:\n");
            sb.append("#     ./add_symbol.sh YOUR_BINARY_FILE.\n");
            sb.append("\n");

            Memory mem = this.currentProgram.getMemory();

            while (iter.hasNext() && !monitor.isCancelled()) {
                Symbol sym = iter.next();
                if (sym != null) {
                    MemoryBlock mb = mem.getBlock(sym.getAddress());
                    println(sym.getName() + "\t" + sym.getAddress()+"\t\t" + sym.isGlobal()+ "mb：" + mb.getName());
                    //sb.append(sym.getAddress() + " " + "A" + " " + sym.getName() + "\n");
                    if(sym.isGlobal()){
                        long offset_in_text = sym.getAddress().subtract(mb.getStart());
                        sb.append("objcopy --add-symbol ");
                        sb.append(sym.getName()+ "="+mb.getName()+":0x"+ Long.toHexString(offset_in_text));
                        sb.append(" $@\n");
                        count+=1;
                    }
                        
                }
            }
            println(count + " symbols added.");

            String path = directory.toString()+"/add_symbol.sh";

            File file = new File(path);

            String content = sb.toString();
            FileOutputStream fileOutputStream = new FileOutputStream(file);
            fileOutputStream.write(content.getBytes());

            fileOutputStream.close();
            println(path + " generated.");
        } catch (CancelledException | IOException e) {
            println("Error!");
            e.printStackTrace();
        }




    }
}