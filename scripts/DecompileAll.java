// DecompileAll.java
// Ghidra 12.x headless postScript (Java — PyGhidra 불필요).
// currentProgram 의 전 함수를 디컴파일해 bin/decompiled/<name>_decompiled.c 로 저장.
// @category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;

public class DecompileAll extends GhidraScript {

    @Override
    public void run() throws Exception {
        String outDir = "<REPO_ROOT>/bin/decompiled";
        File d = new File(outDir);
        if (!d.exists()) {
            d.mkdirs();
        }

        String name = currentProgram.getName();
        String outPath = outDir + File.separator + name + "_decompiled.c";
        println("Decompiling to: " + outPath);

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        FunctionManager fm = currentProgram.getFunctionManager();
        int total = fm.getFunctionCount();
        int done = 0, failed = 0;

        try (PrintWriter w = new PrintWriter(new FileWriter(outPath))) {
            w.println("// Decompiled source of " + name);
            w.println("// Total functions: " + total);
            w.println();

            for (Function func : fm.getFunctions(true)) { // true = forward order
                if (monitor.isCancelled()) {
                    break;
                }
                w.println("// Function: " + func.getName() + " @ " + func.getEntryPoint());
                DecompileResults results = decomp.decompileFunction(func, 30, monitor);
                if (results != null && results.decompileCompleted()) {
                    w.println(results.getDecompiledFunction().getC());
                    done++;
                } else {
                    String err = (results != null) ? results.getErrorMessage() : "null result";
                    w.println("// Decompilation failed for: " + func.getName() + " (" + err + ")");
                    failed++;
                }
                w.println();
            }
        }
        decomp.dispose();
        println("Decompilation complete! ok=" + done + " failed=" + failed + " total=" + total);
    }
}
