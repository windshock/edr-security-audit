# decompile_all.py
# @author Antigravity
# @category Analysis

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import os

# Initialize decompiler
decomp_interface = DecompInterface()
decomp_interface.openProgram(currentProgram)

# Create output folder
output_dir = "<REPO_ROOT>/bin/decompiled"
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

output_file_path = os.path.join(output_dir, currentProgram.getName() + "_decompiled.c")
print("Decompiling to: " + output_file_path)

with open(output_file_path, "w") as f:
    f.write("// Decompiled source of " + currentProgram.getName() + "\n\n")
    
    # Get all functions
    fm = currentProgram.getFunctionManager()
    functions = fm.getFunctions(True) # True = forward order
    
    for func in functions:
        func_name = func.getName()
        f.write("// Function: " + func_name + "\n")
        # Decompile function
        results = decomp_interface.decompileFunction(func, 30, ConsoleTaskMonitor())
        if results and results.decompileCompleted():
            decompiled_code = results.getDecompiledFunction().getC()
            f.write(decompiled_code + "\n\n")
        else:
            f.write("// Decompilation failed for: " + func_name + "\n\n")

print("Decompilation complete!")
