#!/usr/bin/env python3

import idautils
import idaapi
import idc
from importlib import reload

class func():
    def __init__(name, addr):
        self.name = name
        self.addr = addr

class callpath():
    def __init__(start: func, end:func, path: func):
        pass

# Recursive function to search for the target function
def _find_path_to_target_function(current_function, current_name, target_function, path, visited, already):
    # Add the current function to the path
    path.append(current_name)
    #print(f"current {current_name}")
    #
    # Check if we've reached the target function
    if current_name == target_function:
        # Print the path to the target
        res = "PATH to", target_function, ":", " -> ".join([str(addr) for addr in path])
        #print("".join(res))
        if res not in already:
            print(" ".join(res))
        already.add(res)

        # Remove the current function from the path and return
        path.pop()
        return
    visited.add(current_name)

    # Loop through all call instructions in the current function
    for ref in idautils.FuncItems(current_function):
        if idc.print_insn_mnem(ref) in ("call", "jmp"):
            # Get the address of the called function
            child_ea = idc.get_operand_value(ref, 0)
            child_name = idc.get_func_name(child_ea)
            # Check if this is a valid function and hasn't been visited
            #print(f"  call -> {child_name}")
            if child_ea and child_name not in visited:
                # Recursively search from the called function
                #print(f"     decending to -> {child_name}")
                _find_path_to_target_function(child_ea, child_name, target_function, path, visited, already)
            else:
                #print(f"     call already in visited -> {child_name}")
                pass

    # Remove the current function from the path when going back
    path.pop()


def find_path_to_target_function(target):
    # Find the address of the root function (main in this case)
    root_function = idc.get_screen_ea()
    # Check if the main function was found
    if root_function != idaapi.BADADDR:
        print("Starting search from current function...")
        _find_path_to_target_function(root_function, idc.get_func_name(root_function), target, [], set(), set())
        print("done")
    else:
        print("root function ea not found.")
