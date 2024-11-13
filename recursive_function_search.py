#!/usr/bin/env python3

import idautils
import idaapi
import idc

class func():
    def __init__(name, addr):
        self.name = name
        self.addr = addr

class callpath():
    def __init__(start: func, end:func, path: func):
        pass

# Recursive function to search for the target function
def _find_path_to_target_function(current_function, target_function, path):
    # Add the current function to the path
    path.append(current_function)

    # Check if we've reached the target function
    if idc.get_func_name(current_function) == target_function:
        # Print the path to the target
        print("Path to", target_function, ":", " -> ".join([idc.get_func_name(addr) for addr in path]))
        # Remove the current function from the path and return
        path.pop()
        return

    # Loop through all call instructions in the current function
    for ref in idautils.FuncItems(current_function):
        if idc.print_insn_mnem(ref) == "call":
            # Get the address of the called function
            target = idc.get_operand_value(ref, 0)
            # Check if this is a valid function and hasn't been visited
            if idc.get_func_name(target):
                # Recursively search from the called function
                _find_path_to_target_function(target, target_function, path)

    # Remove the current function from the path when going back
    path.pop()


def find_path_to_target_function(target):
    # Find the address of the root function (main in this case)
    root_function = idc.get_screen_ea()
    # Check if the main function was found
    if root_function != idaapi.BADADDR:
        print("Starting search from current function...")
        _find_path_to_target_function(root_function, target, [])
    else:
        print("root function ea not found.")
