"""
This file is used to identify possible optimizations for handling functions
in pre-compiled libraries.
"""

import json
from pprint import pprint
import collections
import numpy as np
from collections import OrderedDict
from argparse import ArgumentParser

from texttable import Texttable
import sys
import os


################################################################################
# GLOBALS
################################################################################

ENCODER_PATH = os.path.dirname(os.path.abspath(__file__))

STDLIB_FILE = ENCODER_PATH + "/" + "STD_LIB.json"
EXT_LIB_OPT_LIST = ENCODER_PATH + "/" + "EXT_LIB_OPT_LIST.json"

# global dictionary of function results (optmizable or not)
FUNC_STATE_DICT = OrderedDict()

# states of observed functions
OPTIMIZABLE_FUNC = "OPTIMIZABLE_FUNC"
NOT_OPT_FUNC = "NOT_OPT_FUNC"
UNDECIDED_FUNC = "UNDECIDED_FUNC"

# tokens to check for
R9_STR = "r9"
BL_STR ="bl"
B_STR = "b.w"
PUSH_STR = "push"
LR_STR = "lr"
BX_STR = "bx"

################################################################################
# FUNCTIONS/CLASSES
################################################################################


def is_unsupported_lib_func(name, lib_dict):
    if name in lib_dict.keys():
        return True
    return False


def is_func_start(line):
    """
    Checks if the current line is a start of a function
    :param line: objdump line
    :return: True if start of a function, false otherwrise
    """
    func_start_tokens = 2
    line_tokens = len(line.split())
    if line_tokens == func_start_tokens:
        return True
    return False


def get_func_name(line):
    name = line.split()[-1].split("<")[-1].split(">")[0]
    return name


def record_curr_func(name, state):
    global FUNC_STATE_DICT
    FUNC_STATE_DICT[name] = state
    return


def get_branch_callee_name(callee_token):
    name = callee_token.replace(">", "").replace("<", "")
    return name


if __name__ == "__main__":
    arg_parser = ArgumentParser()
    arg_parser.add_argument('-f', '--filename', dest='objdump_filename',
                            type=str,
                            help="The name of the file containing objdump"
                                 " output to parse", required=True)

    arg_parser.add_argument('-a', dest='append', default=False,
                            action='store_true',
                            help='If enabled, will append EXT_LIB_OPT_LIST '
                                 'instead of overwriting it.')

    args = arg_parser.parse_args()
    if args.append:
        with open(EXT_LIB_OPT_LIST, 'r') as json_fd:
            FUNC_STATE_DICT = json.load(json_fd)

    # first read the objdump file
    with open(args.objdump_filename, 'r') as input_fd:
        objdump_lines = input_fd.readlines()

    print("="*40)
    search_depth = 3
    for i in range(search_depth):

        func_counter = 0
        opt_funcs_cntr = 0
        undecided_cntr = 0
        func_state = OPTIMIZABLE_FUNC

        '''
        The first loop will classify functions into optimizable, not
        optimizable, and undecided.
        '''
        for objdump_line in objdump_lines:
            if is_func_start(objdump_line):
                func_counter += 1
                # avoid recording the first function without actually
                #  checking it
                if func_counter > 1:
                    # record the current function state
                    record_curr_func(func_name, func_state)
                    if func_state == OPTIMIZABLE_FUNC:
                        opt_funcs_cntr += 1
                        #print("-----------> %s" % func_name)
                    if func_name == "__aeabi_memset":
                        print("[+] func <%s>: %s" % (func_name, func_state))
                # set the name to new function to start recording it
                func_name = get_func_name(objdump_line)
                func_state = OPTIMIZABLE_FUNC
            else:
                '''
                Only check if we did not conclude already that the optimization
                is not possible. The function counter condition is to avoid
                checking it until the first function is found.
                '''
                if func_state == OPTIMIZABLE_FUNC and func_counter > 0:
                    objdump_tokens = objdump_line.split()
                    # loop through the tokens and check for each condition, we
                    # can ignore the first two tokens as they are always
                    # not useful
                    num_tokens = len(objdump_tokens)
                    for idx in range(2, num_tokens):
                        token = objdump_tokens[idx]
                        if (R9_STR in token) or (BL_STR == token) or \
                                (LR_STR in token and
                                         objdump_tokens[idx-1] != BX_STR):
                            func_state = NOT_OPT_FUNC
                        if B_STR == token:
                            # check the callee state
                            callee_name = get_branch_callee_name(
                                objdump_tokens[num_tokens-1])
                            if func_name == "__aeabi_memset":
                                print(objdump_line)
                                print("---")
                                print("callee: ", callee_name)
                            # check if callee has been assigned a state or not
                            if callee_name in FUNC_STATE_DICT:
                                # the state should match the callee
                                func_state = FUNC_STATE_DICT[callee_name]
                            else:
                                func_state = UNDECIDED_FUNC
                                undecided_cntr += 1
                            if func_name == "memset":
                                print(objdump_line)


    print("=" * 40)
    print("[*] # of funcs: %d" % func_counter)
    print("[*] # of optmizable funcs: %d" % opt_funcs_cntr)
    print("[*] # of undecided funcs: %d" % undecided_cntr)
    with open(EXT_LIB_OPT_LIST , 'w') as final_fd:
        json.dump(FUNC_STATE_DICT, final_fd, sort_keys=True, indent=4,
                  ensure_ascii=False)





