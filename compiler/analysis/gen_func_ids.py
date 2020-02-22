"""
This file is used to generate the Flag IDs and keys for the functions in URAI
"""
import contextlib
import networkx as nx
import json
import matplotlib.pyplot as plt
import matplotlib.image as mpimg
import pygraphviz

from networkx.drawing.nx_agraph import graphviz_layout
import networkx.algorithms.approximation as approx
import networkx.algorithms.dag as dag
import networkx.algorithms.components as comps
from pprint import pprint
import collections


import subprocess
import numpy as np
import netgraph as netg
from collections import OrderedDict
from argparse import ArgumentParser

from texttable import Texttable
import random
import sys
import os
import math
import pandas as pd

################################################################################
# GLOBALS
################################################################################


RANDOM = "random_key"
RELATIVE_JUMP = "relative_jump_key"
FLAG_ID_ALGORITHM_OPTIONS = [RANDOM, RELATIVE_JUMP]
ENCODER_PATH = os.path.dirname(os.path.abspath(__file__))
APP_NAME = "app"
UNIFY_TCFI_SETS = True

INDIRECT_POSTFIX = "_Indir"
JSON_EXT = '.json'
CSV_EXT = ".csv"
PNG_EXT = '.png'
MOD = '-updated'
CALLER = 'Caller'
CALLERS = 'Callers'
CALLEES = 'Callees'
CALLEE = 'Callee'
NUM_CALLS_KEY = 'NUM_OF_CALLS_KEY'
NAME_KEY = 'NAME_KEY'
FUNC_NODE_KEY = 'FUNC_NODE_KEY'
SHIFT = 'SHIFT'
IS_SHIFTED = "IS_SHIFTED"
IS_RECURSIVE = 'IS_RECURSIVE'
IS_PATH_RECURSIVE = 'IS_PATH_RECURSIVE'
IS_MULTI_RECURSIVE = 'IS_MULTI_RECURSIVE'
NUM_RECURSIVE_CALLS = 'NUM_RECURSIVE_CALLS'
IS_EH_CONTEXT = 'IS_EH_CONTEXT'
KEY = 'KEY'
INFLAGS = 'INFLAGS'
FLAG_KEY = 'FLAG_KEY'
LABEL = 'LABEL'
START_LBL_KEY = "START_LBL_KEY"
TRAMPOLINE_INST_KEY = "TRAMPOLINE_INST_KEY"
EXIT_LBL_KEY = "EXIT_LBL_KEY"
EXIT_SYM_KEY = "EXIT_SYM_KEY"
EXIT_BRANCH = "EXIT_BRANCH"
KEYS_DICT = 'KEYS_DICT'
SHIFTED_KEY = 'SHIFTED_KEY'
TCFI_SET = "TCFI_SET"
TCFI_INSTRMNT = "TCFI_INSTRMNT"
TCFI_LBL = "TCFI_LBL"
TCFI_EXIT = "TCFI_EXIT"
RET_INSTS = "RET_INSTS"
KEY_WITHOUT_SHIFT = "KEY_WITHOUT_SHIFT"
XOR_INST_KEY = 'XOR_INST_KEY'
ADD_REC_INST_KEY = "ADD_REC_INST_KEY"
SUB_REC_INST_KEY = "SUB_REC_INST_KEY"
MOV_REC_TLR_INST_KEY = "MOV_REC_TLR_INST_KEY"
B_INST_KEY = "B_INST_KEY"
LDR_INST_KEY = "LDR_INST_KEY"
MOV1_INST_KEY = "MOV1_INST_KEY"
MOV2_INST_KEY = "MOV2_INST_KEY"
IS_ENTRY = "IS_ENTRY"
IS_SINGULAR = "IS_SINGULAR"
MAX_INFLAG_KEY = 'MAX_INFLAG_KEY'
MAX_SR_SHIFT_KEY = 'MAX_SR_SHIFT'
INITIAL_SR_KEY = "INITIAL_SR_KEY"
REQ_SR_RESET_KEY = "REQ_SR_RESET_KEY"
RECURSION_SIZE_KEY = "RECURSION_SIZE_KEY"
RECURSION_CNTR_SHIFT_KEY = "RECURSION_CNTR_SHIFT_KEY"
RECURSION_TLR_LBL_KEY = "RECURSION_TLR_LBL_KEY"
IS_UNSUPPORTED_LIB = "IS_UNSUPPORTED_LIB"
LOOKUP_TABLE_RES_FILE = 'urai-keys-flag-ids'
LOGFILE_NAME = 'urai-log.txt'
DEBUG_FILE = "DEBUG_ENCODER.txt"
ERROR_LOG = "ERROR_LOG.txt"
ENCODER_LOG = "ENCODER_LOG.txt"
ENCODER_RES_FILE = "encoder-eval"
SEGMENTATION_EVAL = "segmentation-eval"
FLT_EFF_EVAL = "flt-eff-eval"
TCFI_EVAL_FILE = "tcfi-eval"
TCFI_SETS_STATS = "tcfi-sets-stat"
TCFI_SETS_TEMP_PATH = "" # [rai-debug]/FIXME: Remove this ugly hack!!
XOR_INST = "eor lr,lr,#"

# CG stats
NUM_CG_NODES = 0
NUM_CG_EDGES = 0
CG_NODE_KEY = "Nodes"
CG_EDGES_KEY = "Edges"

FUNC_DICT = OrderedDict()

'''
The limit set by the architecture on the maximum FLT size
'''
MAX_ARCH_FLT = 1024
ARCH_REGISTER_SIZE = 32
MAX_RECURSION_BITS = 4
MAX_STATE_REGISTER_BITS = 48 #32 #ARCH_REGISTER_SIZE - MAX_RECURSION_BITS
STATE_REGISTER_BIT_SIZE = 3 #32
# helps to check if we cannot find a key to satisfy the given bit size
NUM_OF_POSSIBLE_STATES = pow(2, STATE_REGISTER_BIT_SIZE)
'''
Maximum possible value for the Function Lookup Table (FLT). The is just an
initialization value
'''
MAX_FLT_SIZE = 128
# fixed shift step size, (+2)  is for step size (2^2) = 4
SHIFT_SIZE = int(math.ceil(math.log(MAX_FLT_SIZE, 2)) + 2)

'''
The range of possible flag IDs is limited by ARM. For <add, pc,pc,lr>, the
maximum value of lr is 4095. Since the size of the <add> instruction is 2 bytes
and the size of <b> instruction is 4, the possible values we can have begin
from 2 and have a step size of 4. Any value not in the possible range will
result in a run time fault.
'''
VALID_FLAG_ID_RANGE = range(2, 4095, 4)
'''
In order to ensure the values of flag IDs satisfy the VALID_FLAG_ID_RANGE
requirement, we need to have the keys at multiple of 4s.
'''
VALID_KEY_RANGE = range(0, pow(2, SHIFT_SIZE), 4)
INITIAL_SR_VALUE = 2


ROOT_NODE_ATTR = {'shape': 'square', 'color':'darkgreen','style':'filled'}#{'shape': 'triangle', 'color': 'green', 'style':'filled'}
GENERAL_NODE_ATTR = {'shape': 'circle', 'color': 'steelblue', 'style':'filled'}
INDIRCT_NODE_ATTR = {'shape': 'diamond', 'color': 'orange', 'style':'filled'}
LEAF_NODE_ATTR = {'shape': 'square', 'color': 'red', 'style':'filled'}
INDIR_EDGE_ATTR = {'color': 'red', 'style': 'dashed'}
TOTAL_NUM_OF_PATHS = 0
CG_TOTAL_PATHS = 0
IN_FLAGS_ARR = []
OUT_FLAGS_ARR = []
DEBUG_DUMMY = 0
STDLIB_FILE = ENCODER_PATH + "/" + "STD_LIB.json"
EXT_LIB_OPT_LIST_FILE = ENCODER_PATH + "/" + "EXT_LIB_OPT_LIST.json"
ENABLE_DBG_POINT = True
################################################################################
# FUNCTIONS/CLASSES
################################################################################


def log_err_table():
    stdout_holder = sys.stdout
    with open(ERROR_LOG, 'w') as err_fd:
        sys.stdout = err_fd
        for name, func in FUNC_DICT.items():
            print(name)
            func.print_info()
    sys.stdout = stdout_holder


def get_initial_sr_value(shift_size, max_shift):
    sr_value = 0
    for i in range(0, max_shift+1, shift_size):
        sr_value |= 2 << (i)
    return sr_value


def get_sr_enc_segment_size(segment_bits):
    seg_size = pow(2, segment_bits) - 1
    return seg_size


def get_tcfi_label(func_name, callee_name):

    label_name = func_name + "_" + callee_name + "_TCFI"
    return label_name


def get_ldr_inst(target):
    res_inst = "ldr r12,=" + str(target) + "\n"
    return res_inst


def get_ldr_pc_tcfi(idx, tcfi_size):
    '''

    :param idx:
    :param tcfi_size:
    :return:
    '''
    '''
    pc distance:
    even tcfi_set:
        12 -> teq (4) + beq(4) + (4) the last bkpts befor the data
    12 -> ldr(4) + teq (4) + beq(4). Multiply this by the number of remaining
          tcfi check blocks.

    4 -> the constant pool .word size (4). Multiply this by its idx in the
         constant pool.
    '''

    pc_distance = 12 + ((tcfi_size - 1 - idx) * 12) + (4 * idx)

    res_inst = "ldr r12, [pc, #" + str(pc_distance) + "]\n"
    return res_inst


def get_b_inst(target):
    res_inst = "b " + str(target) + "\n"
    return res_inst


def get_beq_inst(target):
    res_inst = "beq.w " + str(target) + "\n"
    return res_inst


def get_xor_inst(key):
    global XOR_INST
    res_inst = XOR_INST + str(key) + "\n"
    return res_inst


def get_tlr_mov1_inst(flt_shift):

    left_shift = flt_shift
    if (flt_shift + SHIFT_SIZE) > ARCH_REGISTER_SIZE:
        '''
        In case we are using a reset of SR (i.e., shift > 32) then adjust
        the shift of the key after resetting SR to the actual segment
        '''
        # get modulus
        mod_factor = ARCH_REGISTER_SIZE / SHIFT_SIZE
        adjusted_shift = flt_shift - (mod_factor * SHIFT_SIZE)
        left_shift = adjusted_shift

    res_inst = "mov r12, lr, lsl #" + str(ARCH_REGISTER_SIZE - left_shift -
                                          SHIFT_SIZE) + "\n"
    return res_inst


def get_tlr_mov2_inst(mask_val):
    res_inst = "mov r12, r12, lsr #" + str(ARCH_REGISTER_SIZE - mask_val) + "\n"
    return res_inst


def get_rec_add_inst(shift_val):
    shifted_inc = 1 << shift_val
    res_inst = "add lr, #" + str(shifted_inc) + "\n"
    return res_inst


def get_rec_sub_inst(shift_val):
    shifted_inc = 1 << shift_val
    res_inst = "sub lr, #" + str(shifted_inc) + "\n"
    return res_inst


def get_rec_tlr_mov_shift_inst(rec_shift):
    # here we use rec_shift + 1 because the first bit is for checking
    # cyclic/multi recursion. There is a move prior that shifts left by one
    # that is applied at the compiler end (i.e., not here), so
    # we need to shift right  (rec_shift + 1) with the 1 as an artifact
    # from the prior shift left.
    res_inst = "mov r12, r12, lsr #" + str(rec_shift+1) + "\n"
    return res_inst


def require_sr_reset(func_sr_shift, callee_sr_shift):
    if (func_sr_shift + SHIFT_SIZE) < ARCH_REGISTER_SIZE:
        if (callee_sr_shift + SHIFT_SIZE) > ARCH_REGISTER_SIZE:
            return True
    return False


class CallerNode:
    def __init__(self, func_node, num_of_calls):
        self.num_of_calls = num_of_calls
        self.func_node = func_node
        # should be func_name:[id flags]
        self.input_flags = OrderedDict()


class CalleeNode:
    def __init__(self, func_node, num_of_calls):
        self.num_of_calls = num_of_calls
        self.func_node = func_node
        # should be in the form func_name:[id flags]
        self.output_flags = OrderedDict()


class FuncNode:
    def __init__(self, name):
        self.name = name
        self.callees = OrderedDict()
        self.callers = OrderedDict()
        self.sum_callees = 0
        self.sum_callers = 0
        self.level_list = []
        # max and min levels are -1 only for initialization,
        # no level should be -1. Levels start at 0 for root functions
        self.max_level = None
        self.min_level = None
        self.key_list = []

        # Formed as {key :{label:label_name, flags:[], NAME: callee_name,
        # SHIFT: shift_val, SHIFTED_KEY: shifted_key}}
        self.keys_dict = OrderedDict()
        # Formed { callee, {in_flag: { Label:return_label_name, caller:name}
        self.in_flags_dict = OrderedDict()
        # a dictionary for recursive functions
        # Formed { label_name {recursion_cntr_bits: bit_size, shift:cntr_shift}
        self.recursive_lbls_dict = OrderedDict()
        self.recursion_tlr_lbl = ""
        self.eh_context = False

        self.in_flags = []
        self.sum_in_flags = 0
        self.out_flags = []
        self.sum_out_flags = 0
        self.root_func = False
        self.leaf_func = False
        self.recursive_func = False
        self.recursive_path = False
        self.multi_recursive = False
        self.num_recursive_calls = 0    # used to check if there are > 1 calls
        self.keys_generated = False
        self.lookup_table_size = 0
        self.num_called_sites = 0
        # the table size with shifting
        self.shifted_flt_size = 0
        # shift value for the function
        self.sr_shift = 0
        # helper variable to calculate number of shifted path from the current
        # caller. We then use the value to multiply it by the FLT size of that
        # caller. This avoids using a for loop with the size of caller's FLT.
        self.num_shifted_caller_paths = 0
        # helper variable to help solve for sr_shift
        self.require_shift = False
        # variable to indicate the function shifted size has been found
        self.shifted_size_finalized = False
        # list of cyclic callees
        self.cyclic_callees = []

    def add_level(self, level):
        # check if the same level value has not been added before to avoid
        # repetition
        if level not in self.level_list:
            self.level_list.append(level)
            if not self.min_level:
                self.min_level = level
            if not self.max_level:
                self.max_level = level

            # automatically update min/max levels
            for level_val in self.level_list:
                if level_val > self.max_level:
                    self.max_level = level_val
                if level_val < self.min_level:
                    self.min_level = level_val

    def get_min_max_levels(self):
        return self.min_level, self.max_level

    def make_root_function(self):
        self.root_func = True
        # also set it as eh_context if not main
        if self.name != "main":
            self.eh_context = True

    def calc_sum_callers_callees(self):
        """
        Calculate the in/out degrees (i.e., sum of callers/callees) for
        FuncNode. It is important to note that this calculates the total number
         of calls, not the the number callers/callees nor the total sum of
         input/output flags (which can be larger the sum_callers/sum_callees)
        :return: None
        """
        # first calculate the in_flags sum
        for caller_name, caller_obj in self.callers.items():
            self.sum_callers += caller_obj.num_of_calls
        # calculate out_flags sum
        for callee_name, callee_obj in self.callees.items():
            self.sum_callees += callee_obj.num_of_calls
        #print("%s: IN=%d, OUT=%d" % (self.name, self.sum_callers, self.sum_callees))

    def calc_in_out_flags_sum(self):
        """
        Calculate the in/out degrees (i.e., sum possible input/output flags).
        :return: None
        """
        self.sum_in_flags = len(self.in_flags)
        self.sum_out_flags = len(self.out_flags)
        return

    def update_callers_num_of_calls(self):
        """
        Updates the number of times each caller calls this FuncNode with the
        correct value. This is done since the resulting JSON from LLVM provides
        the caller functions but does not provide how many times the caller
        calls this function. The update just matches num_of_calls from the
        caller function callee list with num_of_calls in the caller list here
        :return: None
        """
        #[rai-debug]: delete this function
        for caller_name, caller_obj in self.callers.items():
            actual_num_of_calls = caller_obj.func_node.callees[self.name].num_of_calls
            # now update the caller_obj with the new num_of_calls
            caller_obj.num_of_calls = actual_num_of_calls

    def print_callers_callees(self):
        caller_table = Texttable()
        callee_table = Texttable()
        caller_list = []
        callee_list = []
        # columns for the table
        caller_list.append(['Caller', '# of calls'])
        callee_list.append(['Callee', '# of calls'])
        # get caller list
        for caller_name, caller_obj in self.callers.items():
            caller_list.append([str(caller_name), caller_obj.num_of_calls])
        # get callee list
        for callee_name, callee_obj in self.callees.items():
            callee_list.append([str(callee_name), callee_obj.num_of_calls])

        caller_table.add_rows(caller_list)
        callee_table.add_rows(callee_list)
        print('-'*40)
        print('Callers & Callees table for func: %s' % self.name)
        print(caller_table.draw())
        print('*'*20)
        print(callee_table.draw())
        print('-'*40)
        return

    def get_key_outflags(self, key, key_shift, inflags_list):
        outflags_list = []
        for flag in inflags_list:
            #print("func: %s, type(key): %s, type(flag): %s"
            #      % (self.name, key, flag))
            if self.sr_shift < key_shift:
                flag = INITIAL_SR_VALUE
            outflags_list.append(key ^ flag)
        return outflags_list

    def del_outflags(self, label, outflags_list):
        print("|||||||| DELETING OUTFLAGS ||||||||")
        print(" outflag list to delete: ", outflags_list)
        print("func: %s, Label: %s" %(self.name, label))
        #self.print_info()
        print("="*20)
        for flag in outflags_list:
            # [rai-debug]: delete should be in keys_dict
            # [rai-debug]: double check if passing when flag does not
            # exist is OK
            if flag in self.keys_dict[label][FLAG_KEY]:
                self.keys_dict[label][FLAG_KEY].remove(flag)
        #self.print_info()
        print("|||||||||||||||||||||||||||||||||||")
        return

    def add_fid(self, flag, ret_label, caller_node):
        # first verify the flag is correct
        # correctness check, if it does not pass then print error message
        # and exit.
        if (flag - 2) % 4 != 0:
            self.print_info()
            caller_node.print_info()
            print(
            "[-] ERROR: flag %d between %s->%s is not a "
            "valid flag. It does not satisfy (flag -2) %% 4 = 0. Without"
            " this the FLT cannot be aligned correctly. Check "
            "ERROR-LOG.txt for details."
            % (flag, caller_node.name, self.name))
            log_err_table()
            sys.exit(0)
        self.in_flags_dict[flag] = {LABEL: ret_label, CALLER: caller_node}

    def del_inflags(self, inflags):
        for flag in inflags:
            if flag in self.in_flags_dict.keys():
                del(self.in_flags_dict[flag])
            else:
                print("[!] Warning: No inflag <%d> for func<%s>, del_inflags did"
                      "perform any action" %(flag, self.name))

    def get_label_callee(self, label):
        """
        Returns the callee object associated with label from keys_dictionary.
        :param label:
        :return: Callee object
        """
        callee_node = self.keys_dict[label][CALLEE]
        return callee_node

    def get_caller_inflags(self, caller_name):
        """
        Returns a list inflags corresponding the specified caller.
        :param caller_name:
        :return: A list of Flag IDs (i.e., inflags) that point to caller_name.
        """
        caller_inflags = []
        for inflag, inflag_obj in self.in_flags_dict.items():
            if inflag_obj[CALLER].name == caller_name:
                caller_inflags.append(inflag)
        return caller_inflags

    def update_outflags(self, new_inflag):
        """
        Directly computes the new_outflag from inserting new inflag. This
        function does not check conflict with the callee. It relies on the
        check in gen_func_key_flag to catch the conflict (if it exists) and
        replacing the key when func_node pushes the inflags into the callee.
        :param new_inflags:
        :return:
        """
        for label, key_obj in self.keys_dict.items():
            key = key_obj[KEY]
            callee_obj = key_obj[CALLEE]
            shift_val = callee_obj.func_node.sr_shift
            # verify that the caller shift is < than callee shift
            if self.sr_shift > shift_val:
                # this is an error!
                dbg_point = raw_input("[-] ERROR: caller shift > callee shift"
                                      ", caller: %s, callee: %s, "
                                      "caller_shift : %d, callee_shift : %d"
                                      % (self.name, callee_obj.func_node.name,
                                         self.sr_shift,
                                         callee_obj.func_node.sr_shift))
            # if there is a different, in_flag should be the initial SR
            elif self.sr_shift < shift_val:
                new_inflag = INITIAL_SR_VALUE << shift_val
            # if the shift is the same, no need to change the new_inflag
            new_outflag = ((key << shift_val) ^ new_inflag) >> shift_val
            add_func_key_callee_flag(self, callee_obj, key, new_outflag, label,
                                     shift_val, (key << shift_val))
        return

    def is_fid_not_in_flt(self, flag):
        # check if it is a indirect object
        '''
        if INDIRECT_POSTFIX in self.name:
            # for indirect object we need to check all the callees to verify
            # no collisions happen
            for callee_name, callee_obj in self.callees.items():
                if flag in callee_obj.func_node.in_flags_dict:
                    return False
        # otherwise, it is a normal function
        else:
        '''
        if flag in self.in_flags_dict:
            return False

        # if no collisions, flag is good and return true
        return True

    def add_indirect_call_fids(self, fid):
        # double check this is actually an indirect call
        if INDIRECT_POSTFIX in self.name:
            for callee_name, callee_node in self.callees.items():
                # idx is not used for get_label_name with indirect calls
                # so we just pass 0
                ret_label = get_label_name(self.name,
                                           callee_node.func_node.name, 0)
                # add the fid to the callee
                callee_node.func_node.add_fid(fid, ret_label, self)
        return

    def print_info(self):
        """
        Prints 2 tables summarizing the function's information. The first lists
        the Label/Key/OutFlags/Callee. The second InFlag/ReturnLabel/Caller
        :return: None
        """
        key_dict_table = Texttable()
        in_flags_table = Texttable()
        keys_list = []
        inflags_list = []
        keys_list.append(['Label', 'Key','Flags', 'Callee', SHIFT, SHIFTED_KEY])
        inflags_list.append(['InFlag', 'Return_Label', 'Caller'])
        for label, v in self.keys_dict.items():
            hex_key = hex(self.keys_dict[label][KEY])
            hex_shifted_key = hex(self.keys_dict[label][SHIFTED_KEY])
            key_str = str(self.keys_dict[label][KEY]) +\
                      " [" + str(hex_key) + "]"
            shifted_key_str = str(self.keys_dict[label][SHIFTED_KEY]) +\
                              " [" + str(hex_shifted_key) + "]"
            keys_list.append([str(label), key_str,
                              str(self.keys_dict[label][FLAG_KEY]),
                              str(self.keys_dict[label][CALLEE].func_node.name),
                              str(self.keys_dict[label][SHIFT]),
                              str(shifted_key_str)])

        for key, v in self.in_flags_dict.items():
            inflags_list.append([str(key), str(self.in_flags_dict[key][LABEL]),
                              str(self.in_flags_dict[key][CALLER].name)])

        key_dict_table.add_rows(keys_list)
        in_flags_table.add_rows(inflags_list)
        print("-"*80)
        inflags = self.in_flags_dict.keys()
        # safety check in case there are no inflags, only print name and size
        # if there are inflags, then give the stats
        if inflags:
            num_flags = len(inflags)
            print(num_flags, np.max(inflags))
            print("-----------------")
            real_table_size = math.ceil((np.max(inflags)+2)/4.0)
            print("real table size : %d" %real_table_size)
            efficiency_per = round(float(len(inflags))/real_table_size, 1)
            print("FUNCTION NAME %s, Lookup table size: %d, MAX: %d, MIN: %d, "
                  "Efficiency : %0.2f [%d/%d]"
                  % (self.name, len(inflags), np.max(inflags), np.min(inflags),
                     efficiency_per, num_flags, real_table_size))
        else:
            print("FUNCTION NAME %s, Lookup table size: %d"
                  % (self.name, len(inflags)))
        print(key_dict_table.draw())
        print(in_flags_table.draw())
        print("-"*80)


def get_label_name(func_name, callee_name, idx):
    # in case either the caller/callee is an indirect call, then just return
    # the indirect object name, otherwise generate the return label normally
    #if INDIRECT_POSTFIX in func_name:
    #    label_name = func_name
    if INDIRECT_POSTFIX in callee_name:
        label_name = callee_name
    else:
        label_name = func_name + "_" + callee_name + "_" + str(idx)
    return label_name


def is_equivalent_flag(in_flag, ret_label, callee_indict):
    """
    Checks if we have an equivalent flag in case of segmenting
    SR (i.e., shifting)
    :param in_flag:
    :param ret_label:
    :param callee_indict:
    :return:
    """
    if in_flag in callee_indict.keys():
        if ret_label == callee_indict[in_flag][LABEL]:
            return True
        return False
    return False


def is_recursive_call(caller_name, callee_name):
    """
    This function checks wether the the given label is recursive of not. Note
    that the indirect recursion occurs when the indirect call is in the caller
    name.
    :param caller_name:
    :param callee_name:
    :return: Ture if both match, false otherwise.
    """
    caller_name = caller_name.split(INDIRECT_POSTFIX, 1)[0]

    if caller_name == callee_name:
        return True
    return False


def gen_callers_callees(json_call_graph, cg, func_dict):
    """
    Adds the callers/callees for each function in FUNC_DICT global
    :param json_call_graph: json file from LLVM represnting the call graph
    :param CG: An object used to draw the call graph in an object
    :return: None
    """
    global INDIRECT_POSTFIX, NUM_CG_NODES, NUM_CG_EDGES
    # The first loop populates the FuncNode objects using the JSON file
    for func_name, func_node in func_dict.items():
        # add callers, but need to check the function is not a root function
        # since root functions do not have callers
        if not func_dict[func_name].root_func:
            for caller_func_name, num_calls in json_call_graph[func_name][CALLERS].items():
                # add the caller FuncNode and the number of calls
                func_dict[func_name].callers[caller_func_name] = \
                    CallerNode(func_dict[caller_func_name], num_calls)

        # add callees
        # check if it is a leaf function (no callees)
        if not func_dict[func_name].leaf_func:
            #print("#"*40)
            #print("[urai-debug]: %s" % func_name)
            #print("#"*40)
            for callee_func_name, num_calls in json_call_graph[func_name][CALLEES].items():
                # add the caller FuncNode and the number of calls
                func_dict[func_name].callees[callee_func_name] = \
                    CalleeNode(func_dict[callee_func_name], num_calls)

                # add the number of called sites (in_edges) to the callee, the
                # the goal here is measure the minimum possible size of the
                # lookup table for each function
                func_dict[callee_func_name].num_called_sites += num_calls

    # another loop is needed now to updated the num_of_calls for callers. The
    # JSON file has num_of_calls = 1 for each caller, we update this using
    # using the callee information  (num_of_calls) from the caller node
    # As an example, if foo calls bar 3 times (bar should have 'bar':3 in foo's
    # callee list of the JSON file) then bar should have ('foo': 3) in its
    # callers list.
    for func_name, func_node in func_dict.items():
        #func_node.update_callers_num_of_calls()
        # calculate the in/out flags degrees
        #func_node.calc_in_out_flags_sum()
        func_node.calc_sum_callers_callees()

    # After building the CG, always get the latest CG NODES/EDGES number
    cg, NUM_CG_NODES, NUM_CG_EDGES = build_callgraph(cg, func_dict)

    '''
    Get the maximum # of call sites and return it. This enables the
    reconfiguration function to identify possible option for FLT size.
    '''
    num_call_sites_list = []
    for func_name, func_node in func_dict.items():
        num_call_sites_list.append(func_node.num_called_sites)
    max_num_call_sites = np.max(num_call_sites_list)

    return cg, func_dict, max_num_call_sites


def build_callgraph(cg, funcs_dict):
    global INDIRECT_POSTFIX
    cg_nodes = 0
    cg_edges = 0
    # get extlib dictionary
    with open(EXT_LIB_OPT_LIST_FILE, 'r') as extlib_opt_fd:
        extlib_dict = json.load(extlib_opt_fd)
    # loop through the list of functions to add each function callees
    for func_name, func_node in funcs_dict.items():
        if (INDIRECT_POSTFIX not in func_name) and \
                (func_name not in extlib_dict):
            cg_nodes += 1
        for callee_name, callee_obj in func_node.callees.items():
                if INDIRECT_POSTFIX in func_name or INDIRECT_POSTFIX in callee_name:
                    cg.add_edge(func_name, callee_name,
                                weight=callee_obj.num_of_calls,
                                label=callee_obj.num_of_calls,
                                attr_dict=INDIR_EDGE_ATTR)
                else:
                    cg.add_edge(func_name, callee_name,
                                weight=callee_obj.num_of_calls,
                                label=callee_obj.num_of_calls)

                # update num of edges
                if (INDIRECT_POSTFIX not in callee_name) and \
                        (callee_name not in extlib_dict):
                    cg_edges += callee_obj.num_of_calls
    return cg, cg_nodes, cg_edges


def get_leaf_funcs(func_dict):
    leaf_funcs_dict = {}
    print("[+] Collecting leaf functions...")
    for func_name, func_node in func_dict.items():
        if func_node.leaf_func:
            leaf_funcs_dict[str(func_name)] = func_node
            print('\t<%s>' % func_name)
    print("\tNumber of leaf funcs: %d" % len(leaf_funcs_dict))
    return leaf_funcs_dict


def get_root_funcs(func_dict):
    """
    Returns a dictionary of functions that have no callers, these functions are
    root functions in the call graph (i.e., level 0). The dictionary is in the
    format {name, FuncNode object}
    :param json_call_graph:
    :return: list of root functions
    """
    root_func_dict = {}
    print("[+] Collecting root functions...")
    for func_name, func_node in func_dict.items():
        if func_node.root_func:
            root_func_dict[str(func_name)] = func_node
            print('\t<%s>' % func_name)
    print("\tNumber of root funcs: %d" % len(root_func_dict))
    return root_func_dict


def update_func_key(old_key, func_node, invalid_key_list,
                    ret_label, alg_opt):
    """
    Updates func_node with the new key and removes the old key. The update is
    propagated to the callees and sub-callees (i.e., until leaf functions).
    :param old_key:
    :param func_node:
    :param invalid_key_list:
    :param ret_label:
    :param alg_opt:
    :return:
    """

    path = [func_node.name]
    #print("*"*10 )
    print("UPDATE KEY (%d) for func: %s  " %(old_key, func_node.name))
    #func_node.print_info()
    print("REMOVING...........")
    # save the old key information
    #label_name = func_node.keys_dict[old_key][LABEL]
    old_flags = list(func_node.keys_dict[ret_label][FLAG_KEY])
    callee_node = func_node.keys_dict[ret_label][CALLEE]
    # get callee flags
    callee_flags = callee_node.func_node.in_flags_dict.keys()
    # get callee flags without old flags from func_node from this call site
    callee_flags = set(callee_flags) - set(old_flags)
    # set shift value
    shift_val = callee_node.func_node.sr_shift
    # delete the old key
    del(func_node.keys_dict[ret_label])
    # get a new key
    is_invalid_key = True
    while is_invalid_key:
        new_key = gen_func_key(invalid_key_list, func_node, callee_node, alg_opt)
        # assume the key is good, if it is not we will reset it to True later
        is_invalid_key = False
        if new_key not in invalid_key_list:
            new_flags = gen_flags(func_node, callee_node, new_key)
            # check if new flags are not in callee in_flag_ids
            # [rai-debug]: only the path following the callee associated with
            # the call site needs an update

            # check if there is intersection
            if set(new_flags) & set(callee_flags):
                # new key does not work, add it to the invalid list and
                # and search again
                invalid_key_list.append(new_key)
                is_invalid_key = True

        else:
            # key does not work, go through the loop to generate a new key
            invalid_key_list.append(new_key)
            is_invalid_key = True

    # now we have a valid new_key/flags, so add them to the dictionary
    add_func_key_callee_flag(func_node, callee_node, new_key,
                             new_flags, ret_label, shift_val,
                             (new_key << shift_val))
    #print("#"*20)
    #func_node.print_info()
    #callee_node.func_node.print_info()
    #print("#"*20)
    # we only need to update the path from the call site causing the violation
    update_func_flags(new_flags, old_flags, ret_label, func_node,
                      callee_node.func_node, path, alg_opt)
    return new_flags


def update_func_flags(new_inflags, old_inflags, ret_label, caller_func,
                      func_node, path, alg_opt):
    path += [func_node.name]
    '''
    (1) Remove old in_flags and add the new ones. Note we assume a check has
    been done prior to this function
    '''
    # remove old in flags
    for oif in old_inflags:
        #if oif not in func_node.in_flags_dict.keys():
        #    func_node.print_info()
            #stop_var = raw_input('[?] oif %d not in <%s> inflags'
            #                     ', new_inflags = %s, old_inflags =%s, '
            #                     'label: %s' % (oif, func_node.name,
            #                                    new_inflags, old_inflags, ret_label))
        if oif in func_node.in_flags_dict.keys():
            del(func_node.in_flags_dict[oif])
    # add new flags
    add_func_inflags(func_node, caller_func, ret_label, new_inflags)

    '''
    (2) Now, for each key, generate the old outflags associated with the old inflags.
    This is done to remove the old ones from the flag list in
    (func_node.keys_dict).
    (3) Next, generate the new out_flags resulting from the new in_flags. First,
    we calculate the new out_flags.
    (4) We remove the old_outflags from the callee_node
    (old_out_flags from the caller===old_inflags for the callee)
    (5) Then, we check if the result conflicts wit the callee inflags. If this
    is the case we need to update the violating key. If not, we pass the new and
    old out_flags to the callees recursively.
    '''
    for label, key_obj in func_node.keys_dict.items():
        '''
        (2)
        '''
        key = key_obj[KEY]
        # we need to know the shift for the key (i.e., the callee) to generate
        # the correct old_outflags
        key_shift = key_obj[SHIFT]
        print("[rai-debug]: caller: %s, func: %s, key: %s, old_inflags: %s"
              % (caller_func.name, func_node.name, key, old_inflags))
        old_outflags = func_node.get_key_outflags(key, key_shift, old_inflags)
        func_node.del_outflags(label, old_outflags)
        '''
        (3)
        '''
        new_outflags = func_node.get_key_outflags(key, key_shift, new_inflags)
        '''
        (4)
        '''
        # [rai-debug]: we use callee_obj later to add the new_outflags, so we
        # have a separate variable for it. If possible clean this implementation
        callee_obj = func_node.get_label_callee(label)
        callee_node = callee_obj.func_node
        callee_node.del_inflags(old_outflags)
        # set shift value
        shift_val = callee_node.sr_shift
        '''
        (5)
        '''
        # check there is no conflict between new current inflags
        # first we get the set of keys without old_outflags
        callee_updated_inflags = list(set(callee_node.in_flags_dict) -
                                      set(old_outflags))
        # if there is conflict
        if set(new_outflags) & set(callee_updated_inflags):
            invalid_key_list = []#, key] [rai-debug]: check if having key helps or not
            # we need to update (i.e. replace) the current key
            update_func_key(key, func_node, invalid_key_list, label, alg_opt)
        # if there is NO conflict, just add the flags recursively
        else:
            # [rai-debug] add new_outflags to label then call
            add_func_key_callee_flag(func_node, callee_obj, key,
                                     new_outflags, label, shift_val,
                                     (key << shift_val))
            update_func_flags(new_outflags, old_outflags, label, func_node,
                              callee_node, path, alg_opt)
            print("="*20)
            print("update_func_flags PATH: ", path)
            print("="*20)
            path.pop()

    return


def add_func_key_callee_flag(func_node, callee_node,
                             key, flags, ret_label, shift_val, shifted_key):
    # converting flags to list makes it easier for the rest of the function
    flags = np.array(flags).tolist()
    if not isinstance(flags, list):
        flags = [flags]
    '''
    This function has 2 cases:
     1) If we already have the label added then all we need to do is to
        add the additional flag id value.
     2) If the label has not been added, generate the associated label and add
        the key and associated data to the dictionary.

    - Special case: for indirect obj, we append the callee's name to the return
        label in order to push the FIDs to all the typed target set, otherwise
        the keys_dict will contain the last updated callee only.
    '''
    # fix ret_lable in case we have an indirect call as a caller
    #if INDIRECT_POSTFIX in func_node.name:
    #    ret_label += "_" + callee_node.func_node.name
    # ---------------------------
    # 1)
    # ---------------------------
    if ret_label in func_node.keys_dict:
        for f in flags:
            # only add flag if it is not seen before
            if f not in func_node.keys_dict[ret_label][FLAG_KEY]:
                func_node.keys_dict[ret_label][FLAG_KEY].append(f)

    # ---------------------------
    # 2)
    # ---------------------------
    else:
        if (shift_val + SHIFT_SIZE) > ARCH_REGISTER_SIZE:
            '''
            In case we are using a reset of SR (i.e., shift > 32) then adjust
            the shift of the key after resetting SR to the actual segment
            '''
            # get modulus
            mod_factor = ARCH_REGISTER_SIZE / SHIFT_SIZE
            adjusted_shift = shift_val - (mod_factor * SHIFT_SIZE)
            #print("SHIFT_SIZE = %d, shift_val = %d, mod_factor = %d, "
            #      "adjusted_shift = %d" % (SHIFT_SIZE, shift_val, mod_factor,
            #                               adjusted_shift))
            shifted_key = key << adjusted_shift
        func_node.keys_dict[ret_label] = {KEY: key, FLAG_KEY: flags,
                                          CALLEE: callee_node, SHIFT: shift_val,
                                          SHIFTED_KEY: shifted_key,
                                          IS_RECURSIVE: False}
    return


def add_func_inflags(func_node, caller_node, ret_label, inflags):
    if func_node.name == "Func8":
        print("[add_func_inflags] inflags: %s, ret_label: %s, caller: %s"
              % (inflags, ret_label, caller_node.name))
    for flag in inflags:
        # safety check for duplication
        #if flag in func_node.in_flags_dict.keys():
            #func_node.print_info()
            #variable = raw_input("[-] ERROR: Duplicate in_flags for function"
            #                     "<%s>, calling print info" % func_node.name)
        func_node.add_fid(flag, ret_label, caller_node)
    return


def gen_flags(func_node, callee_node, key):

    new_flags = []
    # set the SR shift value
    shift_val = callee_node.func_node.sr_shift

    # loop and generate the possible new flags
    for in_flag in func_node.in_flags_dict:
        if func_node.sr_shift > shift_val:
            # this is an error!
            dbg_point = raw_input(
                "[-] ERROR (gen_flags): caller shift > callee "
                "shift, caller: %s, callee: %s, "
                "caller_shift : %d, callee_shift : %d"
                % (func_node.name, callee_node.func_node.name,
                   func_node.sr_shift,
                   callee_node.func_node.sr_shift))
        # if there is a different, in_flag should be the initial SR
        elif func_node.sr_shift < shift_val:
            in_flag = INITIAL_SR_VALUE #<< shift_val
        new_flags.append(key ^ in_flag)
    return new_flags


def gen_key_flags(func_node, caller_node, path, alg_opt):
    caller_in_flags = func_node.get_caller_inflags(caller_node.name)
    for in_flag in caller_in_flags:

        for callee_name, callee_obj in func_node.callees.items():
            invalid_key_list = []
            for i in range(callee_obj.num_of_calls):
                repeated_flag = True
                # set the return label name
                ret_label = get_label_name(func_node.name, callee_name, i)
                #  set shift val according to callee
                shift_val = callee_obj.func_node.sr_shift
                # set the shifted inflag to inflag at the beginning of each loop
                shifted_inflag = in_flag
                # the while loop here is make sure flags do not repeat
                while repeated_flag:
                    if func_node.keys_generated:
                        key = func_node.keys_dict[ret_label][KEY]
                    else:
                        # should use the flag_gen_alg here
                        key = gen_func_key(invalid_key_list, func_node,
                                           callee_obj, alg_opt)


                    # state_reg should == in_flag here
                    #print("Types, inflag = %s, key =  %s, shift = %s" %(in_flag, key, shift_val))
                    if func_node.sr_shift > shift_val:
                        # this is an error!
                        dbg_point = raw_input(
                            "[-] ERROR (gen_key_flags): caller shift > callee "
                            "shift, caller: %s, callee: %s, "
                            "caller_shift : %d, callee_shift : %d"
                            % (func_node.name, callee_obj.func_node.name,
                               func_node.sr_shift,
                               callee_obj.func_node.sr_shift))
                    # if there is a different, in_flag should be the initial SR
                    elif func_node.sr_shift < shift_val:
                        shifted_inflag = INITIAL_SR_VALUE << shift_val

                    if func_node.sr_shift == shift_val and shift_val > 0:
                        shifted_inflag = in_flag << shift_val
                        flag = ((key << shift_val) ^ shifted_inflag) >> shift_val
                    else:
                        flag = ((key << shift_val) ^ shifted_inflag) >> shift_val

                    # the output flag must not be already in the flag list
                    # or seen before an in_flag for the callee
                    if callee_obj.func_node.is_fid_not_in_flt(flag):
                        repeated_flag = False
                        # update inflags dictionary
                        callee_obj.func_node.add_fid(flag, ret_label, func_node)
                        # update keys_dict with new outflags
                        add_func_key_callee_flag(func_node, callee_obj, key,
                                                 flag, ret_label, shift_val,
                                                 (key << shift_val))
                        # [rai-debug] update the callee with the new out_flags
                        #callee_obj.func_node.update_outflags(flag)

                    # In case of segmentation (i.e., shifting) it is possible
                    # to have the falg generated from the same ret_label, in
                    # this cas we only need to add the keys to the caller.
                    # The callee already has the in_flag
                    elif is_equivalent_flag(flag, ret_label,
                                            callee_obj.func_node.in_flags_dict):
                        repeated_flag = False
                        # update keys_dict with new outflags
                        add_func_key_callee_flag(func_node, callee_obj, key,
                                                 flag, ret_label, shift_val,
                                                 (key << shift_val))
                    # a collision was detected, we need a new key
                    else:
                        # append the key to the invalid list
                        if key not in invalid_key_list or key == 0:
                            invalid_key_list.append(key)
                        # if we are generating new keys for the function, then
                        # do nothing as the while loop take care of calling
                        # gen_func_key to try another key. If we already,
                        # generated the keys for this function, then we need
                        # to update the function with a new key and update its
                        # callees with new flag ids

                        # in case we did not generate keys yet, just loop again
                        if not func_node.keys_generated:
                            continue

                        # if we already generate the keys, we need to replace
                        # the key and update accordingly
                        # should replace and update here
                        print("***** COLLISION!! *****")
                        print("RAT_LABEL: ", ret_label)
                        print("offending key: ", key)
                        print("offending in_flag: ", in_flag)
                        print("offending result flag: ", flag)
                        print(path)
                        #func_node.print_info()
                        #3callee_obj.func_node.print_info()
                        #variable = raw_input('Enter somthing to continue: ')
                        update_func_key(key, func_node, invalid_key_list,
                                        ret_label, alg_opt)
                        print("------- AFTER UPDATE -------")
                        #func_node.print_info()
                        #callee_obj.func_node.print_info()
                        print("*"*20)
                        #variable = raw_input('Enter somthing to continue: ')
                        # stopped here
                        repeated_flag = False

        # We now have visited all callees, then set keys generated to ture
        func_node.keys_generated = True


def relative_jump_key(invalid_key_list, func_node, callee_obj):

    max_inflag = pow(2, 32)     # dummy large value for initialization only
    min_key = None                 # dummy initialization value

    # get func fids
    func_inflags = func_node.in_flags_dict.keys()
    for k in VALID_KEY_RANGE:
        valid_k = True
        k_outflags = []
        #print("k :", k)
        #print("range :", VALID_KEY_RANGE)
        if k not in invalid_key_list:
            # no fids == root func
            if not func_inflags:
                outflag = encode_fk_fid(func_node, callee_obj,
                                        k, INITIAL_SR_VALUE)
                # verify there is no collision
                if not callee_obj.func_node.is_fid_not_in_flt:
                    # there is a collision, add k to invalid and go to the
                    # next iteration
                    invalid_key_list.append(k)
                    continue

                if outflag not in k_outflags:
                    k_outflags.append(outflag)
            # if we are not at root functions
            else:
                for fid in func_inflags:
                    outflag = encode_fk_fid(func_node, callee_obj, k, fid)
                    # verify there is no collision
                    if not callee_obj.func_node.is_fid_not_in_flt:
                        # there is a collision, add k to invalid and go to the
                        # next iteration
                        invalid_key_list.append(k)
                        valid_k = False
                        # break from the inner for loop
                        break
                    if outflag not in k_outflags:
                        k_outflags.append(outflag)
            if valid_k:
                #print("func: ", func_node.name)
                #print("callee: ", callee_obj.func_node.name)
                #print("outflag: ", outflag)
                #print("k_outflags: ", k_outflags)
                if np.max(k_outflags) < max_inflag:
                    min_key = k
                    max_inflag = np.max(k_outflags)
    # check the value of min key
    if min_key is None:
        msg = "[-] ERROR: No key can work for " + func_node.name + \
              " -> " + callee_obj.func_node.name
        print(msg)
        log_err_table()
        #sys.exit(0)
    # if a possible key is found, return it
    return min_key


def random_key(invalid_key_list, func_node, callee_obj):
    if len(invalid_key_list) >= NUM_OF_POSSIBLE_STATES:
        print("[-] ERROR: cannot find a key to satisfy STATE_REGISTER_BIT_SIZE"
              " constraint. Please increase the possible bits.")
    is_invalid = True
    while is_invalid:
        key = random.getrandbits(STATE_REGISTER_BIT_SIZE)
        if key not in invalid_key_list:
            is_invalid = False
    return key


def gen_func_key(invalid_key_list, func_node, callee_obj, alg_opt=RELATIVE_JUMP):
    global DEBUG_DUMMY
    global FLAG_ID_ALGORITHM_OPTIONS
    # verify alg_opt is a vlid option
    if alg_opt not in FLAG_ID_ALGORITHM_OPTIONS:
        print("[-] ERROR: invalid alg_opt: %s, please choose from %s or add"
              " your option to FLAG_ID_ALGORITHM_OPTIONS" % (alg_opt, FLAG_ID_ALGORITHM_OPTIONS))
        sys.exit(0)

    # if case it is an indirect obj, just return 0, otherwise generate
    # the key normally
    if INDIRECT_POSTFIX in callee_obj.func_node.name:
        new_key = 0
    else:
        # this calls the function named in alg_opt
        new_key = globals()[alg_opt](invalid_key_list, func_node, callee_obj)
    return new_key


def gen_dfs_paths(func_node, path, level, alg_opt):
    global TOTAL_NUM_OF_PATHS

    path += [func_node.name]
    func_node.add_level(level)
    level += 1
    for callee_name, callee_node in func_node.callees.items():
        if callee_name not in path:
            # generate key/flags for the callee node
            gen_key_flags(callee_node.func_node, func_node, path, alg_opt)
            # explore the next paths
            gen_dfs_paths(callee_node.func_node, path, level, alg_opt)
    if not func_node.callees:
        TOTAL_NUM_OF_PATHS += 1
    path.pop()


def gen_callgraph_key_flags(func_dict, alg_opt=RELATIVE_JUMP):
    """
    Updates each function node in the call graph with its key, flag and
     possible levels
    :return: None (updates the FUNC_NODE global)
    """
    # start from root functions with DFS
    root_funcs_list = get_root_funcs(func_dict)

    if alg_opt not in FLAG_ID_ALGORITHM_OPTIONS:
        print("[-] ERROR: Uknown algorithm option chosen. Please use one "
              "of the following %s" % FLAG_ID_ALGORITHM_OPTIONS)
        sys.exit(0)

    for func_name, func_node in func_dict.items():
        if func_node.root_func:
            path = []
            level = 0
            '''
            --------------------------------------------------------------------
            (1) generate keys/flags for the root function
            --------------------------------------------------------------------
            '''
            for callee_name, callee_obj in func_node.callees.items():
                invalid_key_list = []
                for i in range(callee_obj.num_of_calls):
                    repeated_flag = True
                    ret_label = get_label_name(func_node.name, callee_name, i)
                    # the while loop here is make sure flags do not repeat
                    # get shift value for callee
                    shift_val = callee_obj.func_node.sr_shift
                    while repeated_flag:
                        key = gen_func_key(invalid_key_list, func_node,
                                           callee_obj, alg_opt)
                        # xor with 0 since we are at root functions
                        flag = ((key << shift_val) ^
                                (INITIAL_SR_VALUE << shift_val)) >> shift_val
                        # the output flag must not be already in the flag list
                        # or seen before an in_flag for the callee
                        if callee_obj.func_node.is_fid_not_in_flt(flag):
                            repeated_flag = False
                            # set the return label name
                            ret_label = get_label_name(func_node.name,
                                                       callee_name, i)
                            callee_obj.func_node.add_fid(flag,
                                                         ret_label, func_node)
                        # a collision was detected, we need a new key
                        else:
                            # append the key to the invalid list
                            if key not in invalid_key_list or key == 0:
                                invalid_key_list.append(key)

                    # update keys_dict
                    add_func_key_callee_flag(func_node, callee_obj, key,
                                             flag, ret_label, shift_val,
                                             (key << shift_val))

            # We now have visited all callees, then set keys generated to true
            func_node.keys_generated = True
            '''
            --------------------------------------------------------------------
            (2) generate paths, levels, keys, and flags for rest of functions
            --------------------------------------------------------------------
            '''
            gen_dfs_paths(func_node, path, level, alg_opt)

    return func_dict


def get_call_graph_max_level(call_graph_dict):
    max_level = 0
    multi_level_funcs = 0
    multi_level_funcs_names = []
    multi_level_leaf_funcs = 0
    multi_level_leaf_names = []
    single_level_leafs = []
    single_level_funcs = []
    for func_name, func_node in call_graph_dict.items():
        if func_node.max_level > max_level:
            max_level = func_node.max_level
        if func_node.leaf_func and len(func_node.level_list) > 1:
            multi_level_leaf_funcs += 1
            multi_level_leaf_names.append(func_name)
        elif func_node.leaf_func and len(func_node.level_list) == 1:
            single_level_leafs.append(func_name)
        elif len(func_node.level_list) > 1 and func_node.leaf_func is not True:
            multi_level_funcs += 1
            multi_level_funcs_names.append(func_name)
        elif len(func_node.level_list) == 1 and func_node.leaf_func is not True:
            single_level_funcs.append(func_name)

    print("SINGLE_LEAFS= %d , MULTI_LEAFS = %d, GENERAL_MULTI_LEVEL = %d"
          ", SINGLE_LEVEL_FUNCS = %d"
          % (len(single_level_leafs), multi_level_leaf_funcs,
             multi_level_funcs, len(single_level_funcs)))
    ''' print("*"*20)
    print("SINGL_LEAFS: ")
    print(single_level_leafs)
    print("MULTI_LEAFS:")
    print(multi_level_leaf_names)
    print("*"*20)
    print("GENERAL_MULTI_LEVEL:")
    print(multi_level_funcs_names)
    print("SINGLE_LEVEL_FUNCS:")
    print(single_level_funcs)
    print("*"*20)
    '''
    return max_level


def unify_func_tcfi_set(json_call_graph):
    global APP_NAME
    tcfi_sizes_list = []
    for func_name, func_json_obj in json_call_graph.items():
        if INDIRECT_POSTFIX not in func_name:
            func_tcfi_list = []
            if func_json_obj[CALLEES]:
                collect_set_stats = False
                for callee_name, val in func_json_obj[CALLEES].items():
                    if INDIRECT_POSTFIX in callee_name:
                        collect_set_stats = True
                        # in case the set is empty, set it to __urai_error
                        if not json_call_graph[callee_name][CALLEES]:
                            json_call_graph[callee_name][CALLEES] = {}
                            continue
                        # now the callee is the indirect object, we need to
                        # get its target set
                        for target_name, tar_val in json_call_graph[callee_name][CALLEES].items():
                            func_tcfi_list.append(target_name)
                if collect_set_stats:
                    # get the target set without duplicates
                    func_tcfi_set = list(set(func_tcfi_list))
                    tcfi_sizes_list.append(len(func_tcfi_set))
                    #print("===========================================")
                    #print("func_name: %s,  "
                    #      "tcfi_set: %s, len(tcfi_set: %d, size_list: %s"
                    #      % (func_name, func_tcfi_set, len(func_tcfi_set),
                    #         tcfi_sizes_list))
                    #print("===========================================")
                for callee_name, val in func_json_obj[CALLEES].items():
                    if INDIRECT_POSTFIX in callee_name:
                        #print("===========================================")
                        #print("func_name: %s, callee_name: %s, "
                        #      "tcfi_set: %s"
                        #      % (func_name, callee_name, func_tcfi_set))
                        #print("===========================================")
                        for target_name in func_tcfi_set:
                            json_call_graph[callee_name][CALLEES][target_name] = 1


    # write the stats
    # verify the list is not empty
    if not tcfi_sizes_list:
        # set to zero
        tcfi_sizes_list.append(0)
    ave_set = np.mean(tcfi_sizes_list)
    median_set = np.median(tcfi_sizes_list)
    max_set = np.max(tcfi_sizes_list)
    min_set = np.min(tcfi_sizes_list)
    print("max: %d, min: %d, median: %d, average: %.1f" % (max_set, min_set,
                                                          median_set, ave_set))
    #print(tcfi_sizes_list)
    # get the stats
    tcfi_stats = OrderedDict()
    tcfi_stats["Min"] = min_set
    tcfi_stats["Median"] = int(round(median_set, 1))
    tcfi_stats["Max"] = np.max(max_set)
    tcfi_stats["Ave"] = int(round(ave_set))

    # add dataFrame of the result
    tcfi_sets_df = pd.DataFrame(tcfi_stats, index=[APP_NAME])
    # write the results to csv file
    tcfi_stats_results_file = TCFI_SETS_TEMP_PATH + "/" + TCFI_SETS_STATS + CSV_EXT
    tcfi_sets_df.to_csv(tcfi_stats_results_file)
    return json_call_graph


def update_incomplete_callers(json_call_graph, CG):
    for func_name, func_json_obj in json_call_graph.items():
        # fix invalid root functions. These are not root functions but have
        # an empty callers dictionary thus confusing them with actual root
        # functions
        if not func_json_obj[CALLERS]:
            # loop again through functions to see if this function is called
            # from another function
            for caller_name, caller_obj in json_call_graph.items():
                if caller_obj[CALLEES]:
                    if func_name in caller_obj[CALLEES]:
                        # get the number of calls, we are not using it but
                        # just as a reference
                        num_calls = caller_obj[CALLEES][func_name]
                        json_call_graph[func_name][CALLERS] = {caller_name:num_calls}
                        #print("Updated Func: %s, caller: %s, num_calls: %d"
                        #      % (func_name, caller_name, num_calls))

    return json_call_graph


def init_func_nodes_list(json_call_graph,  CG, func_dict):
    """
    Populates FUNC_DICT global with initialized function nodes from the JSON
    call graph and sets root/lead flags for each function node
    :param json_call_graph:
    :param filename:
    :return: None
    """
    # first fix the tcfi sets if needed
    if UNIFY_TCFI_SETS:
        json_call_graph = unify_func_tcfi_set(json_call_graph)
    # update the callers dictionary for each function
    json_call_graph = update_incomplete_callers(json_call_graph, CG)
    with open(json_filename +'-mod' + JSON_EXT, 'w') as final_fd:
        json.dump(json_call_graph, final_fd, sort_keys=True, indent=4, ensure_ascii=False)
    for func_name, func_json_obj in json_call_graph.items():
        # create FuncNode object
        func_node = FuncNode(func_name)
        # check if the function is a root function, here we check the json file
        # if no callers exist
        if not func_json_obj[CALLERS]:
            # this is a root function, set the flag and add level 0 to it
            func_node.make_root_function()
            func_node.add_level(0)
            # add func as root to call graph
            CG.add_node(func_name,  ROOT_NODE_ATTR)
        # check if the function is a leaf function (no callees)
        if not func_json_obj[CALLEES]:
            func_node.leaf_func = True
            if not func_node.root_func:
                # add func as a leaf to call graph
                CG.add_node(func_name, LEAF_NODE_ATTR)

        # if function is neither a root of a leaf
        if not func_node.root_func and not func_node.leaf_func:
            # check if it is an indirect call object or a general function
            if INDIRECT_POSTFIX in func_name:
                CG.add_node(func_name, INDIRCT_NODE_ATTR)
            else:
                # add general func to call graph
                CG.add_node(func_name, GENERAL_NODE_ATTR)

        # add func_node object to the global dictionary
        func_dict[func_name] = func_node

    return CG, func_dict


'''
BFS methods to generate FKs/FIDs
'''


def bfs_cg_gen_fk_fid(func_dict, alg_opt=RELATIVE_JUMP):
    """
    Updates each function node in the call graph with its key, flag and
     possible levels
    :return: None (updates the FUNC_NODE global)
    """

    if alg_opt not in FLAG_ID_ALGORITHM_OPTIONS:
        print("[-] ERROR: Uknown algorithm option chosen. Please use one "
              "of the following %s" % FLAG_ID_ALGORITHM_OPTIONS)
        sys.exit(0)

    '''
    We need to loop once for each level, starting from 0 (i.e., root functions).
    '''
    cg_max_level = get_cg_max_level(func_dict)
    tot_num_funcs = len(func_dict)
    func_counter = 0
    for l in range(cg_max_level+1):
        print("="*40)
        print("[+] LEVEL [%d/%d]" % (l, cg_max_level))
        # get a list of functions in the current level
        func_list = get_funcs_at_max_level(func_dict, l)
        # sort the functions according to the largest
        func_list = sort_func_list(func_list)
        # loop through the list and generate the keys
        for func_node in func_list:
            func_counter += 1
            print("[+] Func[%d/%d]: %s" % (func_counter,
                                           tot_num_funcs, func_node.name))
            # if it is a indirect object, then no need to generate FKs
            # as the FIDs has already been passed directly
            #[rai-debug]if INDIRECT_POSTFIX in func_node.name:
            #    continue
            '''
            There are 2 cases here:
            (1) Root functions (level = 0). These do not have FIDs since there
                no callers. Thus, they need to be handled as a special case.
            (2) Other functions. These will use their FIDs to generate the FKs.
            '''
            if l == 0:
                '''
                (1) Root functions
                '''
                for callee_name, callee_obj in func_node.callees.items():
                    invalid_key_list = []
                    for i in range(callee_obj.num_of_calls):
                        repeated_flag = True
                        ret_label = get_label_name(func_node.name, callee_name,
                                                   i)
                        # the while loop here is make sure flags do not repeat
                        # get shift value for callee
                        shift_val = callee_obj.func_node.sr_shift
                        while repeated_flag:
                            key = gen_func_key(invalid_key_list, func_node,
                                               callee_obj, alg_opt)

                            '''
                            In case of an error, return None
                            '''
                            if key is None:
                                return None
                            # xor with 0 since we are at root functions
                            flag = encode_fk_fid(func_node, callee_obj, key,
                                                 INITIAL_SR_VALUE)
                            # the output flag must not be already in the flag list
                            # or seen before an in_flag for the callee
                            if callee_obj.func_node.is_fid_not_in_flt(flag):
                                repeated_flag = False
                                # set the return label name
                                ret_label = get_label_name(func_node.name,
                                                           callee_name, i)
                                callee_obj.func_node.add_fid(flag,
                                                             ret_label,
                                                             func_node)
                            # a collision was detected, we need a new key
                            else:
                                # append the key to the invalid list
                                if key not in invalid_key_list or key == 0:
                                    invalid_key_list.append(key)

                        # update keys_dict
                        add_func_key_callee_flag(func_node, callee_obj, key,
                                                 flag, ret_label, shift_val,
                                                 (key << shift_val))
            else:
                '''
                (2) We can generate the FIDs for all the callees as they
                    will be at a level higher than the caller
                '''
                func_inflag_list = func_node.in_flags_dict.keys()
                for callee_name, callee_obj in func_node.callees.items():

                    '''
                    If it is a recursive call:
                    '''
                    if is_recursive_call(func_node.name, callee_name):
                        for i in range(callee_obj.num_of_calls):
                            # set the return label name
                            ret_label = get_label_name(func_node.name,
                                                       callee_name, i)
                            func_node.recursive_lbls_dict[ret_label] = {
                                IS_RECURSIVE: True,
                                CALLEE: callee_obj,
                                RECURSION_SIZE_KEY: MAX_RECURSION_BITS
                            }

                            # if it is indirect call recursion, or direct
                            # recursion,  make sure to add the return label in
                            #  the callee function for the recursion TLR
                            callee_obj.func_node.recursion_tlr_lbl = ret_label
                            # set the callee as recursive, this is important
                            # in indirect recursion
                            callee_obj.func_node.recursive_func = True
                        # skip to the next iteration as the rest of the code
                        # deals with normal (i.e., non recursive functions)
                        continue


                    '''
                    For regular calls:
                    For each call site, generate the key only once. Verify
                    the key works for the callee with all the FIDs. Otherwise,
                    add it to the invalid list and try again.
                    '''

                    for i in range(callee_obj.num_of_calls):
                        invalid_key_list = []
                        repeated_flag = True
                        # set the return label name
                        ret_label = get_label_name(func_node.name,
                                                   callee_name, i)
                        #  set shift val according to callee
                        shift_val = callee_obj.func_node.sr_shift
                        # we need to generate keys using all fids

                        # the while loop here is make sure flags do not repeat
                        while repeated_flag:
                            # assume will have no collisions unless one is found
                            repeated_flag = False
                            if func_node.keys_generated:
                                key = func_node.keys_dict[ret_label][KEY]
                            else:
                                # should use the flag_gen_alg here
                                key = gen_func_key(invalid_key_list, func_node,
                                                   callee_obj, alg_opt)
                            '''
                            In case of an error, return None
                            '''
                            if key is None:
                                return None

                            # get the result out fids
                            out_fids = []
                            for inflag in func_inflag_list:
                                flag = encode_fk_fid(func_node, callee_obj,
                                                         key, inflag)
                                out_fids.append(flag)
                            if INDIRECT_POSTFIX in func_node.name:
                                if ENABLE_DBG_POINT:
                                    print("###############################")
                                    print("ret_label:", ret_label)
                                    print("func:", func_node.name)
                                    print("i = ", i)
                                    print("key = ", key)
                                    print("inflag = ", inflag)
                                    print("shift = ", shift_val)
                                    print("ofid list = ", out_fids)
                                    print("invalid list = ", invalid_key_list)
                                    callee_obj.func_node.print_info()
                                    print("###############################")
                            # now check that there is no collision with fids
                            for fid in out_fids:
                                '''
                                If there is a collision, break and go to the
                                beginning of the while loop to generate
                                a new key.
                                '''
                                if not \
                                        callee_obj.func_node.is_fid_not_in_flt(fid) \
                                        and not \
                                                is_equivalent_flag(fid, ret_label,
                                                           callee_obj.func_node.in_flags_dict):
                                    repeated_flag = True
                                    invalid_key_list.append(key)
                                    break

                            # in case of collision, loop through the while loop
                            # again to generate a new key
                            if repeated_flag:
                                continue
                            # otherwise, the FKs/FIDs are good so add them
                            else:
                                repeated_flag = False
                                for fid in out_fids:
                                    # update inflags dictionary
                                    callee_obj.func_node.add_fid(fid,
                                                                 ret_label,
                                                                 func_node)
                                    # update keys_dict with new outflags
                                    add_func_key_callee_flag(func_node,
                                                             callee_obj, key,
                                                             fid, ret_label,
                                                             shift_val,
                                                             (key << shift_val))
                                    # if the callee is an indirect call, we
                                    # need to push the fids to the callees
                                    # (i.e., the target set) directly
                                    # [rai-debug]
                                    #if INDIRECT_POSTFIX in \
                                    #        callee_obj.func_node.name:
                                    #    callee_obj.func_node.\
                                    #        add_indirect_call_fids(fid)

            func_node.keys_generated = True

    return func_dict


def encode_fk_fid(func_node, callee_node, key, inflag):
    shift_val = callee_node.func_node.sr_shift
    if func_node.sr_shift > shift_val:
        # this is an error!
        dbg_point = raw_input(
            "[-] ERROR (gen_key_flags): caller shift >"
            " callee shift, caller: %s, callee: %s, "
            "caller_shift : %d, callee_shift : %d"
            % (func_node.name, callee_node.func_node.name,
               func_node.sr_shift,
               callee_node.func_node.sr_shift))
    # if there is a different, in_flag should be
    # the initial SR
    elif func_node.sr_shift < shift_val:
        shifted_inflag = INITIAL_SR_VALUE << shift_val

    else:   # func_node.sr_shift == shift_val:
        shifted_inflag = inflag << shift_val

    flag = ((key << shift_val) ^ shifted_inflag) >> shift_val

    return flag

'''
FLT size and SR shift functions
'''


def walk_cg_paths(func_node, path, level):
    global CG_TOTAL_PATHS

    path += [func_node.name]
    func_node.add_level(level)
    func_node.lookup_table_size += 1
    level += 1

    '''
    In case the root is not main, then the other options are handler functions
    so set this functions as one that can be called from a handler context
    '''
    if path[0] != "main":
        func_node.eh_context = True

    for callee_name, callee_node in func_node.callees.items():
        for i in range(callee_node.num_of_calls):
            if callee_name not in path:
                # explore the next paths
                walk_cg_paths(callee_node.func_node, path, level)
            else:
                if func_node.name == callee_name:
                    # a recursive function
                    callee_node.func_node.recursive_func = True
                    # update recursive calls counter, this is to distinguish
                    # multi recursion from single recursion.
                    callee_node.func_node.num_recursive_calls = \
                        callee_node.num_of_calls
                    if callee_node.func_node.num_recursive_calls > 1:
                        callee_node.func_node.multi_recursive = True
                    #print("!"*20)
                    #print("[!] RECURSIVE FUNC: %s" % func_node.name)
                    #print("[!] Path: ", path)
                    #print("!"*20)
                else:
                    callee_node.func_node.recursive_path = True
                    func_node.cyclic_callees.append(callee_name)
                    #print("!"*20)
                    #print("[!] RECURSIVE path at func: %s" % func_node.name)
                    #print("[!] Path: ", path)
                    #print("!"*20)
    if not func_node.callees:
        CG_TOTAL_PATHS += 1
    path.pop()
    return


def mark_shifted_funcs(func_dict):

    shifted_funcs = []
    shift_idx = 0 # tracks how many times we performed a shift
    '''
    (1) Mark functions that need shift, and set the size for ones that do not.
    '''
    # mark functions that need shifting
    #print("0"*20)
    for func_name, func_node in func_dict.items():
        if func_node.lookup_table_size > MAX_FLT_SIZE:
            #print("MAX_FLT = ", MAX_FLT_SIZE)
            #print("@1520 A shifted func: ", func_name)
            func_node.require_shift = True
            shifted_funcs.append(func_node)
        else:
            # otherwise set the shifted size and finalize it
            func_node.shifted_flt_size = func_node.lookup_table_size
            func_node.shifted_size_finalized = True
            #print("@1528 NOT SHIFTED", func_name)

    while shifted_funcs:
        #print_funcs_level_info(func_dict)
        # update shifting index
        shift_idx += 1
        #print("<"*10)
        #print("shifted_funcs: ")
        #for f in shifted_funcs:
        #    print (f.name)
        #print("shift_idx: ", shift_idx)
        #print("<"*10)
        '''
        (2) Reset the shifted FLT size for all functions that have not
            been finalized, and push their values to the callees. This is
            important when a callee requires a shift, while the caller
            has been finalized.
        '''
        # first reset the unfinalized functions
        for func_name, func_node in func_dict.items():
            if not func_node.shifted_size_finalized:
                func_node.shifted_flt_size = 0

        # update the neighboring functions
        for func_name, func_node in func_dict.items():
            if func_node.shifted_size_finalized:
                for callee_name, callee_node in func_node.callees.items():
                    if not callee_node.func_node.shifted_size_finalized:
                        callee_node.func_node.shifted_flt_size += \
                            callee_node.num_of_calls

        '''
        (3) remove duplicates from shifted functions
        '''
        for func_node in shifted_funcs:
            # check that we did not unmark the function from a previous
            # function in the list
            if func_node.require_shift:
                for callee_name, callee_node in func_node.callees.items():
                    # make sure that we only unmark higher level (i.e., deeper
                    # in call stack) functions.
                    if callee_node.func_node.require_shift and \
                                    func_node.min_level < \
                                    callee_node.func_node.min_level:
                        # unmark the function
                        callee_node.func_node.require_shift = False
                        #print("@remove_duplicate %s->%s [no shift?!]"
                        #      % (func_node.name, callee_node.func_node.name))

        # remove the duplicates from the shifted_funcs
        for func_node in shifted_funcs:
            if not func_node.require_shift:
                shifted_funcs.remove(func_node)
                #print("[POP] removed %s from shifted_funcs" % func_node.name)

        '''
        (4) Traverse the call graph starting from the shifted functions and set
            calculate the shifted size
        '''
        for func_node in shifted_funcs:
            #print("@1588[shifted_funcs]: ")
            #for f in shifted_funcs:
            #    print(f.name)
            shift_bits = SHIFT_SIZE * shift_idx
            path = []
            walk_shifted_paths(func_node, shift_bits, path)

        '''
        (5) Reset the shift index and check if there are remaining functions
            that require additional shifting.
        '''
        shifted_funcs = []
        for func_name, func_node in func_dict.items():
            if func_node.shifted_flt_size > MAX_FLT_SIZE:
                func_node.require_shift = True
                shifted_funcs.append(func_node)
            else:
                func_node.require_shift = False
                func_node.shifted_size_finalized = True
                #print("@16010 SHIFT_FINALIED: ", func_name)

    return


def walk_shifted_paths(func_node, shift_val, path):
    # update path, shifted_flt_size, and set sr_shift value
    path += [func_node.name]

    func_node.sr_shift = shift_val
    for callee_name, callee_node in func_node.callees.items():
        '''
        we need to loop the same size of the initial shifted flt, For example,
         ---------------------   2 calls   -------------
        |   caller (flt = 3)  | --->      |   callee    |
         ---------------------             -------------
         Without considering the shifted flt size, the calle size will be 2,
         which is wrong. The correct answer should be 3*2 = 6
        '''
        callee_node.func_node.num_shifted_caller_paths = callee_node.func_node.shifted_flt_size # reset
        #for _ in range(func_node.shifted_flt_size):     # _ : unused value
        for i in range(callee_node.num_of_calls):
            #callee_node.func_node.num_shifted_caller_paths += 1
            #callee_node.func_node.shifted_flt_size += func_node.shifted_flt_size #1
            '''
            if os.path.exists(DEBUG_FILE):
                append_write = 'a'  # append if already exists
            else:
                append_write = 'w'  # make a new file if not
            stdout_backup = sys.stdout
            with open(DEBUG_FILE, append_write) as debug_fd:
                sys.stdout = debug_fd
                print("-"*20)
                print("%s [flt = %d] -> %s, FLT size now = %d"
                      % (func_node.name, func_node.shifted_flt_size,
                         callee_node.func_node.name,
                         callee_node.func_node.shifted_flt_size))
                print("-" * 20)
            sys.stdout = stdout_backup
            '''
            if callee_name not in path:
                callee_node.func_node.shifted_flt_size += func_node.shifted_flt_size
                # explore the next paths
                walk_shifted_paths(callee_node.func_node, shift_val, path)
        #callee_node.func_node.shifted_flt_size += \
        #    func_node.shifted_flt_size * \
        #    callee_node.func_node.num_shifted_caller_paths

    path.pop()


def sort_func_list(func_list):
    """
    Sorts the list of functinos according to:
    (1) Shift size
    (2) Shifted FLT size
    :param func_list:
    :return: sorted function list
    """
    sorted_func_list = []
    shift_val_list = []
    for func in func_list:
        if func.sr_shift not in shift_val_list:
            shift_val_list.append(func.sr_shift)

    # sort shift vals in reverse to start from the largest
    shift_val_list.sort(reverse=True)
    for shift_val in shift_val_list:
        shift_val_funcs = []
        for func in func_list:
            if func.sr_shift == shift_val:
                shift_val_funcs.append(func)
        # now sort the funcs with the current shift level according to FLT size
        shift_val_funcs.sort(key=lambda x: x.shifted_flt_size, reverse=True)
        # add the functions to the sorted list
        for func in shift_val_funcs:
            sorted_func_list.append(func)

    # return the sorted list
    return sorted_func_list


def calc_lookup_tables_size(func_dict):
    for func_name, func_node in func_dict.items():
        if func_node.root_func:
            path = []
            level = 0
            '''
            Start from roots and explore the possible paths
            '''
            walk_cg_paths(func_node, path, level)

    '''
    Calculate the shifted FLT
    '''
    mark_shifted_funcs(func_dict)

    lookup_table_info_ = Texttable()
    lookup_table_list = []
    lookup_table_list.append(['Function', 'Lookup Table Size',
                              '# of Called Sites (Min.)', 'Shifted FLT Size',
                              'Shift value'])
    table_sizes_list = []
    shifted_flt_size_list = []
    sr_shifts_list = []
    tables_larger_than_1K = 0
    num_called_sites_list = []
    # print the results and stats
    for func_name, func_node in func_dict.items():

        lookup_table_list.append([str(func_name),
                                  str(func_node.lookup_table_size),
                                  str(func_node.num_called_sites),
                                  str(func_node.shifted_flt_size),
                                  str(func_node.sr_shift)])
        table_sizes_list.append(func_node.lookup_table_size)
        shifted_flt_size_list.append(func_node.shifted_flt_size)
        sr_shifts_list.append(func_node.sr_shift)
        num_called_sites_list.append(func_node.num_called_sites)

        if func_node.lookup_table_size > 1000:
            tables_larger_than_1K += 1

    lookup_table_info_.add_rows(lookup_table_list)
    print("------------------------------ Stats ------------------------------")
    print("MAX_FLT: %d" % MAX_FLT_SIZE)
    print(" # of Funcs: %d" % len(table_sizes_list))
    print("[Lookup table stats] Max: %d, Mean : %d, Median: %d, "
          "lager than 1K: %d" % (np.max(table_sizes_list),
                                 np.mean(table_sizes_list),
                                 np.median(table_sizes_list),
                                 tables_larger_than_1K))

    print("[Shifted FLT stats] Max: %d, Mean : %d, Median: %d, "
          "Max. shift: %d" % (np.max(shifted_flt_size_list),
                              np.mean(shifted_flt_size_list),
                              np.median(shifted_flt_size_list),
                              np.max(sr_shifts_list)))

    print("[# of called sites stats] Max: %d, Mean : %d, Median: %d "
          % (np.max(num_called_sites_list),
             np.mean(num_called_sites_list), np.median(num_called_sites_list)))
    print(lookup_table_info_.draw())
    print("\n")
    #var = raw_input("[rai-Debug] Check the table above...")
    return func_dict, shifted_flt_size_list, sr_shifts_list, num_called_sites_list


def export_lookup_table_results(func_dict, res_file, app_path):
    res_json = {}
    total_num_of_lables = 0
    total_num_flag_ids = 0
    res_json[IS_SHIFTED] = False
    res_json[IS_RECURSIVE] = False
    max_shift = 0
    recursion_cntr_bits = MAX_RECURSION_BITS

    with open(STDLIB_FILE, 'r') as stdlib_fd:
        json_dict = json.load(stdlib_fd)

    with open(EXT_LIB_OPT_LIST_FILE, 'r') as extlib_opt_fd:
        extlib_dict = json.load(extlib_opt_fd)

    for func_name, func_node in func_dict.items():
        max_func_inflag = 0

        if INDIRECT_POSTFIX in func_name:
            res_json[func_name] = {KEYS_DICT: {}, INFLAGS: {}, RET_INSTS: {},
                                   TCFI_INSTRMNT: {}}
        else:
            res_json[func_name] = {KEYS_DICT: {}, INFLAGS: {}, RET_INSTS: {}}

        # add isEntry (i.e., isRoot) value
        res_json[func_name][IS_ENTRY] = func_node.root_func
        res_json[func_name][IS_UNSUPPORTED_LIB] = is_unsupported_lib_func(
            func_name, json_dict)
        res_json[func_name][SHIFT] = func_node.sr_shift
        res_json[func_name][IS_RECURSIVE] = func_node.recursive_func
        res_json[func_name][IS_PATH_RECURSIVE] = func_node.recursive_path
        res_json[func_name][IS_MULTI_RECURSIVE] = func_node.multi_recursive
        res_json[func_name][NUM_RECURSIVE_CALLS] = func_node.num_recursive_calls

        # if this is an indirect object, then add a target set dictionary
        if INDIRECT_POSTFIX in func_name:
            res_json[func_name][TCFI_SET] = []
            for callee_name in func_node.callees.keys():
                res_json[func_name][TCFI_SET].append(callee_name)

            tcfi_size = len(res_json[func_name][TCFI_SET])
            tcfi_idx = 0
            # add TCFI instrumentation
            for callee_name in res_json[func_name][TCFI_SET]:
                ldr_inst = get_ldr_pc_tcfi(tcfi_idx, tcfi_size) #callee_name)
                tcfi_lbl = get_tcfi_label(func_name, callee_name)
                tcfi_llvm_lbl = str(tcfi_lbl) + ":\n"
                tcfi_b_inst = get_beq_inst(tcfi_lbl)
                res_json[func_name][TCFI_INSTRMNT].update(
                    {callee_name: {LDR_INST_KEY: ldr_inst, LABEL: tcfi_llvm_lbl,
                     B_INST_KEY: tcfi_b_inst}}
                )
                tcfi_idx += 1

            # add TCFI label (i.e., the indirect label) and the branch to it
            tcfi_exit_lbl = func_name + ":\n"
            tcfi_exit_instr = get_b_inst(func_name)
            res_json[func_name][TCFI_LBL] = tcfi_exit_lbl
            res_json[func_name][TCFI_EXIT] = tcfi_exit_instr

        # add keys
        for label, key_obj in func_node.keys_dict.items():
            # check is there is a need to reset SR
            callee_shift_val = key_obj[CALLEE].func_node.sr_shift
            reset_sr = require_sr_reset(func_node.sr_shift, callee_shift_val)
            no_shift_key_val = key_obj[KEY]
            key = key_obj[SHIFTED_KEY]
            encode_inst = get_xor_inst(key)
            callee_name = key_obj[CALLEE].func_node.name
            b_inst = get_b_inst(callee_name)
            llvm_label = str(label) + ":\n"
            is_recursive_lbl = key_obj[IS_RECURSIVE]
            res_json[func_name][KEYS_DICT].update(
                {label: {LABEL: llvm_label, KEY: key,
                         KEY_WITHOUT_SHIFT: no_shift_key_val,
                         XOR_INST_KEY: encode_inst, B_INST_KEY: b_inst,
                         REQ_SR_RESET_KEY: reset_sr,
                         IS_RECURSIVE: is_recursive_lbl}})
            total_num_of_lables += 1

        # add recursive labels
        for label, key_obj in func_node.recursive_lbls_dict.items():
            callee_name = key_obj[CALLEE].func_node.name
            recursion_cntr_l_shift = ARCH_REGISTER_SIZE - MAX_RECURSION_BITS
            b_inst = get_b_inst(callee_name)
            rec_add_inst = get_rec_add_inst(recursion_cntr_l_shift)
            rec_sub_inst = get_rec_sub_inst(recursion_cntr_l_shift)
            llvm_label = str(label) + ":\n"
            is_recursive_lbl = key_obj[IS_RECURSIVE]
            # write the results to the dictionary
            res_json[func_name][KEYS_DICT].update(
                {label: {LABEL: llvm_label, KEY: None,
                         KEY_WITHOUT_SHIFT: None,
                         XOR_INST_KEY: None, B_INST_KEY: b_inst,
                         ADD_REC_INST_KEY: rec_add_inst,
                         SUB_REC_INST_KEY: rec_sub_inst,
                         REQ_SR_RESET_KEY: reset_sr,
                         IS_RECURSIVE: is_recursive_lbl,
                         RECURSION_CNTR_SHIFT_KEY: recursion_cntr_l_shift}})
            total_num_of_lables += 1

        # add the function tlr recursion lbl, if it exists
        res_json[func_name][RECURSION_TLR_LBL_KEY] = func_node.recursion_tlr_lbl
        # add the recursion tlr mov instructions, if is ever needed
        recursion_cntr_l_shift = ARCH_REGISTER_SIZE - MAX_RECURSION_BITS
        rec_tlr_inst = get_rec_tlr_mov_shift_inst(recursion_cntr_l_shift)
        res_json[func_name][MOV_REC_TLR_INST_KEY] = rec_tlr_inst

        # add inflags
        for inflag, inflag_obj in func_node.in_flags_dict.items():
            ret_label = inflag_obj[LABEL]
            lookup_inst = get_b_inst(ret_label)
            res_json[func_name][INFLAGS].update({int(inflag): lookup_inst})
            total_num_flag_ids += 1
            # update the max_func_inflag
            if int(inflag) > max_func_inflag:
                max_func_inflag = int(inflag)

        # add tlr's first relative jump sequence in case of segmentation
        segment_size = get_sr_enc_segment_size(func_node.sr_shift)
        mov1_inst = get_tlr_mov1_inst(func_node.sr_shift)
        mov2_inst = get_tlr_mov2_inst(SHIFT_SIZE)
        res_json[func_name][RET_INSTS].update({MOV1_INST_KEY: mov1_inst,
                                               MOV2_INST_KEY: mov2_inst})

        # write the max_func_inflag of the function
        res_json[func_name][MAX_INFLAG_KEY] = max_func_inflag

        '''
        The below are fields to check if there is any recursion or segmentation
        in the application. If neither occur then we can
        optimize the TLR instructions.
        '''
        if func_node.sr_shift > 0:
            res_json[IS_SHIFTED] = True
        if func_node.recursive_func or func_node.recursive_path:
            res_json[IS_RECURSIVE] = True

        # collect the maximum shift in the application
        if func_node.sr_shift > max_shift:
            max_shift = func_node.sr_shift

        # check if function is root without callees (i.e., singular), this
        # allows as not to instrument it safely
        if func_node.root_func and len(func_node.callees) == 0:
            res_json[func_name][IS_SINGULAR] = True
        else:
            res_json[func_name][IS_SINGULAR] = False

        # set up the exit lable and exit branch instructions
        func_exit_lbl = func_name + "_EXIT"
        func_exit_b_inst = get_b_inst(func_exit_lbl)
        func_exit_lbl_llvm = func_exit_lbl + ":\n"
        res_json[func_name][EXIT_LBL_KEY] = func_exit_lbl_llvm
        res_json[func_name][EXIT_BRANCH] = func_exit_b_inst
        res_json[func_name][EXIT_SYM_KEY] = func_exit_lbl

        # set up start label and tempoline jump
        func_start_lbl = func_name + "_START"
        func_trampoline_b_inst = get_b_inst(func_start_lbl)
        func_start_lbl_llvm =  func_start_lbl + ":\n"
        res_json[func_name][START_LBL_KEY] = func_start_lbl_llvm
        res_json[func_name][TRAMPOLINE_INST_KEY] = func_trampoline_b_inst

        # write if a function is eh_context
        res_json[func_name][IS_EH_CONTEXT] = func_node.eh_context

    # write the initial value of SR and the size of recursion counter
    initial_sr_val = get_initial_sr_value(SHIFT_SIZE, max_shift)
    recursion_cntr_bits = ARCH_REGISTER_SIZE - (max_shift + SHIFT_SIZE)
    # [rai-debug]
    while recursion_cntr_bits < 0:
        recursion_cntr_bits += ARCH_REGISTER_SIZE
    print("[rai-debug]: ARCH_REGISTER_SIZE: %d, max_shift: %d, SHIFT_SIZE: %d, "
          "recursion_cntr_bits = %d"
          % (ARCH_REGISTER_SIZE, max_shift, SHIFT_SIZE, recursion_cntr_bits))

    if recursion_cntr_bits != MAX_RECURSION_BITS:
        print("[-] ERROR: recursion_cntr_bits (%d) != MAX_RECURSION_BITS (%d)"
              % (recursion_cntr_bits, MAX_RECURSION_BITS))
        sys.exit(1)
    # end of rai debug

    res_json[RECURSION_SIZE_KEY] = recursion_cntr_bits
    res_json[INITIAL_SR_KEY] = initial_sr_val
    # write the maximum shift in the application
    res_json[MAX_SR_SHIFT_KEY] = max_shift

    # write the results to a file
    with open(res_file, 'w') as res_fd:
        json.dump(res_json, res_fd, sort_keys=True, indent=4,
                  ensure_ascii=False)

    std_lib_copy = app_path + "/" + "STD_LIB.json"
    with open(std_lib_copy, 'w') as stdlib_cp_fd:
        json.dump(json_dict, stdlib_cp_fd, sort_keys=True, indent=4,
                  ensure_ascii=False)

    extlib_opt_list_copy = app_path + "/" + "EXT_LIB_OPT_LIST.json"
    with open(extlib_opt_list_copy, 'w') as extlib_opt_cp_fd:
        json.dump(extlib_dict, extlib_opt_cp_fd, sort_keys=True, indent=4,
                  ensure_ascii=False)
    # ExtLibJsonRoot
    print("[+] SUMMARY: TOTAL INFALG IDS = %d, TOTAL LABELS = %d"
          % (total_num_flag_ids, total_num_of_lables))
    print("[+] Lookup table results written to %s" % res_file)
    return


def write_flt_results_file(func_dict, res_path, json_keys_file):
    global APP_NAME
    table_sizes_list = []
    shifted_flt_size_list = []
    num_called_sites_list = []
    # write the results and stats
    for func_name, func_node in func_dict.items():
        # execlude Indirect calls from the calculation
        if INDIRECT_POSTFIX not in func_name:
            table_sizes_list.append(func_node.lookup_table_size)
            shifted_flt_size_list.append(func_node.shifted_flt_size)
            num_called_sites_list.append(func_node.num_called_sites)

    # collect stats
    '''
    (1) encoder evaluation
    '''
    flt_min_name = "$FLT_{Min}$"
    urai_flt_size_name = "$FLT_{\\toolname}$"
    segment_size_name = "SR Segment\nSize (bits)"
    min_name = "Min."
    median_name = "Median"
    max_name = "Max."
    ave_name = "Ave."
    no_segmentation_str = "Without Segmentation"
    segmented_flt_str = "Segmeneted"
    reduction_name = "Reduction"
    num_equi_classes_name = "# of ECs"
    quan_sec_name = "Quantitative Security" # EC/LC
    app_flt_min = np.max(num_called_sites_list)
    min_rai_flt_size = np.min(shifted_flt_size_list)
    encoder_eval = OrderedDict()
    encoder_eval[CG_NODE_KEY] = NUM_CG_NODES
    encoder_eval[CG_EDGES_KEY] = NUM_CG_EDGES
    encoder_eval[flt_min_name] = app_flt_min
    encoder_eval[urai_flt_size_name] = MAX_FLT_SIZE
    encoder_eval[segment_size_name] = SHIFT_SIZE

    encoder_df = pd.DataFrame(encoder_eval, index=[APP_NAME])
    # write the results to csv file
    encoder_results_file = res_path + "/" + ENCODER_RES_FILE + CSV_EXT
    encoder_df.to_csv(encoder_results_file)

    '''
    (2) Segmentation reduction evaluation
    '''
    segmentation_dict = OrderedDict()
    segmentation_dict[no_segmentation_str] = {}
    segmentation_dict[segmented_flt_str] = {}
    # fill non-segmentation stats
    segmentation_dict[no_segmentation_str][min_name] = np.min(table_sizes_list)
    segmentation_dict[no_segmentation_str][median_name] = \
        int(round(np.median(table_sizes_list)))
    segmentation_dict[no_segmentation_str][max_name] = np.max(table_sizes_list)
    segmentation_dict[no_segmentation_str][ave_name] = \
        int(round(np.mean(table_sizes_list)))
    # fill segmeneted-flt stats
    segmentation_dict[segmented_flt_str][min_name] = \
        np.min(shifted_flt_size_list)
    segmentation_dict[segmented_flt_str][median_name] = \
        int(round(np.median(shifted_flt_size_list)))
    segmentation_dict[segmented_flt_str][max_name] = \
        np.max(shifted_flt_size_list)
    segmentation_dict[segmented_flt_str][ave_name] = \
        int(round(np.mean(shifted_flt_size_list)))

    reduction_val = 100 * (1 - (round(np.mean(shifted_flt_size_list)) /
                                round(np.mean(table_sizes_list))))

    segmentation_dict[reduction_name] = str(reduction_val) + str("%")

    # write segmentation results
    segmentation_res_file = res_path + "/" + SEGMENTATION_EVAL + JSON_EXT
    with open(segmentation_res_file, 'w') as fd:
        json.dump(segmentation_dict, fd, sort_keys=True, indent=4,
                  ensure_ascii=False)

    '''
    (3) FLT efficiency results
    '''
    flt_eff_list = []
    flt_eval = OrderedDict()
    # open json fk/fid file to get MAX_INFLAG_KEY for each function
    with open(json_keys_file) as fd:
        json_fk_fid = json.load(fd)
        for func_name, func_node in func_dict.items():
            if INDIRECT_POSTFIX not in func_name and not func_node.root_func:
                max_fid = json_fk_fid[func_name][MAX_INFLAG_KEY]
                # we always start at idx 2, and step size of 4. The +4 is to
                # include max_fid
                tot_fids = 0
                used_fids = 0
                for i in range(2, max_fid+4, 4):
                    tot_fids += 1
                    if str(i) in json_fk_fid[func_name][INFLAGS].keys():
                        used_fids += 1
                flt_eff = 100 * (float(used_fids)/tot_fids)
                flt_eff_list.append(flt_eff)
    # get the stats
    flt_eval[min_name] = np.min(flt_eff_list)
    flt_eval[median_name] = np.median(flt_eff_list)
    flt_eval[max_name] = np.max(flt_eff_list)
    flt_eval[ave_name] = np.mean(flt_eff_list)

    # add dataFrame of the result
    flt_eff_df = pd.DataFrame(flt_eval, index=[APP_NAME])
    # write the results to csv file
    flt_eff_results_file = res_path + "/" + FLT_EFF_EVAL + CSV_EXT
    flt_eff_df.to_csv(flt_eff_results_file)

    '''
    (4) TCFI comparison
    '''
    tcfi_set_size_list = []
    tcfi_eval = OrderedDict()
    for func_name, func_node in func_dict.items():
        # execlude Indirect calls from the calculation
        if INDIRECT_POSTFIX not in func_name and not func_node.root_func:
            # add the number of called sites for the function
            tcfi_set_size_list.append(func_node.num_called_sites)

    # get the stats
    tcfi_eval[min_name] = np.min(tcfi_set_size_list)
    tcfi_eval[median_name] = int(round(np.median(tcfi_set_size_list), 1))
    tcfi_eval[max_name] = np.max(tcfi_set_size_list)
    tcfi_eval[ave_name] = int(round(np.mean(tcfi_set_size_list)))
    #tcfi_eval[num_equi_classes_name] = len(tcfi_set_size_list)
    #tcfi_eval[quan_sec_name] = float(len(tcfi_set_size_list)) / \
    #                           (np.max(tcfi_set_size_list))

    # add dataFrame of the result
    tcfi_eval_df = pd.DataFrame(tcfi_eval, index=[APP_NAME])
    # write the results to csv file
    tcfi_eval_results_file = res_path + "/" + TCFI_EVAL_FILE + CSV_EXT
    tcfi_eval_df.to_csv(tcfi_eval_results_file)



'''
Function level methods (i.e., call stack depth)
'''


def get_cg_max_level(func_dict):
    max_level = 0
    for func_name, func_node in func_dict.items():
        if func_node.max_level > max_level:
            max_level = func_node.max_level

    return max_level


def get_funcs_at_max_level(func_dict, level):
    func_list = []
    for func_name, func_node in func_dict.items():
        if func_node.max_level == level:
            func_list.append(func_node)
    return func_list


def print_funcs_level_info(func_dict):
    print("*" * 80)
    func_level_table_info = Texttable()
    cg_level_table_info = Texttable()
    func_level_table_list = []
    cg_level_table_list = []
    '''
    get call graph levels summary
    '''
    cg_level_table_list.append(['Level', '# funcs'])
    cg_max_level = get_cg_max_level(func_dict)
    debug_func_list = []
    for i in range(cg_max_level+1):
        level_cntr = 0
        for func_name, func_node in func_dict.items():
            if func_node.max_level == i:
                level_cntr += 1
                debug_func_list.append(func_name)
        # updated the cg_level_table_list with the number of functions
        cg_level_table_list.append([str(i), str(level_cntr)])
    # update the table
    cg_level_table_info.add_rows(cg_level_table_list)

    # verify the result is correct
    tot_num_funcs = 0
    for i in range(len(cg_level_table_list)):
        if i != 0:
            tot_num_funcs += int(cg_level_table_list[i][1])

    if tot_num_funcs != len(func_dict):
        print("[-] ERROR: @print_funcs_level_info,[cg_max_level = %d] "
              "tot_num_funcs [%d] != len(FUNC_DICT) [%d]." % (cg_max_level,
                                                              tot_num_funcs,
                                                              len(func_dict)))
        for func_name, func_node in func_dict.items():
            if func_name not in debug_func_list:
                print("------------------------------")
                print("MISSING: ", func_name)
                print("[levels]: %s" % func_node.level_list)
        sys.exit(0)
    '''
    get func level summary
    '''
    func_level_table_list.append(['Function', 'Min. Level', 'Level list'])
    # print the results and stats
    for func_name, func_node in func_dict.items():
        func_level_table_list.append([str(func_name),
                                 str(func_node.min_level),
                                 str(func_node.level_list)])

    func_level_table_info.add_rows(func_level_table_list)

    print("CALL GRAPH LEVELS SUMMARY")
    print("MAX_LEVEL: %d, # OF FUNCS: %d, len(func_dict)= %d"
          % (cg_max_level, tot_num_funcs, len(func_dict)))
    print(cg_level_table_info.draw())
    print(" ")
    print(func_level_table_info.draw())
    print("*"*80)
    print("\n")


'''
Automated re-configuration function.
'''


def get_possible_flt_list(max_cs, json_cg):


    # get the possible flt sizes
    all_flt_list = [1 << i for i in range(int(math.log(MAX_ARCH_FLT, 2)+1))]
    flt_list = []
    # {flt_size: inverse memory overhead}
    flt_eff_dict = OrderedDict()
    direct_flt_eff_dict = OrderedDict()
    shifted_flt_eff_dict = OrderedDict()
    for flt_size in all_flt_list:
        if flt_size >= max_cs:
            flt_list.append(flt_size)

    '''
    calculate the initial lookup table for all
    '''
    stdout_backup = sys.stdout
    with open(DEBUG_FILE, 'w') as debug_fd:
        sys.stdout = debug_fd

        while flt_list:
            reconfig_max_flt(flt_list)
            flt_size = flt_list[0]
            func_dict = OrderedDict()
            cg = nx.DiGraph()
            # initialize FuncNode object for each function
            cg, func_dict = init_func_nodes_list(json_cg, cg, func_dict)
            # add callers/callees
            cg, func_dict, mx_cs = gen_callers_callees(json_cg, cg, func_dict)

            func_dict, shift_flt_list, shift_list,\
                num_called_sites_list = calc_lookup_tables_size(func_dict)

            max_shift = np.max(shift_list)
            # get efficiency and add the result to the dictionary
            sum_cs = float(np.sum(num_called_sites_list))
            sum_shifted = np.sum(shift_flt_list)
            eff = sum_cs/sum_shifted

            # verify the solution is applicable to the architecture
            if (max_shift + SHIFT_SIZE) <= MAX_STATE_REGISTER_BITS:
                if max_shift == 0:
                    direct_flt_eff_dict[flt_size] = eff
                else:
                    shifted_flt_eff_dict[flt_size] = eff
                flt_eff_dict[flt_size] = eff
                print("[+] FLT[%d] EFF: [%d/%d] = %f, MAX_SHIFT = %d,"
                      " SHIFT_SIZE = %d"
                      % (flt_size, sum_cs, sum_shifted,
                         flt_eff_dict[flt_size], max_shift, SHIFT_SIZE))
            else:
                print("[-] FLT[%d] Not solvable: max_shift [%d],"
                      " SHIFT_SIZE [%d] > "
                      "MAX_STATE_REGISTER_BITS [%d], expected_eff = %f"
                      % (flt_size, max_shift, SHIFT_SIZE, MAX_STATE_REGISTER_BITS, eff))
            print("=-"*20)
            # delete the current value from the list
            del flt_list[0]

        sorted_flt_options = []
        '''
        removed this to choose FLT with best EFF, it will also be the faster
        to compile
        # first sort non-shifted options
        while direct_flt_eff_dict:
            max_val = max(direct_flt_eff_dict, key=flt_eff_dict.get)
            sorted_flt_options.append(max_val)
            del direct_flt_eff_dict[max_val]
        # now sort the shifted options
        while shifted_flt_eff_dict:
            max_val = max(shifted_flt_eff_dict, key=flt_eff_dict.get)
            sorted_flt_options.append(max_val)
            del shifted_flt_eff_dict[max_val]
        '''
        # choose the best efficiency regardless of shifting
        while flt_eff_dict:
            max_val = max(flt_eff_dict, key=flt_eff_dict.get)
            sorted_flt_options.append(max_val)
            del flt_eff_dict[max_val]

        print("[+] SORTED_FLT_SIZES: %s" % sorted_flt_options)
        print("="*80)
    sys.stdout = stdout_backup
    if ENABLE_DBG_POINT:
        debug_point = raw_input("[+] Initial FLT efficiency results generated. "
                                "Press Enter to continue...")
    return sorted_flt_options


def reconfig_max_flt(flt_sizes_list):
    global MAX_FLT_SIZE, SHIFT_SIZE, VALID_KEY_RANGE

    # if there are other options, update the configuration and return
    # if not, exit and print error message
    if flt_sizes_list:
        '''
        Maximum possible value for the Function Lookup Table (FLT). The is just an
        initialization value
        '''
        MAX_FLT_SIZE = flt_sizes_list[0]
        # fixed shift step size, (+2)  is for step size (2^2) = 4
        SHIFT_SIZE = int(math.ceil(math.log(MAX_FLT_SIZE, 2)) + 2)

        '''
        In order to ensure the values of flag IDs satisfy the VALID_FLAG_ID_RANGE
        requirement, we need to have the keys at multiple of 4s.
        '''
        VALID_KEY_RANGE = range(0, pow(2, SHIFT_SIZE), 4)
        return True
    else:
        return False


'''
function to re-configure max recursions counter bits
'''


def get_max_recursion_bits(func_dict, shift_size):
    max_shift = 0
    for func_name, func_node in func_dict.items():
        if func_node.sr_shift > max_shift:
            max_shift = func_node.sr_shift
    recursion_cntr_bits = ARCH_REGISTER_SIZE - (max_shift + shift_size)
    # [rai-debug]
    while recursion_cntr_bits < 0:
        recursion_cntr_bits += ARCH_REGISTER_SIZE
    return recursion_cntr_bits


def is_unsupported_lib_func(func_name, dict):
    if func_name in dict.keys():
        return True
    return False

if __name__ == "__main__":
    arg_parser = ArgumentParser()
    arg_parser.add_argument('-f', '--filename', dest='json_filename', type=str,
                        help="The name of the json file to analyze", required=True)
    arg_parser.add_argument('-a', '--appname', dest='app_name', type=str,
                        help="The name of the appliction to compile", required=False)
    arg_parser.add_argument('-s','--stats',metavar="FILE",
                        help='analyze the json file of the app and print its '
                             'stats', required=False)
    arg_parser.add_argument('-t', dest='test', default=False,
                            action='store_true',
                            help='Flag used for quick testing during '
                                 'development')
    arg_parser.add_argument('-opt', '--optlevel', dest='opt_level', type=int,
                        help="Compilation Optmization level", required=False)

    arg_parser.add_argument('-nodebug', dest='no_debug', default=False,
                            action='store_true',
                            help='Flag used to enable stopping at debug points'
                                 ' in the application (e.g., raw_input)')
    args = arg_parser.parse_args()

    if args.app_name:
        APP_NAME = args.app_name

    if args.opt_level == 0:
        UNIFY_TCFI_SETS = False

    # check if nodebug is enabled
    if args.no_debug:
        ENABLE_DBG_POINT = False

    if args.test:
        print("Test flag for quick debugging...")


    else:

        # graph object to draw the call graph
        CG = nx.DiGraph()
        json_filename = args.json_filename.rsplit(JSON_EXT)[0]
        res_path = json_filename.rsplit('/', 1)[0]
        log_file = res_path + "/" + LOGFILE_NAME
        res_filename = res_path + "/" + LOOKUP_TABLE_RES_FILE + JSON_EXT
        ENCODER_LOG = res_path + "/" + ENCODER_LOG
        # [rai-debug]/FIXME
        TCFI_SETS_TEMP_PATH = res_path
        #-----------------
        # open json file
        with open(json_filename + JSON_EXT) as fd:
            json_call_graph = json.load(fd)
            print("="*80)
            '''
            Plot the call graph
            '''
            # initialize FuncNode object for each function
            CG, FUNC_DICT = init_func_nodes_list(json_call_graph, CG, FUNC_DICT)
            # add callers/callees
            CG, FUNC_DICT, max_call_sites = gen_callers_callees(json_call_graph,
                                                                CG, FUNC_DICT)

            # draw the call graph
            p = nx.drawing.nx_pydot.to_pydot(CG)
            nx.drawing.nx_pydot.write_dot(CG, json_filename + '.dot' )
            dot_to_pdf_cmd =  "dot -Tpdf " + json_filename +".dot  -o " + \
                              json_filename + "--callgraph.pdf"
            return_val = subprocess.call(dot_to_pdf_cmd, shell=True)
            if return_val:
                print("[-] ERROR: could not convert dot file to pdf.")

            print("[+] Calculating FLT sizes....")

            # get possible flts
            possible_flts = get_possible_flt_list(max_call_sites,
                                                  json_call_graph)
            if not reconfig_max_flt(possible_flts):
                print("[-] ERROR: No possible FLT was found")
                sys.exit(0)

            while possible_flts:
                # make sure we have the initial FUNC_DICT
                FUNC_DICT = OrderedDict()
                # graph object to draw the call graph
                CG = nx.DiGraph()
                # initialize FuncNode object for each function
                CG, FUNC_DICT = init_func_nodes_list(json_call_graph, CG,
                                                     FUNC_DICT)
                # add callers/callees
                CG, FUNC_DICT, max_call_sites = gen_callers_callees(
                    json_call_graph,
                    CG, FUNC_DICT)
                # save stdout
                stdout_backup = sys.stdout
                with open(log_file, 'w') as log_fd:
                    sys.stdout = log_fd
                    FUNC_DICT, shifted_flt_list,\
                    shifts_list, num_cs_list = calc_lookup_tables_size(FUNC_DICT)
                    print_funcs_level_info(FUNC_DICT)
                sys.stdout = stdout_backup

                if ENABLE_DBG_POINT:
                    var = raw_input("[rai-Debug] Done generating initail FLT. "
                                    "Press Enter to continue...")

                # re-calculate the max recursion bits counter
                MAX_RECURSION_BITS = get_max_recursion_bits(FUNC_DICT,
                                                            SHIFT_SIZE)

                # generate keys/flag IDs
                #FUNC_DICT = gen_callgraph_key_flags(FUNC_DICT, RELATIVE_JUMP)
                FUNC_DICT = bfs_cg_gen_fk_fid(FUNC_DICT, RELATIVE_JUMP)
                '''
                if we found a solution, write the results.
                '''
                if FUNC_DICT:
                    '''
                    Verify no error occured. If so, try another FLT
                    '''
                    if FUNC_DICT is None:
                        print("[-] ERROR: MAX_FLT_SIZE = %d not satisfiable." % MAX_FLT_SIZE)

                    stdout_backup = sys.stdout
                    with open(log_file, 'a') as log_fd:
                        sys.stdout = log_fd
                        for name, func in FUNC_DICT.items():
                            print(name)
                            func.print_info()
                    sys.stdout = stdout_backup

                    # write the results to the results file
                    export_lookup_table_results(FUNC_DICT, res_filename, res_path)
                    # write encoder stat results
                    write_flt_results_file(FUNC_DICT, res_path, res_filename)
                    print("=" * 80)
                    break
                else:
                    '''
                    otherwise, reconfigure and try next FLT option
                    '''
                    print("[-] ERROR: MAX_FLT_SIZE = %d not satisfiable."
                          % MAX_FLT_SIZE)
                    # delete the first index as it was already used
                    del possible_flts[0]
                    if not reconfig_max_flt(possible_flts):
                        print("[-] ERROR: all FLT options were tried without"
                              " reaching a solution")




