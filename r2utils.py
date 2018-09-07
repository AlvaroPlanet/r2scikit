#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import r2pipe
import re
import os
import logging

def get_functions_name(instance_r2, reg_exr, neg_reg_exr):
    
    bin_name = os.path.basename(os.path.normpath(instance_r2.cmdj('ij')['core']['file']))
    
    logging.info('{Radare2:  getting function list} Binary: %s', bin_name)
    list_functions = instance_r2.cmdj('aflj')
    
    p = re.compile(reg_exr)
    neg_p = re.compile(neg_reg_exr)
#    list_functions_filtered = [item['name'] for item in list_functions if p.match(item['name'])]
    
    list_functions_filtered = []
    if list_functions is not None:
        for item in list_functions:
            if p.match(item['name']):
                if not neg_p.match(item['name']):
                    function = {'name':'', 'size':''}
                    function['name'] = item['name']
                    function['size'] = item['size']
                    list_functions_filtered.append(function)
    
    return list_functions_filtered

def get_function_details(instance_r2, function_name):
    
    bin_name = os.path.basename(os.path.normpath(instance_r2.cmdj('ij')['core']['file']))
    
    #Seek to a function by its name 
    logging.debug('{Radare2: seek to function} %s.%s', bin_name, function_name)
    instance_r2.cmd('sf ' + function_name)
    
    logging.debug('{Radare2: disassembling function} %s.%s', bin_name, function_name)
    
    list_instructions = instance_r2.cmdj('pdfj')
    
    result = {'name':function_name, 'r2_size':list_instructions['size'], 'real_size': 0, 'instructions_len':'', 'instructions': []}
    
    for item in list_instructions['ops']:
        opcode = {'opcode':'', 'size':''}
        
        opcode_key = item.get('opcode')
        
        #Check if exists the key 'opcode' in the dict
        if opcode_key not in ['', None]:
            opcode['opcode'] = str.split(opcode_key)[0]
            opcode['size'] = item['size']
            result['real_size'] += item['size']
        else:
            opcode['opcode'] = 'invalid'
            opcode['size'] = 'invalid'
            logging.warning('There is not key opcode. Function:%s.%s', bin_name, function_name)
            return None
            
        result['instructions'].append(opcode)
    
    result['instructions_len'] = len(result['instructions'])    
    
    if result['real_size'] is not result['r2_size']:
        logging.debug('{Radare2: checking function size} The radare size and the real size do not match %s.%s', bin_name, function_name)
    
    return result

def get_binaries_details(path_to_binary=''):
    
    # open without arguments only for #!pipe
    r2 = r2pipe.open(path_to_binary)
    
    if path_to_binary is '':
        binary = os.path.basename(os.path.normpath(r2.cmdj('ij')['core']['file']))
    else:
        binary = os.path.basename(os.path.normpath(path_to_binary))

    logging.info('{Processing binary} Binary:%s', binary)

#   Checking if the architecture is x86
    arch = r2.cmd('e asm.arch')
    if arch not in ('x86'):
        logging.warning('{The architecture is not x86} Binary:%s', binary)
    
    logging.info('BEGIN {Radare2: analyzing} Binary:%s', binary)
    r2.cmd('aa;aac;aar;aan')
    logging.info('FINISH {Radare2: analyzing} Binary:%s', binary)

    name_functions = get_functions_name(r2, '^(fcn.*|entry0|int.*|sub.*|sym.*)', '^(sym.imp.*)')
    
    result_binary = {'name':binary, 'functions_with_errors': 0, 'functions_len': 0, 'functions': []}
    
    for index_functions, item in enumerate(name_functions, start=1):
        logging.debug('BEGIN {Extracting opcodes} Binary:%s Function:%s [%s - %s]', binary, item['name'], index_functions, len(name_functions))
        
        function_details = get_function_details(r2, item['name'])
        
        if function_details is not None:
            result_binary['functions'].append(function_details)
            logging.debug('FINISH {Extracting opcodes} APPENDED Binary:%s Function:%s [%s - %s]', binary, item['name'], index_functions, len(name_functions))

        else:
            result_binary['functions_with_errors'] += 1
            logging.debug('FINISH {Extracting opcodes} NOT APPENDED Binary:%s Function:%s [%s - %s]', binary, item['name'], index_functions, len(name_functions))

    
    result_binary['functions_len'] = len(result_binary['functions'])

    r2.quit()
    
    logging.info('FINISH {Processing binary} Binary:%s', binary)

    return result_binary