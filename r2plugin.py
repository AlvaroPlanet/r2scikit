#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""

    This plugin provides a classification in order to
    detect functions that have been disassembled wrongly,
    such as data in .text section.
    
    The model has been trained with a dataset of x86 binaries
    in PE format, extracted from Windows-7 installer.
    
    Example:
      [0x00000000]> #!pipe python ./r2plugin.py
    
    Example:
      $ r2 -qi r2plugin.py /bin/ls
      
"""

import r2utils

import logging
from imp import reload
import sys
from time import time
import pickle

import texttable as tt

from sklearn.externals import joblib

from pathlib import Path


def size_mb(docs):
    return sum(len(s.encode('utf-8')) for s in docs) / 1e6

if __name__ == '__main__':

    #Configures logging
    reload(logging)
    logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.INFO)
    
    # Load the model
    path_model = Path("model.pkl")
    if path_model.is_file():
        clf = joblib.load(path_model)
    else:
        logging.error('Some error occurred reading the file of the model %s', path_model)
        sys.exit()
        
    path_vector = Path('vocabulary.pickle')
    if path_vector.is_file():
        vectorizer = pickle.load(open(path_vector, "rb"))
    else:
        logging.error('Some error occurred reading the serializated file vector %s', path_vector)
        sys.exit()
    
    #Get binary details
    binary_details = r2utils.get_binaries_details()
    
    pre_features_vector = []
    name_functions = []
    
    for function in binary_details['functions']:
        name_functions.append(function['name'])
        opcodes_sequence = ''
        for instruction in function['instructions']:
            opcodes_sequence += ' '+instruction['opcode']
        pre_features_vector.append(opcodes_sequence)    

    
    data_size_mb = size_mb(pre_features_vector)
    
#   Vectorialization features
    logging.info("Extracting features from the processed binary")
    t0 = time()
    X = vectorizer.transform(pre_features_vector)
    duration = time() - t0
    logging.info("Done in %fs at %0.3fMB/s" % (duration, data_size_mb / duration))
    logging.info("n_samples: %d, n_features: %d" % X.shape)    

#   Get the prediction
    pred = clf.predict(X)
        
#   Print results in a table
    tab = tt.Texttable()
    tab.header(['Function name','Prediction'])
    for row in zip(name_functions, pred.tolist()):
        tab.add_row(row)
    print(tab.draw())