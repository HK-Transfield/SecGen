#!/usr/bin/env python
import argparse
import getopt
import glob
import csv
import json
import os
import random
import shlex
import sys
import time
import xml.etree.ElementTree as ET
from collections import ChainMap
from constants import *

def read_module_metadata(filepath, namespace):
    """Reads the XML metadata from a SecGen file

    """

    module_list = []

    for file in glob.glob(filepath, recursive=True):

        # TODO: expand tags as needed
        metadata = {
            "name": "",
            "filepath": "",
            "description": "",
        }

        names = []

        metadata["filepath"] = file

        with open(file, encoding="utf-8-sig") as module:
            try:
                tree = ET.parse(module)
                root = tree.getroot()

                # Get module name and description
                metadata["name"] = root.find(namespace + XML_TAGS.NAME).text
                metadata["description"] = root.find(namespace + XML_TAGS.DESCRIPTION).text

            except Exception as e:
                print("Something went wrong!")
                print(e)

        module_list.append(metadata)

    module_metadata = {"modules": module_list}
    return module_list



def list_modules(filepath):
    """Gets a list of all modules from a directory.

    Args:
        filepath: The regex for where to search for.

    Returns:
        The list of all module filepaths.
    """

    list_modules = []

    for module in glob.glob(filepath, recursive=True):
        list_modules.append(module.replace('/secgen_metadata.xml', ''))

    return list_modules


def create_random_scenario():
    """Creates a simple scenario template for SecGen to randomise"""

    # Define lists of modules
    list_base = list_modules(DIRECTORY.BASE)
    print(list_base)
    list_vulnerability = list_modules(DIRECTORY.VULNERABILITY)
    list_service = list_modules(DIRECTORY.SERVICE)
    list_utility = list_modules(DIRECTORY.UTILITY)
    list_network = list_modules(DIRECTORY.NETWORK)

def print_name(modules):
    for module in modules:
        print(module["name"])


def main():
    os.system('cls||clear')
    # create_random_scenario()
    bases = read_module_metadata(DIRECTORY.BASE, NAMESPACE.BASE)
    services = read_module_metadata(DIRECTORY.SERVICE, NAMESPACE.SERVICE)
    utilities = read_module_metadata(DIRECTORY.UTILITY, NAMESPACE.UTILITY)

    print_name(utilities)



if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n" + bcolors.FAIL +
              "Closing SecGen scenario generator!" + bcolors.ENDC)
        try:
            sys.exit(130)
        except SystemExit:
            os._exit(130)
