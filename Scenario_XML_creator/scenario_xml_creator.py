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

# Define constants


# MODULE_PATH = "./"
# BASE_MODULE_PATH = "modules/bases/"
# VULNERABILITY_MODULE_PATH = "modules/vulnerabilities/"
# SERVICE_MODULE_PATH = "modules/services/"
# UTILITY_MODULE_PATH = "modules/utilities/"
# NETWORK_MODULE_PATH = "modules/networks/"


def parse_args():
    """
    https://www.annasyme.com/docs/python_structure.html
    Retrieves any arguments passed to it through the CLI
    """

    # Define CLI arguments and options
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument(
        "-b",
        "--base",
        help="Select the Operating System of the ")

    arg_parser.add_argument("-nv",
                            "--num-vulnerabilities",
                            type=int,
                            help="set number of vulnerabilities")

    arg_parser.add_argument("-ns",
                            "--num-service",
                            type=int,
                            help="set number of services")

    arg_parser.add_argument("-nu",
                            "--num-utilitiy",
                            type=int,
                            help="set number of utilities")

    arg_parser.add_argument("-nn",
                            "--num-network",
                            type=int,
                            help="set number of networks")

    arg_parser.add_argument("-g",
                            "--generate",
                            type=int,
                            help="set number of scenarios to generate")

    arg_parser.add_argument("-d",
                            "--difficulty",
                            help="select a difficulty level [low/medium/hard]")

    # Retrieve values from CLI
    args = arg_parser.parse_args()
    return args


def read_module_types(filepath, namespace):
    """Reads value of a <type> tag from a SecGen_metadata.xml file.

    Args:
        filepath: The directory regex to search for the modules.
        namespace: The SecGen namespace that the file must be compared to.

    Returns:
        The list of unique module types.
    """
    unique_types = []

    for file in glob.glob(filepath, recursive=True):

        with open(file, encoding="utf-8-sig") as module:
            try:
                tree = ET.parse(module)
                root = tree.getroot()

                for type_metadata in root.iter(namespace):
                    # some modules have multiple types

                    type_text = type_metadata.text  # get the type

                    if type_text not in unique_types:
                        unique_types.append(type_text)
            except Exception as e:
                print("Something went wrong!")
                print(e)

    return unique_types


# def read_module_metadata(filepath, namespace):
#     """Reads the XML metadata from a SecGen file

#     """

#     module_list = []

#     for file in glob.glob(filepath, recursive=True):

#         # TODO: expand tags as needed
#         metadata = {
#             "name": "",
#             "filepath": "",
#             "description": "",
#             "type": [],
#             "tags": []
#         }

#         metadata["filepath"] = file

#         with open(file, encoding="utf-8-sig") as module:
#             try:
#                 tree = ET.parse(module)
#                 root = tree.getroot()

#                 # Get module name and description
#                 metadata["name"] = root.find(namespace + XML_TAGS.NAME).text
#                 metadata["description"] = root.find(namespace + XML_TAGS.DESCRIPTION).text

#                 # Get module type
#                 for md in root.iter(namespace + XML_TAGS.TYPE):
#                     metadata["type"].append(md.text)

#             except Exception as e:
#                 print("Something went wrong!")
#                 print(e)

#         module_list.append(metadata)

#     module_metadata = {"modules": module_list}
#     return module_list

def read_vulnerability_metadata(filepath, namespace):
    """Reads the XML metadata from a SecGen file

    """

    module_list = []
    print("hi")
    print(filepath)

    for file in glob.glob(filepath, recursive=True):

        # TODO: expand tags as needed
        metadata = {
            "name": "",
            "filepath": "",
            "description": "",
            "type": [],
            "cve": "",
            "difficulty": ""
        }

        metadata["filepath"] = file
        print("hi")

        with open(file, encoding="utf-8-sig") as module:
            try:
                tree = ET.parse(module)
                root = tree.getroot()

                # Get module name and description
                metadata["name"] = root.find(namespace + XML_TAGS.NAME).text
                metadata["description"] = root.find(namespace + XML_TAGS.DESCRIPTION).text

                if root.find(namespace + XML_TAGS.CVE) is not None:
                    metadata["cve"] = root.find(namespace + XML_TAGS.CVE).text

                if root.find(namespace + XML_TAGS.DIFFICULTY) is not None:
                    metadata["difficulty"] = root.find(namespace + XML_TAGS.DIFFICULTY).text

                # Get module type
                for md in root.iter(namespace + XML_TAGS.TYPE):
                    metadata["type"].append(md.text)

            except Exception as e:
                print("Something went wrong! " + metadata["name"])
                print(e)

        module_list.append(metadata)

        print(metadata["name"] + ", " + metadata["description"] + ", " + metadata["cve"] + ", " + metadata["difficulty"] + ", ".join(metadata["type"]))

    module_metadata = {"modules": module_list}
    return module_list


def list_mappings(vulnerability_list):
    print(vulnerability_list)
    with open('Att&ckToCveMappings.csv') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        line_count = 0
        for row in csv_reader:
            if line_count == 0:
                print(f'Column names are {", ".join(row)}')
                line_count += 1
            else:
                for vulnerability in vulnerability_list:
                    cve = vulnerability["cve"]
                    print(cve)
                    print('hi')

                # print(f'\t{row[0]} works in the {row[1]} department, and was born in {row[2]}.')
                line_count += 1

    print(f'Processed {line_count} lines.')
    # print("hi")

    # csv_file = csv.reader(open('Att&ckToCveMappings.csv', "r"), delimiter=',')


    # for v in vulnerability_list:
    #     cve = v["cve"]
    #     print("hi")

    #     for row in csv_file:
    #         print(row)
    #         if cve == row[0]:
    #             print(row)

    return None


def assign_tags(module_types):

    tags = []
    print("HI")
    # Load JSON file
    with open(DOMAIN_JSON) as f:
        domain_json = json.load(f)

    for mt in module_types:
        print(mt)
        paths = list(get_tags(domain_json, mt))
        for path in paths:
            print(path)

    return tags


def get_tags(data, value, path=[]):
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, (dict, list)):
                yield from get_tags(v, value, path + [k])
            elif v == value:
                yield path + [k]
    elif isinstance(data, list):
        for i, v in enumerate(data):
            if isinstance(v, (dict, list)):
                yield from get_tags(v, value, path + [i])
            elif v == value:
                yield path + [i]


def find(element, JSON, path, all_paths):
    if element in JSON:
        path = path + element + ' = ' + JSON[element].encode('utf-8')
        print(path)
        all_paths.append(path)
    for key in JSON:
        if isinstance(JSON[key], dict):
            find(element, JSON[key], path + key + '.', all_paths)


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
    list_vulnerability = list_modules(DIRECTORY.VULNERABILITY)
    list_service = list_modules(DIRECTORY.SERVICE)
    list_utility = list_modules(DIRECTORY.UTILITY)
    list_network = list_modules(DIRECTORY.NETWORK)


def create_custom_scenario():

    return None


def create_specialised_scenario():
    os.system('cls||clear')
    return None


def main():
    os.system('cls||clear')
    print(bcolors.HEADER + "***************************" + bcolors.ENDC)
    print(bcolors.HEADER + "~SecGen Scenario Generator~" + bcolors.ENDC)
    print(bcolors.HEADER + "by Harmon Transfield" + bcolors.ENDC)
    print(bcolors.HEADER + "***************************" + bcolors.ENDC)
    print("\n")

    #################################
    # Get the value of any passed args
    #################################
    args = parse_args()
    # num_vulnerabilities = args.vulnerability
    # num_services = args.service
    # num_utilities = args.utilitiy
    # num_networks = args.network
    # num_scenarios = args.generate
    #################################

    #################################
    # Get a list of each module type
    ################################
    unique_base_types = {
        'bases': read_module_types(
            DIRECTORY.BASE,
            NAMESPACE.BASE.join('type')
        )
    }
    unique_vulnerability_types = {
        'vulnerabilities': read_module_types(
            DIRECTORY.VULNERABILITY,
            NAMESPACE.VULNERABILITY.join('type')
        )
    }
    unique_service_types = {
        'services': read_module_types(
            DIRECTORY.SERVICE,
            NAMESPACE.SERVIVE.join('type')
        )
    }
    unique_utility_types = {
        'utilities': read_module_types(
            DIRECTORY.UTILITY,
            NAMESPACE.UTILITY.join('type')
        )
    }
    #################################

    options = ["random", "custom", "specialised"]
    user_input = ""
    input_message = "What type of scenario do you want to create?\n"

    # base_metadata = read_module_metadata(DIRECTORY.BASE, NAMESPACE.BASE)
    vulnerability_metadata = read_vulnerability_metadata(DIRECTORY.VULNERABILITY, NAMESPACE.VULNERABILITY)
    print(vulnerability_metadata)
    #list_mappings(vulnerability_metadata)

    # for index, item in enumerate(options):
    #     input_message += f'{index+1}) {item}\n'

    # input_message += 'Your choice: '

    # while user_input.lower() not in options:
    #     user_input = input(input_message)

    # scenario_filename = ""

    # if user_input.lower() == options[0]:
    #     scenario_filename = create_random_scenario()
    # elif user_input.lower() == options[1]:
    #     scenario_filename = create_custom_scenario()
    # elif user_input.lower() == options[2]:
    #     scenario_filename = create_specialised_scenario()

    # os.system("ruby secgen.rb --scenario " + filename + " run")


# TODO: Read metadata from schema files


# Search recursively for secgen_metadata


# for s in glob.glob('./modules/services/**/secgen_metadata.xml', recursive=True):
#     f.write("\nSERVICES:\n")
#     f.write("------------------------------------\n")
#     f.write('\n'.join(str(s)))

# for u in glob.glob('./modules/utilities/**/secgen_metadata.xml', recursive=True):
#     f.write("\nUTILITIES\n")
#     f.write("------------------------------------\n")
#     f.write('\n'.join(str(u)))

# for n in glob.glob('./modules/networks/**/secgen_metadata.xml', recursive=True):
#     f.write("\nNETWORKS\n")
#     f.write("------------------------------------\n")
#     f.write('\n'.join(str(n)))

# with open("module_path.txt", "w") as f:
#     f.write("BASES:\n")
#     f.write("------------------------------------\n")
#     f.write('\n'.join(str(b) for b in list_base))

#     f.write("\nVULNERABILITIES:\n")
#     f.write("------------------------------------\n")
#     f.write('\n'.join(str(v) for v in list_vulnerability))

#     f.write("\nSERVICES:\n")
#     f.write("------------------------------------\n")
#     f.write('\n'.join(str(s) for s in list_service))

#     f.write("\nUTILITIES\n")
#     f.write("------------------------------------\n")
#     f.write('\n'.join(str(u) for u in list_utility))

#     f.write("\nNETWORKS\n")
#     f.write("------------------------------------\n")
#     f.write('\n'.join(str(n) for n in list_network))


# # Randomly select modules
# random_base = random.choice(list_base).replace('./', '')
# random_vulnerability = random.choice(list_vulnerability).replace('./', '')
# random_service = random.choice(list_service).replace('./', '')
# random_utility = random.choice(list_utility).replace('./', '')
# random_network = random.choice(list_network).replace('./', '')

# # Randomly select modules
# random_base = random.choice(list_base)
# random_vulnerability = random.choice(list_vulnerability)
# random_service = random.choice(list_service)
# random_utility = random.choice(list_utility)
# random_network = random.choice(list_network)

# print(random_base)
# print(random_vulnerability)
# print(random_service)
# print(random_utility)
# print(random_network)

# # Create the XML root element
# scenario = ET.Element("scenario")
# scenario.set("xmlns", "http://www.github/cliffe/SecGen/scenario")
# scenario.set("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
# scenario.set("xsi:schemaLocation", "http://www.github/cliffe/SecGen/scenario")

# system = ET.SubElement(scenario, "system")

# system_name = ET.SubElement(system, "system_name")
# system_name.text = "randomised_scenario"
# base = ET.SubElement(system, "base")
# base.set("module_path", random_base.replace('./', ''))

# # # Some manually defined base attributes for testing
# # base.set("distro", "Debian 9")
# # base.set("type", "server")
# # base.set("p", "./modules/bases/" + random_base)

# if num_vulnerabilities is not None:
#     for i in range(num_vulnerabilities):
#         vulnerability = ET.SubElement(system, "vulnerability")

# if num_services is not None:
#     for i in range(num_services):
#         service = ET.SubElement(system, "service")

# if num_utilities is not None:
#     for i in range(num_utilities):
#         utility = ET.SubElement(system, "utility")

# if num_networks is not None:
#     for i in range(num_networks):
#         network = ET.SubElement(system, "network")
# # generator = ET.SubElement(system, "generator")
# # encoder = ET.SubElement(system, "encoder")
# # Write randomly generated scenario to a .xml file
# timestr = time.strftime("%Y%m%d_%H%M%S")
# filename = "random_scenario" + timestr + ".xml"
# tree = ET.ElementTree(scenario)
# # tree.write(filename, xml_declaration=True)
# # if num_scenarios is None:
# #     os.system("ruby secgen.rb --scenario " + filename + " run")
# # else:
# #     for i in range(num_scenarios):
# #         os.system("ruby secgen.rb --scenario " + filename + " run")
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
