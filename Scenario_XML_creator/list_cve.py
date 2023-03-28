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

def read_vulnerability_metadata(filepath, namespace):
    """Reads the XML metadata from a SecGen file

    """

    module_list = []
    count = 0

    for file in glob.glob(filepath, recursive=True):
        # TODO: expand tags as needed
        metadata = {
            "name": "",
            "filepath": "",
            "description": "",
            "type": [],
            "cve": "",
            "cvss base score": "",
            "cvss vector": "",
            "difficulty": ""
        }

        metadata["filepath"] = file
        count = count + 1
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

                if root.find(namespace + XML_TAGS.CVSS_BASE_SCORE) is not None:
                    metadata["cvss base score"] = root.find(namespace + XML_TAGS.CVSS_BASE_SCORE).text

                if root.find(namespace + XML_TAGS.CVSS_VECTOR) is not None:
                    metadata["cvss vector"] = root.find(namespace + XML_TAGS.CVSS_VECTOR).text

                # Get module type
                for md in root.iter(namespace + XML_TAGS.TYPE):
                    metadata["type"].append(md.text)

            except Exception as e:
                print("Something went wrong! " + metadata["name"])
                print(e)

        module_list.append(metadata)

    module_metadata = {"modules": module_list}
    print(f"number of vulnerability modules: {count}")
    return module_list


def list_mappings(cve_list):
    with open('Att&ckToCveMappings.csv', newline='') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')

        for cve in cve_list:
            print(cve)
            for row in csv_reader:

                print(row)
                if cve in row:
                    print(row)
    return None


def map_cve_to_mitre(cve):
    with open('Att&ckToCveMappings.csv', newline='') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')

        for row in csv_reader:
            if cve in row:
                print(row)

    csv_file.close()
    return None


def main():
    vulnerability_metadata = read_vulnerability_metadata(DIRECTORY.VULNERABILITY, NAMESPACE.VULNERABILITY)

    cve_list = []
    type_list = []
    cvss_vector_list = []
    cvss_score_list = []

    for vulnerability in vulnerability_metadata:

        if vulnerability["cve"] not in cve_list:
            if vulnerability["cve"] != "":
                cve_list.append(vulnerability["cve"])

        if vulnerability["cvss vector"] not in cvss_vector_list:
            if vulnerability["cvss vector"] != "":
                cvss_vector_list.append(vulnerability["cvss vector"])

        if vulnerability["cvss base score"] not in cve_list:
            if vulnerability["cvss base score"] != "":
                cvss_score_list.append(vulnerability["cvss base score"])

        for v_type in vulnerability["type"]:
            if v_type not in type_list:
                type_list.append(v_type)

    print(f"number of CVEs: {len(cve_list)}")
    print(f"number of types: {len(type_list)}")
    print(cve_list)
    print(type_list)
    print(cvss_vector_list)
    print(cvss_score_list)
    print("--------------")
    for cve in cve_list:
        map_cve_to_mitre(cve)


if __name__ == "__main__":
    main()
