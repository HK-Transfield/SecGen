ROOT_DIR = "../"
#!/usr/bin/env python

# File/directory constants
BASE_DIR = './modules/bases/**/secgen_metadata.xml'
VULNERABILITY_DIR = './modules/vulnerabilities/**/secgen_metadata.xml'
SERVICE_DIR = './modules/services/**/secgen_metadata.xml'
UTILITY_DIR = './modules/utilities/**/secgen_metadata.xml'
NETWORK_DIR = "./modules/networks/**/secgen_metadata.xml"


# Namespace constants
BASE_NAMESPACE = '{http://www.github/cliffe/SecGen/base}'
VULNERABILITY_NAMESPACE = '{http://www.github/cliffe/SecGen/vulnerability}'
SERVIVE_NAMESPACE = '{http://www.github/cliffe/SecGen/service}'
UTILITY_NAMESPACE = '{http://www.github/cliffe/SecGen/utility}'

# JSON file
DOMAIN_JSON = "./json/domains.json"


class XML_TAGS:
    NAME = "name"
    DESCRIPTION = "description"
    TYPE = "type"


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
