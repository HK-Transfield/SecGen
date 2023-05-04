#!/usr/bin/env python
ROOT_DIR = "../"

"""
Vulnerabilities: ftp, client-side, system, update, container_escape, bind_shell, simple_backdoor, bash, distcc, web_training_platform, webapp, nfs, ^ftp$, http, irc, in_the_wild, webapp_with_db, bruteforceable, www_rand, privilege_escalation, unpatched_kernel, race_condition, desktop_environment, phishing, samba, access_control_misconfiguration, suid_root_viewer_shell, suid_root_editor, access_controls, zip_file, ctf_challenge, programming_challenge, script_challenge, pwnable_binary, reverse_engineering, java, pcap

Services: nfs, storage, ftp, $ftp^, servlet, tomcat, httpd, update, java, http, web_server, database, http_bash, webapp, ircd, log_tool, smb, mail_server, pop3, ntp

Utilities: system, security_settings, mitigations, update, win_debugger, mac, office, audit_tools, configuration_api, networking, xinetd, puppet_import, vm_tools, cli_tools, script_challenge_container, rootkit, userspace_rootkit, forensic_artifact, authentication_configuration, containers, container, docker, chatbot, httpd, log_tool, irc_client, chat_client, build_tools, language, go, java, ruby, python, lab-infrastucture, puppet_module, utility, rootkit_scanner, reversing_tools, hash_cracking_tools, linux_debugger, web_browser, desktop|desktop_environment, desktop_environment, upgrade, smb, network_message, firewall, VCS, email_client, local_webapp, attack_tools, attack, sqlmap, desktop, ctf_generator

"""

# JSON file
DOMAIN_JSON = "./json/domains.json"

# File/directory constants
class DIRECTORY:
    BASE = '../modules/bases/**/secgen_metadata.xml'
    VULNERABILITY = '../modules/vulnerabilities/**/secgen_metadata.xml'
    SERVICE = '../modules/services/**/secgen_metadata.xml'
    UTILITY = '../modules/utilities/**/secgen_metadata.xml'
    NETWORK = "../modules/networks/**/secgen_metadata.xml"

# Namespace constants
class NAMESPACE:
    BASE = '{http://www.github/cliffe/SecGen/base}'
    VULNERABILITY = '{http://www.github/cliffe/SecGen/vulnerability}'
    SERVICE = '{http://www.github/cliffe/SecGen/service}'
    UTILITY = '{http://www.github/cliffe/SecGen/utility}'

class XML_TAGS:
    NAME = "name"
    DESCRIPTION = "description"
    TYPE = "type"
    DIFFICULTY = "difficulty"
    CVE = "cve"
    ACCESS = "access"
    PRIVILEGE = "privilege"
    CVSS_BASE_SCORE = "cvss_base_score"
    CVSS_VECTOR = "cvss_vector"


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
