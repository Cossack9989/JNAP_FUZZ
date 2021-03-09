# -*- coding:utf-8 -*-

import os
import json
import random
from pwn import *
from JNAP import *
from binascii import hexlify


dangerous_interface_list = [
    (
        "core/SetUnsecuredWiFiWarning",
        ["enabled"]
    ),
    (
        "dynamicsession/GetDynamicSessionInfo",
        ["sessionUUID"]
    ),
    (
        "guestnetwork/Authenticate",
        ["macAddress", "ipAddress", "password"]
    ),
    (
        "httpproxy/RemoveHttpProxyRule",
        ["ruleUUID"]
    ),
    (
        "routerlog/GetIncomingLogEntries",
        ["firstEntryIndex", "entryCount"]
    ),
    (
        "routerlog/GetOutgoingLogEntries",
        ["firstEntryIndex", "entryCount"]
    ),
    (
        "routerlog/GetSecurityLogEntries",
        ["firstEntryIndex", "entryCount"]
    ),
    (
        "routerlog/GetDHCPLogEntries",
        ["firstEntryIndex", "entryCount"]
    ),
    (
        "ui/SetRemoteSetting",
        ["isEnabled"]
    )
]


def fuzz_file(param):
    files_list = os.listdir("sample/" + param)
    return "sample" + '/' + param + '/' + random.choice(files_list)


def fuzz_random(param, param_tmp_fuzz_file):
    try:
        p = process(["/usr/bin/radamsa", param_tmp_fuzz_file])
        tmp_fuzz_data = p.recv().decode()
    except Exception:
        tmp_fuzz_data = hexlify(os.urandom(8)).decode()
    return tmp_fuzz_data





def generate_payload(param_list):
    ret_dict = {}
    for param in param_list:
        ret_dict[param] = fuzz_random(param, fuzz_file(param))
    return ret_dict


def save_result(response, data,interface, idx):
    log_flag = True
    if response.status_code == 200:
        response_text = json.loads(response.text)
        if response_text["result"] == "_ErrorInvalidInput":
            if "error" in response_text.keys():
                if response_text["error"].startswith("Invalid string member value") or response_text["error"].startswith("Failed to deserialize") or response_text["error"].startswith("Invalid string value (string contains embedded null character)"):
                    log_flag = False
        elif response_text["result"] == "ErrorHttpProxyRuleDoesNotExist":
            log_flag = False
    if log_flag is True:
        record_file = open("result/{interface}_{idx}.txt".format(interface=interface.replace('/', '_'), idx=idx), "w")
        record_file.write(str(data) + str(response.status_code) + response.text)
        record_file.close()
    print("save done with {data} {interface}".format(data=data, interface=interface))


def fuzz(interface_list, idx):
    for interface in interface_list:
        hackEA = Linksys("http://192.168.1.1")
        # info("======================================================")
        data = generate_payload(interface[1])
        # info("{interface}: {data}".format(interface=interface[0], data=data))
        rsp = hackEA.do_action(interface[0], data=data)
        # info("{status}".format(status=rsp.status_code))
        # info("{content}".format(content=rsp.text))
        # info("******************************************************")
        save_result(rsp, data, interface[0], idx)
        # print("\n")


for i in range(1000):
    fuzz(dangerous_interface_list, i)