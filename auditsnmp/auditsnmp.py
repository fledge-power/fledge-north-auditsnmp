# -*- coding: utf-8 -*-

# FLEDGE_BEGIN
# See: http://fledge-iot.readthedocs.io/
# FLEDGE_END

""" SNMP North plugin"""

import asyncio
import json
import os
import logging
from copy import deepcopy
from fledge.common import logger

__author__ = "Jeannin David"
__copyright__ = "Copyright (c) 2022, RTE (https://www.rte-france.com)"
__license__ = "Apache 2.0"
__version__ = "${VERSION}"

_LOGGER = logger.setup(__name__, level=logging.INFO)



_DEFAULT_CONFIG = {
    'plugin': {
         'description': 'SNMP audit Plugin',
         'type': 'string',
         'default': 'auditsnmp',
         'readonly': 'true'
    },
    'destination': {
        'description': 'Destination Manager that will receive the traps',
        'type': 'string',
        'default': '127.0.0.1:162',
        'order': '1',
        'displayName': 'Manager address:port'
    },
    "source": {
         "description": "Source of data to be sent on the stream. May be either readings or statistics.",
         "type": "enumeration",
         "default": "audit",
         "options": ["audit"],
         'order': '2',
         'displayName': 'Source'
    },
    'snmpVersion': {
        'description': 'SNMP Version. Either v2c or v3.',
        "type": "enumeration",
        "default": "v2c",
        "options": ["v2c","v3"],
        'order': '2',
        'displayName': 'SNMP Version'
    },
    'EngID': {
        'description': 'Engine ID if using SNMPv3.',
        "type": "string",
        "default": "",
        'order': '3',
        'displayName': 'Engine ID (SNMPv3)',
        "validity": "snmpVersion == \"v3\""
        },
    'Security': {
        'description': 'Security level if using SNMPv3.',
        "type": "enumeration",
        "default": "noAuthNoPriv",
        "options": ["noAuthNoPriv","authNoPriv","authPriv"],
        'order': '4',
        'displayName': 'Security level (SNMPv3)',
        "validity": "snmpVersion == \"v3\""
    },
    'User': {
        'description': 'User name if using SNMPv3.',
        "type": "string",
        "default": "snmp3user",
        'order': '4',
        'displayName': 'User name (SNMPv3)',
        "validity": "snmpVersion == \"v3\""
    },
    'AuthType': {
        'description': 'Authentification type if using SNMPv3.',
        "type": "enumeration",
        "default": "SHA",
        "options": ["SHA","MD5"],
        'order': '6',
        'displayName': 'Authentification type (SNMPv3)',
        "validity": "snmpVersion == \"v3\" && Security!=\"noAuthNoPriv\""
    },
    'pwd': {
        'description': 'Password if using SNMPv3.',
        "type": "string",
        "default": "default",
        'order': '5',
        'displayName': 'Password (SNMPv3)',
        "validity": "snmpVersion == \"v3\" && Security!=\"noAuthNoPriv\""
    },
    'EncType': {
        'description': 'Encryption type if using SNMPv3.',
        "type": "enumeration",
        "default": "AES",
        "options": ["AES","DES"],
        'order': '6',
        'displayName': 'Encryption type (SNMPv3)',
        "validity": "snmpVersion == \"v3\" && Security==\"authPriv\""
    },
    'EncPwd': {
        'description': 'Password for encryption if using SNMPv3.',
        "type": "string",
        "default": "default",
        'order': '6',
        'displayName': 'PrivPassword (SNMPv3)',
        "validity": "snmpVersion == \"v3\" && Security==\"authPriv\""
    },
}

def plugin_info():
    """ Used only once when call will be made to a plugin.
        Args:
        Returns:
            Information about the plugin including the configuration for the plugin
    """
    return {
        'name': 'auditsnmp',
        'version': '1.1.4',
        'type': 'north',
        'interface': '1.0',
        'config': _DEFAULT_CONFIG
    }

def loadMIB():
    global MIB_dict
    MIB_dict=None
    current_directory = os.path.dirname(__file__) #open the auditSNMP.json in the current folder
    load_path = current_directory+"/mib/auditSNMP.JSON"
    _LOGGER.info("Loading" + load_path)
    try :
        with open(load_path,'r')as f:
            MIB_dict=json.load(f)
            _LOGGER.info("Success loading the MIB File")
    except Exception as ex: #exception handle
        _LOGGER.exception("Error loading the MIB File : %s",str(ex))
    except :
        _LOGGER.error("Unknown Error loading the MIB File")


def plugin_init(data):

    loadMIB()
    config_data = deepcopy(data)
    config_data['audit_snmp'] = SNMPnorthaudit(config=config_data)
    return config_data

async def plugin_send(handle, payload, stream_id):

    try:
        audit_snmp = handle['audit_snmp'] 
        is_data_sent, new_last_object_id, num_sent = await audit_snmp.send_payloads(payload)
    except asyncio.CancelledError:
        pass
    else:
        return is_data_sent, new_last_object_id, num_sent

def plugin_reconfigure():
    pass

def plugin_shutdown(handle):
    _LOGGER.info('snmp plugin shut down.')





class SNMPnorthaudit(object):
    """ North SNMP audit Plugin """

    def __init__(self, config):
        self.event_loop = asyncio.get_event_loop()
        self.config = config

        
    def json_oid(self,data,researched_name): #Search for a name in the JSON db and return it's OID
        oid=None
        for i in data:
            if i['name']==researched_name:
                oid=i['oidValue']
                break
        return(oid)



    def sending_trap(self,snmp_server,asset,value):
        oid = self.json_oid(MIB_dict,asset)
        if oid!=None:
            try :
                if self.config["snmpVersion"]["value"]=="v2c":
                    data_string = "snmptrap -v2c -c public {} '' {} .1 {} \"{}\"".format(snmp_server, oid, 's', value)
                else :
                    if self.config["Security"]["value"] == "noAuthNoPriv":
                        data_string = "snmptrap -v3 -e {} -u {} -l {} {} '' {} .1 {} \"{}\"".format(self.config["EngID"]["value"],self.config["User"]["value"],self.config["Security"]["value"],snmp_server,oid, 's', value)
                    elif self.config["Security"]["value"] == "authNoPriv":
                        data_string = "snmptrap -v3 -e {} -u {} -a {} -A {} -l {} {} '' {} .1 {} \"{}\"".format(self.config["EngID"]["value"],self.config["User"]["value"],self.config["AuthType"]["value"],self.config["pwd"]["value"],self.config["Security"]["value"],snmp_server,oid, 's', value)
                    else:
                        data_string = "snmptrap -v3 -e {} -u {} -a {} -A {} -x {} -X {} -l {} {} '' {} .1 {} \"{}\"".format(self.config["EngID"]["value"],self.config["User"]["value"],self.config["AuthType"]["value"], self.config["pwd"]["value"],self.config["EncType"]["value"],self.config["EncPwd"]["value"],self.config["Security"]["value"],snmp_server,oid, 's', value)
                os.system(data_string)
                _LOGGER.info(data_string)
            except :
                    _LOGGER.error("Error sending trap")
        else :
            _LOGGER.info("Missing oid for : {}".format(asset))

            
    async def send_payloads(self, payloads):
        is_data_sent = False
        last_object_id = 0
        num_sent = 0

        
        _LOGGER.debug('processing payloads')
        try: #writing of a new list
            payload_block=list()
            for p in payloads:
                last_object_id=p["id"]
                read=dict()
                read["asset"] = p['asset_code']
                read["timestamp"]=p['user_ts']
                read["content"]=p['reading']
                if MIB_dict != None :
                    read["oid"]=self.json_oid(MIB_dict,read['asset'])
                    value="{'ts': '" + str(read["timestamp"]) + "'}" + str(read["content"])#setting of the string to be send with the trap
                    self.sending_trap(self.config["destination"]["value"],read["asset"],value)
                payload_block.append(read)
            num_sent=await self._send_payloads(payload_block)
            is_data_sent=True

        except Exception as ex: #exception handle
            _LOGGER.exception("Error, %s",str(ex))

        return is_data_sent, last_object_id, num_sent

    async def _send_payloads(self, payloads_block): #incrementation of the Fledge "Sent" Counter
        num_count=0
        num_count += len(payloads_block)
        return num_count




