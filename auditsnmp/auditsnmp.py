# -*- coding: utf-8 -*-

# FLEDGE_BEGIN
# See: http://fledge-iot.readthedocs.io/
# FLEDGE_END

""" SNMP North plugin"""

import asyncio
import json
import os
from itertools import chain
from attr import s

from fledge.common import logger
from fledge.plugins.common import utils

__author__ = "Jeannin David"
__copyright__ = "Copyright (c) 2022, RTE (https://www.rte-france.com)"
__license__ = "Apache 2.0"
__version__ = "${VERSION}"

SNMPnorthaudit = None
MIB_dict=None
config = ""
_LOGGER = logger.setup(__name__, level=logger.logging.INFO)



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
        "validity": "snmpVersion == \"v3\"" and "Security!=\"noAuthNoPriv\""
    },
    'pwd': {
        'description': 'Password if using SNMPv3.',
        "type": "string",
        "default": "default",
        'order': '5',
        'displayName': 'Password (SNMPv3)',
        "validity": "snmpVersion == \"v3\"" and "Security!=\"noAuthNoPriv\""
    },
    'EncType': {
        'description': 'Encryption type if using SNMPv3.',
        "type": "enumeration",
        "default": "AES",
        "options": ["AES","DES"],
        'order': '6',
        'displayName': 'Encryption type (SNMPv3)',
        "validity": "snmpVersion == \"v3\"" and "Security==\"authPriv\""
    },
    'EncPwd': {
        'description': 'Password for encryption if using SNMPv3.',
        "type": "string",
        "default": "default",
        'order': '6',
        'displayName': 'PrivPassword (SNMPv3)',
        "validity": "snmpVersion == \"v3\"" and "Security==\"authPriv\""
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
        'version': '1.0.2',
        'type': 'north',
        'interface': '1.0',
        'config': _DEFAULT_CONFIG
    }


def plugin_init(data):
    """ Used for initialization of a plugin.
    Args:
        data - Plugin configuration
    Returns:
        Dictionary of a Plugin configuration
    """
    global SNMPnorthaudit, config,MIB_dict
    SNMPnorthaudit = SNMPnorthaudit()
    config = data

    
    current_directory = os.path.dirname(__file__) #open the auditSNMP.json in the current folder
    load_path = current_directory+"/mib/auditSNMP.JSON"
    _LOGGER.info("Loading" + load_path)
    try :
        with open(load_path,'r')as f:
            MIB_dict=json.load(f)
            _LOGGER.info("Success loading the MIB File")
    except :
        _LOGGER.error("Error loading the MIB File")
    return config

async def plugin_send(handle, payload, stream_id):
    """ Used to send the readings block from north to the configured destination.
    Args:
        handle - An object which is returned by plugin_init
        payload - A List of readings block
        stream_id - An Integer that uniquely identifies the connection from Fledge instance to the destination system
    Returns:
        Tuple which consists of
        - A Boolean that indicates if any data has been sent
        - The object id of the last reading which has been sent
        - Total number of readings which has been sent to the configured destination
    """
    
    try:
        is_data_sent, new_last_object_id, num_sent = await SNMPnorthaudit.send_payloads(payload)
    except asyncio.CancelledError:
        pass
    else:
        return is_data_sent, new_last_object_id, num_sent


def plugin_shutdown(handle):
    """ Used when plugin is no longer required and will be final call to shutdown the plugin. It should do any necessary cleanup if required.
    Args:
         handle - Plugin handle which is returned by plugin_init
    Returns:
    """
    _LOGGER.info('snmp plugin shut down.')

class SNMPnorthaudit():
    """ North SNMP audit Plugin """

        
    def json_oid(self,data,researched_name): #Search for a name in the JSON db and return it's OID
        for i in data:
            oid=None
            if i['name']==researched_name:
                oid=i['oidValue']
                break
        return(oid)

    def sending_trap(self,snmp_server,asset,value):
        oid = self.json_oid(MIB_dict,asset)
        if oid!=None:
            try :
                if config["snmpVersion"]["value"]=="v2c":
                    os.system("snmptrap -v2c -c public {} '' {} .1 {} \"{}\"".format(snmp_server, oid, 's', value))
                    _LOGGER.info("snmptrap -v2c -c public {} '' {} .1 {} \"{}\"".format(snmp_server, oid, 's', value))
                else :
                    if config["Security"]["value"] == "noAuthNoPriv":
                        os.system("snmptrap -v3 -e {} -u {} -l {} {} '' {} .1 {} \"{}\"".format(config["EngID"]["value"],config["User"]["value"],config["Security"]["value"],snmp_server,oid, 's', value))
                        _LOGGER.info("snmptrap -v3 -e {} -u {} -l {} {} '' {} .1 {} \"{}\"".format(config["EngID"]["value"],config["User"]["value"],config["Security"]["value"],snmp_server,oid, 's', value))
                    elif config["Security"]["value"] == "authNoPriv":
                        os.system("snmptrap -v3 -e {} -u {} -a {} -A {} -l {} {} '' {} .1 {} \"{}\"".format(config["EngID"]["value"],config["User"]["value"],config["AuthType"]["value"],config["pwd"]["value"],config["Security"]["value"],snmp_server,oid, 's', value))
                        _LOGGER.info("snmptrap -v3 -e {} -u {} -a {} -A {} -l {} {} '' {} .1 {} \"{}\"".format(config["EngID"]["value"],config["User"]["value"],config["AuthType"]["value"],config["pwd"]["value"],config["Security"]["value"],snmp_server,oid, 's', value))
                    else:
                        os.system("snmptrap -v3 -e {} -u {} -a {} -A {} -x {} -X {} -l {} {} '' {} .1 {} \"{}\"".format(config["EngID"]["value"],config["User"]["value"],config["AuthType"]["value"], config["pwd"]["value"],config["EncType"]["value"],config["EncPwd"]["value"],config["Security"]["value"],snmp_server,oid, 's', value))
                        _LOGGER.info("snmptrap -v3 -e {} -u {} -a {} -A {} -x {} -X {} -l {} {} '' {} .1 {} \"{}\"".format(config["EngID"]["value"],config["User"]["value"],config["AuthType"]["value"], config["pwd"]["value"],config["EncType"]["value"],config["EncPwd"]["value"],config["Security"]["value"],snmp_server,oid, 's', value))
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
                read["oid"]=self.json_oid(MIB_dict,read['asset'])
                value="{'ts': '" + str(read["timestamp"]) + "'}" + str(read["content"])#setting of the string to be send with the trap
                payload_block.append(read)
                self.sending_trap(config["destination"]["value"],read["asset"],value)
            num_sent=await self._send_payloads(payload_block)
            is_data_sent=True

        except Exception as ex: #exception handle
            _LOGGER.exception("Error, %s",str(ex))

        return is_data_sent, last_object_id, num_sent

    async def _send_payloads(self, payloads_block): #incrementation of the Fledge "Sent" Counter
        num_count=0
        num_count += len(payloads_block)
        return num_count




