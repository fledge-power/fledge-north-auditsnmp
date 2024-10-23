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
from datetime import datetime

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
    'mainDestination': {
        'description': 'Destination Manager that will receive the traps',
        'type': 'string',
        'default': '127.0.0.1:162',
        'order': '1',
        'mandatory':'true',
        'displayName': 'Manager (address:port)'
    },
    'backupDestination': {
        'description': 'Destination Manager that will receive the traps in backup (can be empty)',
        'type': 'string',
        'default': '',
        'order': '2',
        'displayName': '(optional) Secondary Manager (address:port)'
    },
    "source": {
         "description": "Source of data to be sent on the stream.",
         "type": "enumeration",
         "default": "audit",
         "options": ["audit"],
         'order': '3',
         'displayName': 'Source'
    },
    "OIDbindings": {
         "description": "Binding of events type to OID",
         "type": "JSON",
         'default': json.dumps({
            "bindings": [
                {
                    "name": "START",
                    "oidValue": "replace_by_your_oid"
                },
                {
                    "name": "FSTOP",
                    "oidValue": "replace_by_your_oid"
                },
                {
                    "name": "CONCH",
                    "oidValue": "replace_by_your_oid"
                },
                {
                    "name": "CONAD",
                    "oidValue": "replace_by_your_oid"
                },
                {
                    "name": "SRVRG",
                    "oidValue": "replace_by_your_oid"
                },
                {
                    "name": "SRVUN",
                    "oidValue": "replace_by_your_oid"
                },
                {
                    "name": "SRVFL",
                    "oidValue": "replace_by_your_oid"
                }
            ]
         }),
         'order': '4',
         'mandatory':'true',
         'displayName': 'OID bindings'
    },
    'snmpVersion': {
        'description': 'SNMP Version. Either v2c or v3.',
        "type": "enumeration",
        "default": "v2c",
        "options": ["v2c","v3"],
        'order': '5',
        'displayName': 'SNMP Version'
    },
    'EngID': {
        'description': 'Engine ID',
        "type": "string",
        "default": "",
        'order': '6',
        'displayName': 'Engine ID (SNMPv3)',
        "validity": "snmpVersion == \"v3\""
        },
    'Security': {
        'description': 'Security level',
        "type": "enumeration",
        "default": "noAuthNoPriv",
        "options": ["noAuthNoPriv","authNoPriv","authPriv"],
        'order': '7',
        'displayName': 'Security level (SNMPv3)',
        "validity": "snmpVersion == \"v3\""
    },
    'User': {
        'description': 'User name',
        "type": "string",
        "default": "snmp3user",
        'order': '8',
        'displayName': 'User name (SNMPv3)',
        "validity": "snmpVersion == \"v3\""
    },
    'AuthType': {
        'description': 'Authentification type',
        "type": "enumeration",
        "default": "SHA",
        "options": ["SHA","MD5"],
        'order': '9',
        'displayName': 'Authentification type (SNMPv3)',
        "validity": "snmpVersion == \"v3\" && Security!=\"noAuthNoPriv\""
    },
    'pwd': {
        'description': 'Password',
        "type": "string",
        "default": "default",
        'order': '10',
        'displayName': 'Password (SNMPv3)',
        "validity": "snmpVersion == \"v3\" && Security!=\"noAuthNoPriv\""
    },
    'EncType': {
        'description': 'Encryption type',
        "type": "enumeration",
        "default": "AES",
        "options": ["AES","DES"],
        'order': '11',
        'displayName': 'Encryption type (SNMPv3)',
        "validity": "snmpVersion == \"v3\" && Security==\"authPriv\""
    },
    'EncPwd': {
        'description': 'Password for encryption',
        "type": "string",
        "default": "default",
        'order': '12',
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
        'version': '2.1.0',
        'type': 'north',
        'interface': '1.0',
        'config': _DEFAULT_CONFIG
    }

def plugin_init(data):
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
        self.MIB_dict = self.load_oid_bindings()

    def load_oid_bindings(self):
        try:
            oid_data = self.config['OIDbindings']['value']
            oid_bindings = oid_data.get('bindings', [])
            
            mib_dict = {}
            for binding in oid_bindings:
                mib_dict[binding['name']] = binding['oidValue']
            return mib_dict
        except json.JSONDecodeError as e:
            _LOGGER.error(f"JSON parsing error in OIDbindings: {str(e)}")
            return {}
        except KeyError as e:
            _LOGGER.error(f"Missing key in OIDbindings: {str(e)}")
            return {}
        except Exception as e:
            _LOGGER.error(f"Error loading OIDbindings: {str(e)}")
            return {}

    def json_oid(self, asset):
        return self.MIB_dict.get(asset, "")

    def sending_trap(self, asset, value):
        oid = self.json_oid(asset)
        if oid != None:
            try:
                snmp_content = json.dumps(value)
                if self.config["snmpVersion"]["value"] == "v2c":
                    data_string = "snmptrap -v2c -c public {} '' {} .1 {} {}".format(self.config["mainDestination"]["value"], oid, 's', snmp_content)
                    data_string_bck = "snmptrap -v2c -c public {} '' {} .1 {} {}".format(self.config["backupDestination"]["value"], oid, 's', snmp_content)
                else:
                    if self.config["Security"]["value"] == "noAuthNoPriv":
                        data_string = "snmptrap -v3 -e {} -u {} -l {} {} '' {} .1 {} {}".format(self.config["EngID"]["value"], self.config["User"]["value"], self.config["Security"]["value"], self.config["mainDestination"]["value"], oid, 's', snmp_content)
                        data_string_bck = "snmptrap -v3 -e {} -u {} -l {} {} '' {} .1 {} {}".format(self.config["EngID"]["value"], self.config["User"]["value"], self.config["Security"]["value"], self.config["backupDestination"]["value"], oid, 's', snmp_content)
                    elif self.config["Security"]["value"] == "authNoPriv":
                        data_string = "snmptrap -v3 -e {} -u {} -a {} -A {} -l {} {} '' {} .1 {} {}".format(self.config["EngID"]["value"], self.config["User"]["value"], self.config["AuthType"]["value"], self.config["pwd"]["value"], self.config["Security"]["value"], self.config["mainDestination"]["value"], oid, 's', snmp_content)
                        data_string_bck = "snmptrap -v3 -e {} -u {} -a {} -A {} -l {} {} '' {} .1 {} {}".format(self.config["EngID"]["value"], self.config["User"]["value"], self.config["AuthType"]["value"], self.config["pwd"]["value"], self.config["Security"]["value"], self.config["backupDestination"]["value"], oid, 's', snmp_content)
                    else:
                        data_string = "snmptrap -v3 -e {} -u {} -a {} -A {} -x {} -X {} -l {} {} '' {} .1 {} {}".format(self.config["EngID"]["value"], self.config["User"]["value"], self.config["AuthType"]["value"], self.config["pwd"]["value"], self.config["EncType"]["value"], self.config["EncPwd"]["value"], self.config["Security"]["value"], self.config["mainDestination"]["value"], oid, 's', snmp_content)
                        data_string_bck = "snmptrap -v3 -e {} -u {} -a {} -A {} -x {} -X {} -l {} {} '' {} .1 {} {}".format(self.config["EngID"]["value"], self.config["User"]["value"], self.config["AuthType"]["value"], self.config["pwd"]["value"], self.config["EncType"]["value"], self.config["EncPwd"]["value"], self.config["Security"]["value"], self.config["backupDestination"]["value"], oid, 's', snmp_content)
                os.system(data_string)
                if self.config["backupDestination"]["value"] != "":
                    os.system(data_string_bck)
                _LOGGER.info(data_string)
            except:
                _LOGGER.error("Error sending trap")
        else:
            _LOGGER.debug("Missing oid for : {}".format(asset))

    async def send_payloads(self, payloads):
        is_data_sent = False
        last_object_id = 0
        num_sent = 0
        try:
            payload_block = list()
            for p in payloads:
                last_object_id = p["id"]
                read = dict()
                read["asset"] = p['asset_code']
                read["timestamp"] = p['user_ts']
                read["content"] = p['reading']
                
                read["oid"] = self.json_oid(read['asset'])
                
                combined_data = {
                    "ts": read["timestamp"],
                    "content": read["content"]
                }
                
                value = json.dumps(combined_data)
                
                if read["oid"]:
                    self.sending_trap(read["asset"], value)
                else:
                    _LOGGER.debug(f"No OID found for the asset: {read['asset']}")
                
                payload_block.append(read)
            
            num_sent = await self._send_payloads(payload_block)
            is_data_sent = True

        except Exception as ex:
            _LOGGER.error(f"Error: {str(ex)}")

        return is_data_sent, last_object_id, num_sent

    async def _send_payloads(self, payloads_block): #incrementation of the Fledge "Sent" Counter
        num_count = 0
        num_count += len(payloads_block)
        return num_count
