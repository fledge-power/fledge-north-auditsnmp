# -*- coding: utf-8 -*-

# FLEDGE_BEGIN
# See: http://fledge-iot.readthedocs.io/
# FLEDGE_END

""" SNMP North plugin """

import asyncio
import json
import re
import logging
from copy import deepcopy
from datetime import datetime
from typing import Dict, List, Any, Optional

# SNMP imports - Explicit imports instead of *
try:
    from pysnmp.hlapi import (
        SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
        UsmUserData, usmHMACSHAAuthProtocol, usmHMACMD5AuthProtocol,
        usmAesCfb128Protocol, usmDESPrivProtocol, NotificationType,
        sendNotification
    )
    from pysnmp.proto.rfc1902 import OctetString, Integer, Counter32, Gauge32, TimeTicks, ObjectIdentifier
    PYSNMP_AVAILABLE = True
except ImportError:
    PYSNMP_AVAILABLE = False
    
from fledge.common import logger

__author__ = "Jeannin David"
__copyright__ = "Copyright (c) 2022, RTE (https://www.rte-france.com)"
__license__ = "Apache 2.0"
__version__ = "${VERSION}"

_LOGGER = logger.setup(__name__, level=logging.INFO)

# Default configuration with cleaned structure (removed enableDebugLogs and trapTimeout)
_DEFAULT_CONFIG = {
    'plugin': {
        'description': 'SNMP audit Plugin',
        'type': 'string',
        'default': 'auditsnmp',
        'readonly': 'true'
    },
    
    # SNMP Destinations
    'destinations': {
        'description': 'SNMP destination servers configuration',
        'type': 'JSON',
        'default': json.dumps({
            "servers": [
                {
                    "name": "primary",
                    "address": "127.0.0.1",
                    "port": 162,
                    "enabled": True
                },
                {
                    "name": "backup", 
                    "address": "",
                    "port": 162,
                    "enabled": False
                }
            ]
        }),
        'order': '1',
        'mandatory': 'true',
        'displayName': 'SNMP Destinations'
    },

    # Data source 
    "source": {
        "description": "Source of data to be sent on the stream.",
        "type": "enumeration",
        "default": "audit",
        "options": ["audit"],
        'order': '2',
        'displayName': 'Source'
    },

    # Processing Rules
    "processingRules": {
        "description": "Rules configuration for audit events processing",
        "type": "JSON",
        'default': json.dumps({
            "plugin_configuration": {
                "bind_1": {
                    "name": "Configuration Changes",
                    "enabled": True,
                    "trigger": {
                        "source": ["CONCH", "CONAD"],
                        "details": ".*"
                    },
                    "action": {
                        "oid": ".1.3.6.1.4.1.39059.3.3",
                        "payload": {
                            "type": "string",
                            "data": "Config change: ${source} at ${timestamp}"
                        },
                        "trapOnEvent": True,
                        "storeInMIB": False,
                        "createFledgeLog": "INFO"
                    }
                },
                "bind_2": {
                    "name": "Service Events",
                    "enabled": True,
                    "trigger": {
                        "source": ["SRVFL", "SRVUN", "SRVRG"],
                        "details": ".*"
                    },
                    "action": {
                        "oid": ".1.3.6.1.4.1.39059.3.5",
                        "payload": {
                            "type": "string",
                            "data": "Service event: ${source} - ${details}"
                        },
                        "trapOnEvent": True,
                        "storeInMIB": False,
                        "createFledgeLog": "WARNING"
                    }
                }
            }
        }),
        'order': '3',
        'mandatory': 'true',
        'displayName': 'Processing Rules'
    },

    # SNMP Configuration
    'snmpVersion': {
        'description': 'SNMP Version. Either v2c or v3.',
        "type": "enumeration",
        "default": "v2c",
        "options": ["v2c", "v3"],
        'order': '4',
        'displayName': 'SNMP Version'
    },
    'EngID': {
        'description': 'Engine ID',
        "type": "string",
        "default": "",
        'order': '5',
        'displayName': 'Engine ID (SNMPv3)',
        "validity": "snmpVersion == \"v3\""
    },
    'Security': {
        'description': 'Security level',
        "type": "enumeration",
        "default": "noAuthNoPriv",
        "options": ["noAuthNoPriv", "authNoPriv", "authPriv"],
        'order': '6',
        'displayName': 'Security level (SNMPv3)',
        "validity": "snmpVersion == \"v3\""
    },
    'User': {
        'description': 'User name',
        "type": "string",
        "default": "snmp3user",
        'order': '7',
        'displayName': 'User name (SNMPv3)',
        "validity": "snmpVersion == \"v3\""
    },
    'AuthType': {
        'description': 'Authentication type',
        "type": "enumeration",
        "default": "SHA",
        "options": ["SHA", "MD5"],
        'order': '8',
        'displayName': 'Authentication type (SNMPv3)',
        "validity": "snmpVersion == \"v3\" && Security!=\"noAuthNoPriv\""
    },
    'pwd': {
        'description': 'Password',
        "type": "string",
        "default": "default",
        'order': '9',
        'displayName': 'Password (SNMPv3)',
        "validity": "snmpVersion == \"v3\" && Security!=\"noAuthNoPriv\""
    },
    'EncType': {
        'description': 'Encryption type',
        "type": "enumeration",
        "default": "AES",
        "options": ["AES", "DES"],
        'order': '10',
        'displayName': 'Encryption type (SNMPv3)',
        "validity": "snmpVersion == \"v3\" && Security==\"authPriv\""
    },
    'EncPwd': {
        'description': 'Password for encryption',
        "type": "string",
        "default": "default",
        'order': '11',
        'displayName': 'PrivPassword (SNMPv3)',
        "validity": "snmpVersion == \"v3\" && Security==\"authPriv\""
    }
}


class TemplateProcessor:
    """Generic template processor that can handle any JSON structure"""
    
    @staticmethod
    def process_template(template: str, data: Dict[str, Any]) -> str:
        """
        Process template string with variable substitution
        Supports: ${source}, ${timestamp}, ${details}, ${reading.any.path}
        """
        if not template:
            return ""
            
        def replace_var(match):
            var_path = match.group(1)
            return TemplateProcessor._get_value_from_path(var_path, data)
        
        # Replace ${variable} patterns
        result = re.sub(r'\$\{([^}]+)\}', replace_var, template)
        return result
    
    @staticmethod
    def _get_value_from_path(path: str, data: Dict[str, Any]) -> str:
        """
        Get value from nested dictionary using dot notation
        Examples: 'source', 'reading.category', 'reading.items.logLevel.newValue'
        """
        try:
            keys = path.split('.')
            value = data
            
            for key in keys:
                if isinstance(value, dict) and key in value:
                    value = value[key]
                else:
                    return f"[undefined:{path}]"
            
            # Convert to string representation
            if isinstance(value, dict):
                return json.dumps(value, separators=(',', ':'))
            elif isinstance(value, list):
                return json.dumps(value, separators=(',', ':'))
            else:
                return str(value)
                
        except Exception as e:
            _LOGGER.debug(f"Template variable resolution failed for '{path}': {e}")
            return f"[error:{path}]"


class RuleEngine:
    """Rule matching and execution engine"""
    
    def __init__(self, rules_config: Dict[str, Any]):
        self.rules = self._load_rules(rules_config)
        
    def _load_rules(self, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Load and validate rules from configuration"""
        try:
            plugin_config = config.get('plugin_configuration', {})
            rules = []
            
            for rule_id, rule_data in plugin_config.items():
                if rule_data.get('enabled', False):
                    rules.append({
                        'id': rule_id,
                        'name': rule_data.get('name', rule_id),
                        'trigger': rule_data.get('trigger', {}),
                        'action': rule_data.get('action', {})
                    })
                    
            _LOGGER.info(f"Loaded {len(rules)} active rules")
            return rules
            
        except Exception as e:
            _LOGGER.error(f"Failed to load rules: {e}")
            return []
    
    def find_matching_rules(self, audit_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find all rules that match the given audit data"""
        matching_rules = []
        
        source = audit_data.get('asset_code', '')
        details = json.dumps(audit_data.get('reading', {}), separators=(',', ':'))
        
        for rule in self.rules:
            trigger = rule.get('trigger', {})
            
            # Check source matching
            if self._matches_source(source, trigger.get('source', [])):
                # Check details matching (regex)
                if self._matches_details(details, trigger.get('details', '.*')):
                    matching_rules.append(rule)
                    
        return matching_rules
    
    def _matches_source(self, source: str, trigger_sources) -> bool:
        """Check if source matches trigger criteria"""
        if isinstance(trigger_sources, str):
            trigger_sources = [trigger_sources]
        elif not isinstance(trigger_sources, list):
            return False
            
        for trigger_source in trigger_sources:
            if trigger_source == '*' or trigger_source == source:
                return True
                
        return False
    
    def _matches_details(self, details: str, pattern: str) -> bool:
        """Check if details match regex pattern"""
        try:
            # Convert * to .* for simple wildcard support
            if pattern == '*':
                pattern = '.*'
            return bool(re.search(pattern, details, re.IGNORECASE))
        except re.error:
            _LOGGER.warning(f"Invalid regex pattern: {pattern}")
            return False


class SNMPSender:
    """SNMP trap sender using pysnmp"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.destinations = self._load_destinations()
        self.snmp_config = self._load_snmp_config()
        
        if not PYSNMP_AVAILABLE:
            _LOGGER.error("pysnmp library not available. Please install: pip install pysnmp")
            raise ImportError("pysnmp library required")
            
    def _load_destinations(self) -> List[Dict[str, Any]]:
        """Load SNMP destinations from configuration"""
        try:
            dest_config = self.config.get('destinations', {}).get('value', {})
            if isinstance(dest_config, str):
                dest_config = json.loads(dest_config)
                
            servers = dest_config.get('servers', [])
            enabled_servers = [s for s in servers if s.get('enabled', False) and s.get('address')]
            
            _LOGGER.info(f"Loaded {len(enabled_servers)} enabled SNMP destinations")
            return enabled_servers
            
        except Exception as e:
            _LOGGER.error(f"Failed to load destinations: {e}")
            return []
    
    def _load_snmp_config(self) -> Dict[str, Any]:
        """Extract SNMP configuration"""
        return {
            'version': self.config.get('snmpVersion', {}).get('value', 'v2c'),
            'engine_id': self.config.get('EngID', {}).get('value', ''),
            'security': self.config.get('Security', {}).get('value', 'noAuthNoPriv'),
            'user': self.config.get('User', {}).get('value', 'snmp3user'),
            'auth_type': self.config.get('AuthType', {}).get('value', 'SHA'),
            'auth_password': self.config.get('pwd', {}).get('value', 'default'),
            'priv_type': self.config.get('EncType', {}).get('value', 'AES'),
            'priv_password': self.config.get('EncPwd', {}).get('value', 'default'),
        }
    
    async def send_trap(self, oid: str, payload_type: str, payload_data: str) -> bool:
        """Send SNMP trap to all enabled destinations"""
        if not self.destinations:
            _LOGGER.warning("No enabled SNMP destinations configured")
            return False
            
        success_count = 0
        
        for destination in self.destinations:
            try:
                if await self._send_trap_to_destination(destination, oid, payload_type, payload_data):
                    success_count += 1
            except Exception as e:
                _LOGGER.error(f"Failed to send trap to {destination['name']}: {e}")
                
        return success_count > 0
    
    async def _send_trap_to_destination(self, destination: Dict[str, Any], oid: str, 
                                       payload_type: str, payload_data: str) -> bool:
        """Send trap to a single destination"""
        try:
            # Convert payload to appropriate SNMP type
            snmp_value = self._convert_payload(payload_type, payload_data)
            
            # Build trap
            trap_data = self._build_trap_data(destination, oid, snmp_value)
            
            # Send trap
            for (errorIndication, errorStatus, errorIndex, varBinds) in sendNotification(*trap_data):
                if errorIndication:
                    _LOGGER.error(f"SNMP error indication: {errorIndication}")
                    return False
                elif errorStatus:
                    _LOGGER.error(f"SNMP error status: {errorStatus.prettyPrint()} at {errorIndex}")
                    return False
                    
            _LOGGER.debug(f"SNMP trap sent successfully to {destination['name']}")
            return True
            
        except Exception as e:
            _LOGGER.error(f"Error sending trap to {destination['name']}: {e}")
            return False
    
    def _convert_payload(self, payload_type: str, payload_data: str):
        """Convert payload to appropriate SNMP type"""
        try:
            if payload_type == 'string':
                return OctetString(payload_data)
            elif payload_type == 'integer':
                return Integer(int(payload_data))
            elif payload_type == 'counter':
                return Counter32(int(payload_data))
            elif payload_type == 'gauge':
                return Gauge32(int(payload_data))
            elif payload_type == 'timeticks':
                return TimeTicks(int(payload_data))
            elif payload_type == 'oid':
                return ObjectIdentifier(payload_data)
            else:
                _LOGGER.warning(f"Unknown payload type '{payload_type}', using string")
                return OctetString(payload_data)
        except (ValueError, TypeError) as e:
            _LOGGER.warning(f"Failed to convert payload '{payload_data}' to {payload_type}: {e}")
            return OctetString(str(payload_data))
    
    def _build_trap_data(self, destination: Dict[str, Any], oid: str, snmp_value):
        """Build SNMP trap data structure"""
        target = destination['address']
        port = destination.get('port', 162)
        
        if self.snmp_config['version'] == 'v2c':
            return [
                SnmpEngine(),
                CommunityData('public'),
                UdpTransportTarget((target, port)),
                ContextData(),
                'trap',
                NotificationType(ObjectIdentifier(oid)).addVarBinds(
                    (ObjectIdentifier(oid + '.1'), snmp_value)
                )
            ]
        else:  # v3
            auth_protocol = usmHMACSHAAuthProtocol if self.snmp_config['auth_type'] == 'SHA' else usmHMACMD5AuthProtocol
            priv_protocol = usmAesCfb128Protocol if self.snmp_config['priv_type'] == 'AES' else usmDESPrivProtocol
            
            if self.snmp_config['security'] == 'noAuthNoPriv':
                user_data = UsmUserData(self.snmp_config['user'])
            elif self.snmp_config['security'] == 'authNoPriv':
                user_data = UsmUserData(
                    self.snmp_config['user'], 
                    self.snmp_config['auth_password'],
                    authProtocol=auth_protocol
                )
            else:  # authPriv
                user_data = UsmUserData(
                    self.snmp_config['user'],
                    self.snmp_config['auth_password'],
                    self.snmp_config['priv_password'],
                    authProtocol=auth_protocol,
                    privProtocol=priv_protocol
                )
            
            return [
                SnmpEngine(),
                user_data,
                UdpTransportTarget((target, port)),
                ContextData(),
                'trap',
                NotificationType(ObjectIdentifier(oid)).addVarBinds(
                    (ObjectIdentifier(oid + '.1'), snmp_value)
                )
            ]


class SNMPNorthAuditV2:
    """Main SNMP North Audit Plugin class"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        
        # Initialize components
        try:
            rules_config = self._load_rules_config()
            self.rule_engine = RuleEngine(rules_config)
            self.snmp_sender = SNMPSender(config)
            self.template_processor = TemplateProcessor()
            
            _LOGGER.info("SNMP North Audit Plugin V2 initialized successfully")
            
        except Exception as e:
            _LOGGER.error(f"Failed to initialize plugin: {e}")
            raise
    
    def _load_rules_config(self) -> Dict[str, Any]:
        """Load processing rules from configuration"""
        try:
            rules_data = self.config.get('processingRules', {}).get('value', '{}')
            if isinstance(rules_data, str):
                return json.loads(rules_data)
            return rules_data
        except Exception as e:
            _LOGGER.error(f"Failed to load rules configuration: {e}")
            return {}
    
    async def send_payloads(self, payloads: List[Dict[str, Any]]) -> tuple:
        """Process audit payloads according to configured rules"""
        is_data_sent = False
        last_object_id = 0
        num_sent = 0
        
        _LOGGER.debug(f"Processing {len(payloads)} audit payloads")
        
        try:
            for payload in payloads:
                last_object_id = payload.get("id", 0)
                
                # Prepare audit data for template processing
                audit_data = {
                    'source': payload.get('asset_code', ''),
                    'timestamp': payload.get('user_ts', ''),
                    'details': json.dumps(payload.get('reading', {}), separators=(',', ':')),
                    'reading': payload.get('reading', {}),
                    'asset_code': payload.get('asset_code', ''),
                    'user_ts': payload.get('user_ts', ''),
                    'ts': payload.get('ts', ''),
                    'id': payload.get('id', 0)
                }
                
                # Find matching rules
                matching_rules = self.rule_engine.find_matching_rules(audit_data)
                
                if matching_rules:
                    rule_names = [r.get('name', r.get('id')) for r in matching_rules]
                    _LOGGER.debug(f"Audit {audit_data['source']} matched {len(matching_rules)} rules: {rule_names}")
                
                # Execute actions for each matching rule
                for rule in matching_rules:
                    if await self._execute_rule_action(rule, audit_data):
                        num_sent += 1
                        is_data_sent = True
                        
        except Exception as e:
            _LOGGER.error(f"Error processing payloads: {e}")
            
        return is_data_sent, last_object_id, num_sent
    
    async def _execute_rule_action(self, rule: Dict[str, Any], audit_data: Dict[str, Any]) -> bool:
        """Execute action for a matched rule"""
        try:
            action = rule.get('action', {})
            
            # Process template in payload data
            payload_config = action.get('payload', {})
            payload_type = payload_config.get('type', 'string')
            payload_template = payload_config.get('data', '')
            
            processed_payload = self.template_processor.process_template(payload_template, audit_data)
            
            # Send SNMP trap if enabled
            if action.get('trapOnEvent', False):
                oid = action.get('oid', '')
                if oid:
                    success = await self.snmp_sender.send_trap(oid, payload_type, processed_payload)
                    if success:
                        _LOGGER.debug(f"SNMP trap sent for rule '{rule.get('name')}': {processed_payload}")
                else:
                    _LOGGER.warning(f"No OID specified for rule '{rule.get('name')}'")
                    return False
            
            # Create Fledge log if requested
            log_level = action.get('createFledgeLog', 'None')
            if log_level != 'None':
                self._create_fledge_log(log_level, rule.get('name', ''), processed_payload)
            
            return True
            
        except Exception as e:
            _LOGGER.error(f"Failed to execute action for rule '{rule.get('name')}': {e}")
            return False
    
    def _create_fledge_log(self, level: str, rule_name: str, message: str):
        """Create Fledge log entry"""
        try:
            log_message = f"SNMP Rule '{rule_name}': {message}"
            
            if level.upper() == 'DEBUG':
                _LOGGER.debug(log_message)
            elif level.upper() == 'INFO':
                _LOGGER.info(log_message)
            elif level.upper() == 'WARNING':
                _LOGGER.warning(log_message)
            elif level.upper() == 'ERROR':
                _LOGGER.error(log_message)
            else:
                _LOGGER.info(log_message)
                
        except Exception as e:
            _LOGGER.error(f"Failed to create Fledge log: {e}")


# Fledge plugin interface functions
def plugin_info():
    """ Used only once when call will be made to a plugin.
        Args:
        Returns:
            Information about the plugin including the configuration for the plugin
    """
    return {
        'name': 'auditsnmp',
        'version': '2.9.3',
        'type': 'north',
        'interface': '1.0',
        'config': _DEFAULT_CONFIG
    }


def plugin_init(data):
    """Initialize the plugin"""
    config_data = deepcopy(data)
    config_data['audit_snmp_v2'] = SNMPNorthAuditV2(config=config_data)
    return config_data


async def plugin_send(handle, payload, stream_id):
    """Send data northbound"""
    try:
        audit_snmp = handle['audit_snmp_v2']
        is_data_sent, new_last_object_id, num_sent = await audit_snmp.send_payloads(payload)
    except asyncio.CancelledError:
        pass
    else:
        return is_data_sent, new_last_object_id, num_sent


def plugin_reconfigure():
    """Reconfigure the plugin"""
    pass


def plugin_shutdown(handle):
    """Shutdown the plugin"""
    _LOGGER.info('SNMP North Audit Plugin V2 shut down.') 