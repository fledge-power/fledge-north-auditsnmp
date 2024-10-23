# fledge-north-auditsnmp
A Fledge north plugin that sends SNMP traps from audits events

# Configuration
## Gloabal
### Manager (address:port)
The destination to which traps should be sent  

### (optional) Secondary Manager (address:port)
Secondary destination, in backup from the previous one. Thie field can be empty if none.

### Source
Source of the data. Only audits are handled.

### OID bindings
JSON containing bindings between the Fledge audit name and OID.

### SNMP Version
SNMP version that will be used by the plugin. Can be v2c or v3.

### Engine ID
**V3**
The Engine ID used by the plugin

### Security
**V3**
The security level used by the plugin. Can be noAuthNoPriv,authNoPriv and authPriv.

### User name
**V3**
The name of the SNMP user that will be used by the plugin.

### Authentification type
**V3-auth**
Authentication method used by the plugin. Can be SHA or MD5.

### Password
**V3-auth**
Password used by the plugin.

### Encryption type
**V3-authPriv**
Encryption method used by the plugin. Can be AES or DES.

### PrivPassword
**V3-authPriv**
Cypher Key used for the Encryption.
