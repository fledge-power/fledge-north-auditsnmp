# fledge-north-auditsnmp
A Fledge north plugin that sends audit events data as SNMP traps

Quick installation :

-Download the plugin

-Copy your file in the North plugin folder of Fledge

-Create or copy a MIB in JSON
-Put this file in the plugin repository
-The plugin should be seen in Fledge-GUI

Integration in Fledge-GUI :
-open Fledge-GUI in your browser
-Click on "North" in the left menu
-Click on Add +
-Select auditsnmp and name your service
-IMPORTANT:Check "Add as a Service"
-Next, configure the plugin as your conveniance
-You have a working auditsnmp plugin
