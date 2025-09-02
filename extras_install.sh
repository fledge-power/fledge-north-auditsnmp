#!/usr/bin/env bash

# Installation script for SNMP plugin dependencies
echo "Installing pysnmp dependencies for SNMP plugin..."

os_name=$(grep -o '^NAME=.*' /etc/os-release | cut -f2 -d\" | sed 's/"//g')
os_version=$(grep -o '^VERSION_ID=.*' /etc/os-release | cut -f2 -d\" | sed 's/"//g')
echo "Platform is ${os_name}, Version: ${os_version}"

ID=$(cat /etc/os-release | grep -w ID | cut -f2 -d"=")
if [ ${ID} != "mendel" ]; then
    case $os_name in
        *"Ubuntu"*|*"Debian"*)
            echo "Installing pysnmp for Ubuntu/Debian..."
            python3 -m pip install pysnmp==4.4.12
            ;;
        *"CentOS"*|*"Red Hat"*)
            echo "Installing pysnmp for CentOS/RHEL..."
            python3 -m pip install pysnmp==4.4.12
            ;;
        *)
            echo "Installing pysnmp for generic Linux..."
            python3 -m pip install pysnmp==4.4.12
            ;;
    esac
else
    echo "Mendel platform detected, skipping pysnmp installation"
fi

echo "SNMP plugin dependencies installation completed." 