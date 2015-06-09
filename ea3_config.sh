#!/bin/ksh
# 
# ea3_config.sh - configuration file
#

# Set the enviornment variable below according to the EBS version. Nothing else is needed.
# EBS_VERSION = 11.5, 12.1, 12.2, NONE
export EBS_VERSION="NONE"

# Config file localtion, depending on the version
export EBS115_CONFIG=$IAS_ORACLE_HOME/Apache/Apache/conf
export EBS121_CONFIG=$LOG_HOME/ora/10.1.3/Apache/Apache/conf
export EBS122_CONFIG=$IAS_ORACLE_HOME/instances/*/config/OHS/*/
export EBS_NONE=/home/oracle/dchbane/fake_config

# Filter applied to the 400 errors, to exclude common errors
export ERROR40X_FILTER='grep -v "gif\|ico\| /OA_JAVA/ \| /OA_CGI/ \| /OA_CGI \|dms"'

