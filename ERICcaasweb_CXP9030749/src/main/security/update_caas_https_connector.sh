#!/bin/bash

AWK=/bin/awk
BASENAME=/bin/basename
CERTS_DIR=/ericsson/tor/data/certificates/caasweb
CUT=/bin/cut
ECHO="echo -e"
ENV=/bin/env
GREP=/bin/grep
JBOSS_SERVER_CERT_ALIAS="caas-web"
KEY_PASS="changeit"
KEYSTORE=${CERTS_DIR}/caas-web-server-keystore.jks
LOGGER=/usr/bin/logger
LOGGER_TAG="TOR_CAASWEB"
LITP_JEE_DE_PATTERN="caas-web"
KEYTOOL=/usr/java/default/bin/keytool
SCRIPT_NAME=$( ${BASENAME} ${0} )
SED=/bin/sed
TRUSTSTORE=${CERTS_DIR}/caas-web-server-trustore

##
## ENV
##
STANDALONE_XML=$( ${ECHO} ${LITP_JEE_CONTAINER_command_line_options} | ${GREP} -o \\-\\-server\\-config=\.*\.xml | ${CUT} -d= -f2 | ${AWK} {'print $1'} )
JBOSS_CONFIG=${LITP_JEE_CONTAINER_home_dir}/standalone/configuration/${STANDALONE_XML}
container_check=$( ${ENV} | ${GREP} _JEE_DE_name | ${GREP} ${LITP_JEE_DE_PATTERN} > /dev/null 2>&1 )
ret_val=${?}

##
## INFORMATION print
##
info()
{
	if [ ${#} -eq 0 ]; then
		while read data; do
			logger -s -t ${LOGGER_TAG} -p user.notice "INFORMATION ( ${SCRIPT_NAME} ): ${data}"
		done
	else
		logger -s -t ${LOGGER_TAG} -p user.notice "INFORMATION ( ${SCRIPT_NAME} ): $@"
	fi
}

##
## ERROR print
##
error()
{
	if [ ${#} -eq 0 ]; then
		while read data; do
			logger -s -t ${LOGGER_TAG} -p user.err "ERROR ( ${SCRIPT_NAME} ): ${data}"
		done
	else
		logger -s -t ${LOGGER_TAG} -p user.err "ERROR ( ${SCRIPT_NAME} ): $@"
	fi
}

##
## WARN print
##
warn()
{
	if [ ${#} -eq 0 ]; then
		while read data; do
			logger -s -t ${LOGGER_TAG} -p user.warning "WARN ( ${SCRIPT_NAME} ): ${data}"
		done
	else
		logger -s -t ${LOGGER_TAG} -p user.warning "WARN ( ${SCRIPT_NAME} ): $@"
	fi
}


##
## Clean up function, nothing to do so far
##
cleanup ()
{
	info "No cleanup to be performed"
}

##
## Exit gracfully so as not to break flow
##
graceful_exit ()
{
	[ "${#}" -gt 1 -a "${1}" -eq 0 ] && info "${2}"
	[ "${#}" -gt 1 -a "${1}" -gt 0 ] && error "${2}"
	#cleanup
	exit ${1}
}

############
## EXECUTION
############
if [ ${ret_val} -eq 0 ]; then
	info "CAAS Web Container found, adding SSL connector and new port in ${JBOSS_CONFIG}"

        ${SED} -i "/connector name=\"http\"/a \\\t\t<connector name=\"https-caas-web\" protocol=\"HTTP/1.1\" scheme=\"https\" socket-binding=\"https-caas-web\" secure=\"true\">" ${JBOSS_CONFIG}
        ${SED} -i "/connector name=\"https-caas-web\"/a \\\t\t\t<ssl name=\"ssl\" key-alias=\"${JBOSS_SERVER_CERT_ALIAS}\" password=\"changeit\" certificate-key-file=\"${KEYSTORE}\" verify-client=\"true\" ca-certificate-file=\"${TRUSTSTORE}\"/>" ${JBOSS_CONFIG}
        ${SED} -i "/key-alias=\"${JBOSS_SERVER_CERT_ALIAS}\"/a \\\t\t</connector>" ${JBOSS_CONFIG}
	${SED} -i "/<socket-binding-group/a \\\t<socket-binding name=\"https-caas-web\" port=\"50142\"/>" ${JBOSS_CONFIG}

	#${SED} -i "s|{caasweb.alias}|${JBOSS_SERVER_CERT_ALIAS}|g;\
	#	s|{caasweb.key.file}|${KEYSTORE}|g;\
	#	s|{caasweb.certs}|${TRUSTSTORE}|g" ${JBOSS_CONFIG}

	[ ${?} -eq 0 ] && graceful_exit 0 "Updated ${JBOSS_CONFIG}" || warn "Failed to update ${JBOSS_CONFIG}"
fi

exit 0
