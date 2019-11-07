#!/bin/bash
# Copyright (c) 2018 AT&T intellectual property.
# All rights reserved
#
# SPDX-License-Identifier: GPL-2.0-only

PAM_PROFILE=sandbox
PAM_PROFILE_SRC=/opt/vyatta/share/pam-configs/${PAM_PROFILE}
PAM_PROFILE_DST=/usr/share/pam-configs/${PAM_PROFILE}
PROG=$0

err_exit()
{
	echo "${PROG}: ${1}" >&2
	exit 1
}

action=${1:-enable}
case ${action} in
	disable)
		DEBIAN_FRONTEND=noninteractive pam-auth-update --remove ${PAM_PROFILE}
		rm -f "${PAM_PROFILE_DST}"
		echo "User Isolation Disabled"
		;;
	enable)
		[ -f "${PAM_PROFILE_SRC}" ] && \
			cp -f "${PAM_PROFILE_SRC}" "${PAM_PROFILE_DST}"
		DEBIAN_FRONTEND=noninteractive pam-auth-update --package
		echo "User Isolation Enabled"
		;;
	*)
		err_exit "error: unknown argument '${1}'"
		;;
esac

exit 0
