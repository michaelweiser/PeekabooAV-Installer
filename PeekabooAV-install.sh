#!/bin/bash
#
#
#   PeekabooAV Installer
#
#   this installer is work in progress
#   it has two purposes
#   - an easy way to have a fast installation
#   - documentation on how to set things up
#
#   it can also be used to update an installation
#
#
#   by felix bauer
#  felix.bauer@atos.net
#
# 23.08.2017
#
# Copyright (C) 2016-2018 science + computing ag
#
#

#
# This install script describes and performs a basic installation
# of PeekabooAV
#

# The following function will clear all buffered stdin.  (See
# http://compgroups.net/comp.unix.shell/clear-stdin-before-place-read-a/507380)
fflush_stdin() {
	local dummy=""
	local originalSettings=""
	originalSettings=`stty -g`
	stty -icanon min 0 time 0
	while read dummy ; do : ; done
	stty "$originalSettings"
}

owl="

                         ==                             =
                         ========                 =======
                           ===========?     ===========
                             ========================
                            ==       ========       ===
                           =           ====           =
                          +=     ?     ====     ?     ==
                          ==           =,,=           ==
                           =          ,,,,,,,         =+
                           ==         =,,,,=         ==
                            +====+=======,====== =====
                            ==========================
                          ==============================
                         ===============77===============
                         =========77777777777777+========
                         ======77777777777777777777======
                         =====7777777777777777777777=====
                          ===777777777777777777777777====
                          ===7777777777777777777777777==
                           ==7777777777777777777777777=
                           +=777777777777777777777777==
                            ==77777777777777777777777=
                             ==777777777777777777777=
                              +=7777777777777777777=
                                =7777777777777777=
                                 ==777777777777==
                                    ==777777==
                            ,,,,,,::::::==::::::,,,,,,
                    ,,,,,,,,,,,,,,,              ,,,,,,,,,,,,,
              ,,,,,,,,                                        ,,,,,,
          ,,,,,                                                      ,,,
       ,,,
    ,
"

note="
Welcome to the PeekabooAV installer
===================================

we assume the following:
- you want to install or update PeekabooAV
- this is a Ubuntu 18.04 VM
- /etc/hostname is a valid FQDN
- nothing else runs on this machine
- you run this installer as root
- you know what you're doing!

we will:
- activate the universe (ansible) and multiverse (rar/unrar) repositories
- install latest updates (apt-get dist-upgrade)
- install ansible
- install various system packages which are dependencies for Cuckoo and Peekaboo
- install Cuckoo and Peekaboo with their python dependencies into virtualenvs in /opt
"

usage() {
	echo "$0 [-h|--help] [-q|--quiet]"
	echo
	echo "Automates the standard installation of PeekabooAV."
	echo
	echo "--quiet, -q	be less verbose and noninteractive, most notably"
	echo "		do not print the logo"
	echo "--help, -h	show this help message"
	echo
	echo "$note"
}

bail_arg_required() {
	echo "Argument required for $1"
	usage
	exit 1
}

bail_unknown_argument() {
	echo "Unknown argument: $1"
	usage
	exit 1
}

quiet=
while [ -n "$1" ] ; do
	case "$1" in
		--quiet|-q)
			quiet=1
			;;

		--help|-h)
			usage
			exit 0
			;;

		*)
			bail_unknown_argument
			;;
	esac
	shift
done

if [ "$quiet" != 1 ] ; then
	# The following code is just to have the owl and info scroll by slowly.
	( echo "$owl"; echo "$note" ) | while IFS= read -r line; do
		printf '%s\n' "$line"
		sleep .1
	done

	echo "If any of these is not the case or not acceptable please hit Ctrl+c"
	echo
	echo "Press enter to continue"


	# Discard all input in buffer.
	fflush_stdin

	# Read 'Press enter ..'
	read
fi

if [ $(id -u) != 0 ]; then
	echo "ERROR: $(basename $0) needs to be run as root" >&2
	exit 1
fi

# Check if hostname fqdn is properly set and resolves
if ! hostname --fqdn | grep -q "\." > /dev/null 2>&1
then
	echo "ERROR: hostname FQDN not explicitly assigned" >&2
	exit 1
fi

# prevent apt-get from asking questions because we want to be an automated
# installer, particularly because we do want to work when run from a Dockerfile
# or Vagrantfile
export DEBIAN_FRONTEND=noninteractive

# Refresh package repositories.
if ! apt-get update ; then
	echo "ERROR: the command 'apt-get update' failed. Please fix manually" >&2
	exit 1
fi

if ! apt-get install -y software-properties-common ; then
	echo "ERROR: apt source management helpers cannot be installed" >&2
	exit 1
fi

# multiverse also adds universe and script does an apt-get update as well
if ! apt-add-repository -y multiverse ; then
	echo "ERROR: universe/multiverse repositories cannot be added" >&2
	exit 1
fi

# Upgrade system
if ! apt-get dist-upgrade -y ; then
	echo "ERROR: the command 'apt-get dist-upgrade' failed. Please fix manually" >&2
	exit 1
fi

# Install ansible
if ! apt-get install -y ansible ; then
	echo "ERROR: ansible cannot be installed" >&2
	exit 1
fi

ansibleversion=$(ansible --version | head -n 1 | grep -o "[0-9\.]*")
IFS='.' read -r -a ansibleversionarray <<< "$ansibleversion"
# check major version
if [[ ${ansibleversionarray[0]} -eq 2 ]]
then
	# check minor version
	if [[ ${ansibleversionarray[1]} -lt 5 ]]
	then
		echo "ERROR: ansible version (${ansibleversion}) too old, at least version 2.5 required"
		exit 1
	fi
else
	echo "ERROR: ansible version likely not compatible, at least version 2.5 required"
	exit 1
fi

# Check for SYSTEMD module
if ! ansible-doc systemd 2>/dev/null | grep -q SYSTEMD
then
	echo "ERROR: ansible version maybe too old, SYSTEMD module missing"
	exit 1
fi

ANSIBLE_INVENTORY=$(dirname $0)/ansible-inventory
ANSIBLE_PLAYBOOK=$(basename $0 .sh).yml

if [ ! -r "$ANSIBLE_INVENTORY" ]; then
	echo "ERROR: ansible inventory file "$ANSIBLE_INVENTORY" not found" >&2
	exit 1
fi

if [ ! -r "$ANSIBLE_PLAYBOOK" ]; then
	echo "ERROR: ansible playbook "$ANSIBLE_PLAYBOOK" not found" >&2
	exit 1
fi

ansible-playbook -e 'ansible_python_interpreter=/usr/bin/python3' -i "$ANSIBLE_INVENTORY" "$ANSIBLE_PLAYBOOK"
if [ $? != 0 ];then
	echo "ERROR: 'ansible-playbook' failed. Please fix manually" >&2
	exit 1
fi
# Clear screen.
clear

cat << EOF
Things are Done
===============

now there is a user called peekaboo whose home is at /var/lib/peekaboo

assuming you've done this:
- installed and replicated your VMs on your vmhost
- configured networking properly
- configured some mail thing on the host
- configured cuckoo properly to know and use your VMs

now it's your turn to do the following:
- configure vmhost to allow SSH connections from $HOSTNAME (.ssh/authorized_keys)
- configure static ip in /etc/network/interfaces
- check dataflow through mail, amavis, peekaboo, cuckoo
- reboot & snapshot

That's it well done

Thanks
have a nice day
EOF
