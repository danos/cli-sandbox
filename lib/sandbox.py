# Copyright (c) 2020 AT&T intellectual property.
# All rights reserved
#
# SPDX-License-Identifier: LGPL-2.1-only

import grp

def format_passwd_database_entry(passwd):
    """
    Formats a passwd database (ie. /etc/passwd) entry.
    passwd should be a struct_passwd instance or
    equivalent sequence.
    """
    return (':'.join(str(x) for x in passwd[0:7]))

def format_group_database_entry(group):
    """
    Formats a group database (ie. /etc/group) entry.
    group should be a struct_group instance or
    equivalent sequence eg. [ "users", "x", 100, [] ]
    """
    return ':'.join(str(x) for x in group[0:3]) + \
        ':' + ','.join(group[3])

def parse_group_database(db_iter):
    """
    Returns a generator iterator which yields grp.struct_group
    instances for each value in iter.

    This is similar to grp.getgrall() except that the struct_group
    instances can be created from arbitrary data.
    """
    for entry in db_iter:
        entry = entry.strip()
        fields = entry.split(':', 4)
        try:
            # Mimic struct_group instances as returned
            # by functions of the grp module.
            fields[2] = int(fields[2])
            fields[3] = fields[3].split(',')
            if fields[3] == ['']:
                fields[3].clear()
        except (IndexError, ValueError):
            continue
        yield grp.struct_group(fields)
