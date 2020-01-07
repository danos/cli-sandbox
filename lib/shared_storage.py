#!/usr/bin/python3
# Copyright (c) 2019 AT&T intellectual property.
# All rights reserved
#
# SPDX-License-Identifier: LGPL-2.1-only

"""
Shared Storage Configuration Access Module
This module uses a config file in /run/vyatta/shared_storage.conf to
keep the configuration.

One can add/remove shared storage entries to it. The yaml structure is
as follows. It shouldn't have duplicates.
mounts:
  /shared/path:
    perm: r|rw
    what: pathname of the device or file
    size: size of file system, optional
    exec = False # Allow execution in this directory
dirs:
  /var/log/user:
  perm: r
"""

import os
import sys
import subprocess
from tempfile import NamedTemporaryFile
import yaml


# Configuration for shared-storage and read-only directories
def check_access(top, access, perm):
    """check if access is allowed on top with given perm. top is
       the topdirectory for a mount or a directory share.
    """
    return ((perm == access or (access == 'r' and perm == 'rw')) and
            os.path.exists(top) and
            os.path.isdir(top))


def mkdir_p(path):
    """like mkdir -p - ignores if directory exists - pass on other Errors"""
    try:
        os.makedirs(path)
    except FileExistsError as exc:
        if not os.path.isdir(path):
            raise exc from None


def cmd_run(cmd, ignore=None):
    """run a command. Raise exception unless ignore is True"""
    try:
        subprocess.run(cmd, check=(not ignore))
    except subprocess.CalledProcessError as exc:
        raise SharedStorageError("comand {} exited with {}".format(exc.cmd, exc.returncode))


def get_backing_file_name(top, path):
    """generate file name for loop mount from path"""
    base = check_output_(['/bin/systemd-escape', '--path', path])
    return os.path.realpath('{}/{}.img'.format(top, base))


def is_child_dir(parent, child):
    """Check if child is a subdirectory of parent.
    Expects sanitized paths"""
    return child.startswith(parent + '/')


def mount_point(path):
    """Find the root of the mount point for the path"""
    if not os.path.isdir(path):
        path = os.path.dirname(path)
    while not os.path.ismount(path):
        path = os.path.dirname(path)
    return path


def check_output_(cmd):
    """A wrapper for subprocess.check_output to strip trailing newline"""
    out = subprocess.check_output(cmd)
    source = out.decode().rstrip('\n')
    return source


def validate_path(path):
    """Test is path is same as its realpath
    to avoid symlinks or .. or related paths"""
    rpath = os.path.abspath(os.path.realpath(path))
    if path != rpath:
        raise SharedStorageError('Invalid path {}: realpath {} is different'.format(path, rpath))


def check_mount(what, where):
    """Verify 'what' is mounted at where directory"""
    if not os.path.ismount(where):
        return False
    source = ''
    try:
        cmd1 = '/bin/findmnt -n -o SOURCE'
        source = check_output_(cmd1.split(' ') + [where])
        if source.startswith('/dev/loop'):
            cmd2 = '/sbin/losetup -n -l -O BACK-FILE'
            source = check_output_(cmd2.split(' ') + [source])
        return source == what
    except subprocess.CalledProcessError as exc:
        print("Command {} exited with {}".format(exc.cmd, exc.returncode), file=sys.stderr)
        return False


class SharedStorageError(Exception):
    """Exceptions raised by Shared Storage configuration"""


class SharedStorage:
    """
    SharedStorage(stream=file|string, filename='/run/vyatta/user-share.conf')
    Holds the configuration for shared storage. It is a collection
    of directory mounts and read-only directories as specified in
    vyatta configuration. The configuration is stored in a yaml format.
    """
    def __init__(self):
        self.mounts = {}
        self.dirs = {}
        self.tree = {}

    def __repr__(self):
        return "SharedStorage(mounts:{} dirs:{})".format(
            repr(self.mounts),
            repr(self.dirs))

    def load(self, stream=None, conf_file=None):
        """load configuration from a stream"""
        if not stream and not conf_file:
            return
        try:
            if stream is None:
                with open(conf_file, 'r') as cfile:
                    conf = yaml.load(cfile)
            else:
                conf = yaml.load(stream)
        except FileNotFoundError as exc:
            return
        except yaml.YAMLError as exc:
            raise SharedStorageError(str(exc))
        if 'mounts' in conf:
            self.validate_and_add_mounts(conf['mounts'])
        if 'dirs' in conf:
            self.validate_and_add_dirs(conf['dirs'])

    def dump(self):
        """Return a yaml configuration string"""
        return yaml.safe_dump({'mounts': self.mounts, 'dirs': self.dirs}, default_flow_style=False)

    def write(self, conf_file=None):
        """Write configuration to File"""
        if not conf_file:
            raise SharedStorageError("No filename to write")
        mkdir_p(os.path.dirname(conf_file))
        tfname = None
        try:
            with NamedTemporaryFile(dir=os.path.dirname(conf_file),
                                    prefix=os.path.basename(conf_file),
                                    delete=False) as tmpf:
                tfname = tmpf.name
                tmpf.write(self.dump().encode())
            os.rename(tfname, conf_file)
            os.chmod(conf_file, 0o644)
        except OSError as exc:
            print("failed to create temporary file: {}".format(str(exc)))
        finally:
            if tfname and os.path.exists(tfname):
                os.remove(tfname)

    def check_mount_access(self, path, access):
        """check is a mounted path is allowed the requested access"""
        perm = self.mounts[path]['perm']
        if not check_access(path, access, perm):
            return False
        return check_mount(self.mounts[path]['what'], path)

    def check_dir_access(self, path, access):
        """check is a directory path is allowed the requested access"""
        perm = self.dirs[path]['perm']
        return check_access(path, access, perm)

    def is_access_allowed(self, path, access='r'):
        """Check if 'access' is allowed for 'path'"""
        rpath = os.path.realpath(path)
        while rpath != '/':
            if rpath in self.dirs and self.check_dir_access(rpath, access):
                return True
            if rpath in self.mounts and self.check_mount_access(rpath, access):
                return True
            rpath = os.path.dirname(rpath)
        return False

    def check_update_mount_tree(self, mnt):
        """check if mountpoints overlaps"""
        if not self.tree:
            self.tree = {'name': '/', 'is_mnt': False, 'children': {}}
        node = self.tree
        for pname in mnt.split('/'):
            tmp = node['children'].get(pname)
            if not tmp:
                node['children'][pname] = {'name': pname, 'is_mnt': False, 'children': {}}
                node = node['children'][pname]
            elif tmp['is_mnt']:
                raise SharedStorageError("overlapped mount {}".format(mnt))
            else:
                node = tmp
        node['is_mnt'] = True

    def add_dir(self, path, perm, replace=False):
        """add a directoty with perm. Raise exception if directory already exists"""
        if not path:
            raise SharedStorageError("{}.add_dir(): path is None ".format(self.__class__.__name__))
        if perm and perm not in {'r', 'rw'}:
            raise SharedStorageError(
                "{}.add_dir(): invalid perm: {}".format(self.__class__.__name__, perm))
        validate_path(path)
        if not replace and path in self.dirs:
            raise SharedStorageError(
                "{}.add_dir(): {} exists".format(self.__class__.__name__, path))
        self.dirs[path] = {'perm': perm}

    def add_mount(self, path, perm, what, size, allow_exec, replace=False):
        """add a mount with perm if possible"""
        if perm and perm not in {'r', 'rw'}:
            raise SharedStorageError(
                "{}.add_mount(): invalid perm: {}".format(self.__class__.__name__, perm))
        validate_path(path)
        validate_path(what)
        if path in self.mounts:
            if not replace:
                raise SharedStorageError(
                    "{}.add_mount(): {} exists".format(self.__class__.__name__, path))
        else:
            self.check_update_mount_tree(path)
        self.mounts[path] = {'perm': perm, 'what': what, 'size': size, 'exec': allow_exec}

    def validate_and_add_dirs(self, cfg):
        """validate directory entries from yaml config"""
        if not cfg:
            return
        for k, entry in cfg.items():
            if not entry:
                perm = 'r'
            else:
                perm = entry.get('perm')
            if not perm:
                perm = 'r'
            self.add_dir(k, perm)

    def validate_and_add_mounts(self, cfg):
        """Validate an yaml configuration tree for shared storage config"""
        if not cfg:
            return
        try:
            for k, entry in cfg.items():
                if not entry:
                    raise SharedStorageError("Invalid mountpoint {}: mount infor missing".format(k))
                perm = entry.get('perm')
                if not perm:
                    perm = 'r'
                    entry['perm'] = 'r'
                what = entry.get('what')
                size = entry.get('size')
                allow_exec = entry.get('exec')
                if allow_exec is None:
                    entry['exec'] = False
                if not (size and what and os.path.isabs(what)):
                    raise SharedStorageError(
                        "Invalid entry {}: size({}) or device ({}) missing".format(k, size, what))
                self.add_mount(k, perm, what, size, allow_exec)
        except (AttributeError, TypeError, KeyError) as exc:
            raise SharedStorageError("Error while validating config: {}".format(str(exc)))

    def get_current_mounts(self):
        """returns set of mounts that are currently valid"""
        return {path for path in self.mounts if check_mount(self.mounts[path]['what'], path)}
