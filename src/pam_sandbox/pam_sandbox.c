/*
 * Copyright (c) 2018-2020, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#define _GNU_SOURCE

#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <sched.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <linux/limits.h>
#include <systemd/sd-bus.h>

#define PAM_SM_SESSION
#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>
#include <security/_pam_macros.h>

#define PAM_SOCK "/var/run/pam.sock"
#define PAM_SECURITY_CONF_PATH "/etc/security/pam.conf"
#define PAM_CGROUP_ROOT_PATH "/sys/fs/cgroup"

#define PAM_NAME_MAX_SIZE 256
#define PAM_ID_SIZE 64
#define MAXHOSTNAMELEN 256
#define SANDBOX_RETRY_COUNT 20
#define SANDBOX_RETRY_DELAY (100 * 1000 * 1000) /* Nano seconds */

#define UNUSED(x)		/* X */

static const char *SYSTEMD = "org.freedesktop.systemd1";
static const char *SYSTEMD_PATH = "/org/freedesktop/systemd1";
static const char *SYSTEMD_MANAGER = "org.freedesktop.systemd1.Manager";
static const char *MACHINED = "org.freedesktop.machine1";
static const char *MACHINE_PATH = "/org/freedesktop/machine1";
static const char *MACHINE_MANAGER = "org.freedesktop.machine1.Manager";
static const char *MACHINE_INTF = "org.freedesktop.machine1.Machine";
static const char *exclude_groups[] = { "vyattasu", NULL };

typedef struct sandbox_info {
	char *name;
	char *class;
	char *state;
	char *root_directory;
	pid_t leader;
} sandbox_info_t;

static int is_sandboxed(pam_handle_t * pamh, const struct passwd *pw);
static int enter_sandbox(pam_handle_t * pamh, const struct passwd *pw);
static int wait_for_file(const char *fname);
static int add_to_namespaces(pam_handle_t * pamh, pid_t tpid);
static void free_sandbox_info(sandbox_info_t * info);
static int get_machine_info(pam_handle_t * pamh, sd_bus * bus,
			    const char *name, sandbox_info_t * info);
static int bus_get_machine_path(pam_handle_t * pamh, sd_bus * bus,
				const char *name, char **path);
static int bus_get_machine_property_string(pam_handle_t * pamh,
					    sd_bus * bus,
					    const char *path,
					    char *prop_name, char **value);
static int bus_get_machine_property_uint(pam_handle_t * pamh,
					  sd_bus * bus,
					  const char *path,
					  char *name, void *value);
static int bus_start_unit(pam_handle_t * pamh, sd_bus * bus, const char *unit);
static int get_sandbox(pam_handle_t * pamh, const char *mach,
		       const char *svc, sandbox_info_t * info);
static int get_user_container(pam_handle_t * pamh, const struct passwd *pw,
			      sandbox_info_t * info);
static int open_in_pid(pam_handle_t * pamh, pid_t tpid, const char *rel_path);
static int sandbox_set_hostname(pam_handle_t *pamh, const char *hostname);

int pam_sm_open_session(pam_handle_t * pamh, __attribute__ ((unused))
			int flags, __attribute__ ((unused))
			int arg, __attribute__ ((unused))
			const char **argv)
{
	const char *username;
	int r;
	struct passwd *pw;
	int enter_sandbox_retry = 1;

	r = pam_get_user(pamh, &username, NULL);
	if (r != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_ERR, "Cannont fetch user name");
		return PAM_SERVICE_ERR;
	}

	pw = pam_modutil_getpwnam(pamh, username);
	if (pw == NULL) {
		pam_syslog(pamh, LOG_ERR,
			"sandbox: can't get entry for user %s\n", username);
		return PAM_SERVICE_ERR;
	}

	if (!is_sandboxed(pamh, pw)) {
		return PAM_SUCCESS;
	}
	/* Retry entering sanbox once as it is possible that
	 * earlier sandbox might have exited
	 * after this session detected its presence, but before
	 * this session has attempted to switch namespaces.
	 */
	while(enter_sandbox_retry-- >= 0) {
		r = enter_sandbox(pamh, pw);
		if (r == 0)
			return PAM_SUCCESS;
	}

	return PAM_SERVICE_ERR;
}

int pam_sm_close_session(pam_handle_t * pamh, __attribute__ ((unused))
			 int flags, __attribute__ ((unused))
			 int arg, __attribute__ ((unused))
			 const char **argv)
{
	pam_syslog(pamh, LOG_INFO, "close_session called.\n");
	return PAM_SUCCESS;
}

/*
 * is_sandboxed(const char *username)
 * -- check if sandboxing globally disabled.
 * -- check if the user is in the excluded group.
 */
static int is_sandboxed(pam_handle_t * pamh, const struct passwd *pw)
{
	int i;

	/* don't sandbox uid 0 */
	if (pw->pw_uid == 0)
		return 0;

	/* don't sandbox if user is in one of the excluded groups */
	for (i = 0; exclude_groups[i] != NULL; i++) {
		if (pam_modutil_user_in_group_nam_nam(pamh, pw->pw_name, exclude_groups[i]))
			return 0;
	}
	return 1;
}

/*
 * Enter user's sandbox. This will switch:
 * 1. namespaces
 * 2. chroot into the containers root directory.
 * 3. Setup the container hostname to be same as host
 */
static int enter_sandbox(pam_handle_t * pamh, const struct passwd *pw)
{
	int r;
	sandbox_info_t info = { };
	char hostname[MAXHOSTNAMELEN + 1];

	r = get_user_container(pamh, pw, &info);
	if (r < 0) {
		pam_syslog(pamh, LOG_ERR, "failed to get user's container\n");
		goto out;
	}

	pam_syslog(pamh, LOG_INFO, "%s login entering sandbox %s(leader=%d)\n",
		   pw->pw_name, info.name, info.leader);

	hostname[sizeof(hostname) - 1] = '\0';
	r = gethostname(hostname, sizeof(hostname) - 1);
	if (r < 0) {
		pam_syslog(pamh, LOG_ERR, "failed to get hostname:%s", strerror(errno));
		strcpy(hostname, "localhost"); /* Use something */
	}

	r = add_to_namespaces(pamh, info.leader);

	if (r < 0) {
		pam_syslog(pamh, LOG_ERR,
			   "failed to enter namespaces in container %s\n",
			   info.name);
		goto out;
	}

	/* Lets wait of sandbox to be ready */
	r = wait_for_file("/run/ready");
	if (r < 0) {
		pam_syslog(pamh, LOG_ERR, "failed to enter sandbox - sandbox not ready");
		goto out;
	}

	if (hostname[0] != '\0') {
		sandbox_set_hostname(pamh, hostname);
	}

 out:
	free_sandbox_info(&info);
	return r < 0 ? r : 0;
}

/*
 * Sanitise a system username such that it may be used as part of a
 * machine name. In particular we replace underscores with dots, as
 * underscores are no longer permitted in machine names since systemd 240.
 *
 * The Vyatta configuration does not permit configuring users with dots in
 * the username so there should be no collision.
 */
static char *
sanitise_username(const char *username)
{
	char *p, *out;

	out = strdup(username);
	if (!out)
		return NULL;

	for (p = out; *p; p++)
		*p = (*p == '_') ? '.' : *p;

	return out;
}

/*
 * get the name of the container and the service name to
 * use to start the container
 */
static int
get_user_container(pam_handle_t * pamh, const struct passwd *pw,
		   sandbox_info_t * info)
{
	int r;

	char *name;
	char *sbox = NULL;
	char *svc = NULL;
	assert(pw);

	name = sanitise_username(pw->pw_name);
	if (!name)
		return -1;

	r = asprintf(&sbox, "cli-%s", name);
	if (r < 0)
		goto out;

	r = asprintf(&svc, "cli-sandbox@%s.service", pw->pw_name);
	if (r < 0)
		goto out;

	r = get_sandbox(pamh, sbox, svc, info);
 out:
	free(name);
	free(sbox);
	free(svc);
	return r < 0 ? r : 0;
}

/*
 * Open a file /proc/pid/...
 */
static int open_in_pid(pam_handle_t * pamh, pid_t tpid, const char *rel_path)
{
	char *path_name = NULL;
	int fd;

	if (asprintf(&path_name, "/proc/%d/%s", tpid, rel_path) <= 0) {
		pam_syslog(pamh, LOG_ERR,
			   "open_in_pid():%d %s:asprintf failed\n", tpid,
			   rel_path);
		return -1;
	}
	fd = open(path_name, O_RDONLY);
	if (fd < 0)
		pam_syslog(pamh, LOG_ERR, "open_in_pid():%s failed:%s\n",
			   path_name, strerror(errno));
	free(path_name);
	return fd;
}

static int wait_for_file(const char *fname)
{
	struct stat st;
	const struct timespec delay = { 0, SANDBOX_RETRY_DELAY };
	int retries = SANDBOX_RETRY_COUNT;
	while(retries--) {
		if (stat(fname, &st) == 0)
			return 0;
		nanosleep(&delay, NULL);
	}
	return -1;
}


/* check if both the namespaces are different
 * if one or both them doesn't exist return
 * false as that would cause the caller to skip
 * the next setns call.
 * inspired by nsenter.
 */
static int check_setns(int new_fd, int old_fd)
{
	struct stat new_st, old_st;

	if ((fstat(new_fd, &new_st) < 0) || (fstat(old_fd, &old_st) < 0))
		return 0;

	return new_st.st_ino != old_st.st_ino;
}

/*
 * Switch to namespaces of the leader's pid
 */
static int add_to_namespaces(pam_handle_t * pamh, pid_t tpid)
{
	int ret = -1;
	char *pathbuf = NULL;
	char *ns[] = { "ns/net", "ns/ipc", "ns/uts", "ns/pid", "ns/mnt" };
	size_t n = sizeof(ns) / sizeof(*ns);
	int old_ns_fd[n];
	int new_ns_fd[n];
	size_t i;
	int rfd = -1;
	pid_t cur_pid = getpid();

	for (i = 0; i < n; i++) {
		new_ns_fd[i] = -1;
		old_ns_fd[i] = -1;
	}

	for (i = 0; i < n; i++) {
		old_ns_fd[i] = open_in_pid(pamh, cur_pid, ns[i]);
		new_ns_fd[i] = open_in_pid(pamh, tpid, ns[i]);
		if ((new_ns_fd[i] < 0) || (old_ns_fd[i] < 0))
			goto out;
	}
	rfd = open_in_pid(pamh, tpid, "root");
	if (rfd < 0) {
		pam_syslog(pamh, LOG_ERR, "failed to open 'root' in %d\n",
			   tpid);
		goto out;
	}

	for (i = 0; i < n; i++) {
		if (!check_setns(new_ns_fd[i], old_ns_fd[i]))
			continue;
		if (setns(new_ns_fd[i], 0)) {
			pam_syslog(pamh, LOG_ERR,
				   "failed to change to '%s' namespace fd",
				   ns[i]);
			goto out;
		}
	}

	/*
	 * Now change to target's root directory
	 */
	if (fchdir(rfd) < 0) {
		pam_syslog(pamh, LOG_ERR, "failed chdir to root directory\n");
		goto out;
	}
	if (chroot(".") < 0) {
		pam_syslog(pamh, LOG_ERR, "failed chroot to root directory\n");
		goto out;
	}

	ret = 0;
 out:
	for (i = 0; i < n; i++) {
		if (new_ns_fd[i] >= 0)
			close(new_ns_fd[i]);
		if (old_ns_fd[i] >= 0)
			close(old_ns_fd[i]);
	}
	if (rfd >= 0)
		close(rfd);
	free(pathbuf);

	return ret;
}

static void free_sandbox_info(sandbox_info_t * info)
{
	free(info->name);
	free(info->class);
	free(info->state);
	free(info->root_directory);
	info->name = NULL;
	info->class = NULL;
	info->root_directory = NULL;
	info->state = NULL;
	info->leader = -1;
}

static int
get_machine_info(pam_handle_t * pamh, sd_bus * bus, const char *name,
		 sandbox_info_t * info)
{
	char *path = NULL;
	int r;

	assert(info->name == NULL);
	assert(info->class == NULL);
	assert(info->state == NULL);
	assert(info->root_directory == NULL);
	r = bus_get_machine_path(pamh, bus, name, &path);
	if (r < 0)
		goto err;

	r = bus_get_machine_property_string(pamh, bus, path, "Name",
					     &info->name);
	if (r < 0)
		goto err;
	r = bus_get_machine_property_string(pamh, bus, path, "Class",
					     &info->class);
	if (r < 0)
		goto err;
	r = bus_get_machine_property_string(pamh, bus, path, "RootDirectory",
					     &info->root_directory);
	if (r < 0)
		goto err;
	r = bus_get_machine_property_string(pamh, bus, path, "State",
					     &info->state);
	if (r < 0)
		goto err;
	r = bus_get_machine_property_uint(pamh, bus, path, "Leader",
					   &info->leader);
	if (r < 0)
		goto err;
	return 0;
 err:
	free(path);
	free_sandbox_info(info);
	return r;

}

static int
bus_get_machine_path(pam_handle_t * pamh, sd_bus * bus, const char *name,
		     char **path)
{
	sd_bus_error e = SD_BUS_ERROR_NULL;
	sd_bus_message *m = NULL;
	char *tmp_path;
	int r;

	r = sd_bus_call_method(bus,
			       MACHINED,
			       MACHINE_PATH,
			       MACHINE_MANAGER, "GetMachine", &e, &m, "s",
			       name);

	if (r < 0) {
		/* No device (ENXIO) is expected on 1st access to sandbox */
		if (r != -ENXIO)
			pam_syslog(pamh, LOG_ERR,
				   "Failed to get machine for %s: %s (%d)\n",
				   name, e.message, r);
		goto out;
	}
	/*
	 * Parse the response message
	 */
	r = sd_bus_message_read(m, "o", &tmp_path);
	if (r < 0)
		pam_syslog(pamh, LOG_ERR,
			   "%d: Failed to parse response message: %s\n",
			   __LINE__, strerror(-r));
	*path = strdup(tmp_path);
 out:
	sd_bus_error_free(&e);
	sd_bus_message_unref(m);
	return r < 0 ? r : 0;
}

static int
bus_get_machine_property_string(pam_handle_t * pamh, sd_bus * bus,
				 const char *path, char *prop, char **value)
{
	sd_bus_error e = SD_BUS_ERROR_NULL;
	int r;

	r = sd_bus_get_property_string(bus,
				       MACHINED,
				       path, MACHINE_INTF, prop, &e, value);
	if (r < 0) {
		pam_syslog(pamh, LOG_ERR,
			   "%d:Failed to parse response message prop=%s: %s:%s\n",
			   __LINE__, prop, strerror(-r), e.message);
		goto out;
	}
 out:
	sd_bus_error_free(&e);
	return r < 0 ? -1 : 0;
}

static int
bus_get_machine_property_uint(pam_handle_t * pamh, sd_bus * bus,
			       const char *path, char *prop, void *value)
{
	sd_bus_error e = SD_BUS_ERROR_NULL;
	int r;

	r = sd_bus_get_property_trivial(bus,
					MACHINED,
					path, MACHINE_INTF, prop, &e, 'u',
					value);
	if (r < 0) {
		pam_syslog(pamh, LOG_ERR,
			   "%d:Failed to parse response message: %s:%s\n",
			   __LINE__, strerror(-r), e.message);
		goto out;
	}
 out:
	sd_bus_error_free(&e);
	return r < 0 ? -1 : 0;
}

static int bus_start_unit(pam_handle_t * pamh, sd_bus * bus, const char *unit)
{
	sd_bus_error e = SD_BUS_ERROR_NULL;
	sd_bus_message *m = NULL;
	const char *path = NULL;
	int r;

	r = sd_bus_call_method(bus,
			       SYSTEMD,
			       SYSTEMD_PATH,
			       SYSTEMD_MANAGER,
			       "StartUnit", &e, &m, "ss", unit, "fail");

	if (r < 0) {
		pam_syslog(pamh, LOG_ERR,
			   "Failed to issue method call StartUnit:%s:%s\n",
			   unit, e.message);
		goto out;
	}

	r = sd_bus_message_read(m, "o", &path);
	if (r < 0) {
		pam_syslog(pamh, LOG_ERR,
			   "can't parse response message: StartUnit:%s: %s\n",
			   unit, strerror(-r));
		goto out;
	}
 out:
	sd_bus_error_free(&e);
	sd_bus_message_unref(m);
	return r < 0 ? -1 : 0;
}

/*
 * get the sandbox information. looks for a "machine" names mach. If not
 * found attempt to start a service name svc.
 */
static int
get_sandbox(pam_handle_t * pamh, const char *mach, const char *svc,
	    sandbox_info_t * info)
{
	sd_bus *bus = NULL;
	int r;
	int service_queued = 0;
	int retry = SANDBOX_RETRY_COUNT;
	const struct timespec delay = { 0, SANDBOX_RETRY_DELAY };

	/*
	 * Connect to the system bus
	 */
	r = sd_bus_open_system(&bus);
	if (r < 0) {
		pam_syslog(pamh, LOG_ERR,
			   "Failed to connect to system bus: %s\n",
			   strerror(-r));
		return -1;
	}

	do {
		r = get_machine_info(pamh, bus, mach, info);
		if (r == 0)
			break;
		/* No device (ENXIO) is expected on 1st access to sandbox */
		if (r != -ENXIO)
			pam_syslog(pamh, LOG_ERR,
				   "get_machine_info failed - starting unit\n");
		if (!service_queued) {
			r = bus_start_unit(pamh, bus, svc);
			if (r < 0)
				pam_syslog(pamh, LOG_ERR,
					   "Failed to start service. remaining %d retries\n",
					   retry);
			else
				service_queued = 1;
		}
		nanosleep(&delay, NULL);
	} while (retry-- >= 0);
	sd_bus_unref(bus);
	if (retry < 0)
		return -1;
	else
		return 0;
}

/* set the uts nodename so that we aren't
 * showing the nodename inherited from the
 * "machine-name" in systemd-nspawn. called
 * after switching to new namespace.
 */
static int sandbox_set_hostname(pam_handle_t *pamh, const char *hostname)
{
	int r;
	char oldname[MAXHOSTNAMELEN + 1];
	r = gethostname(oldname, sizeof(oldname));
	if (r < 0 || strncmp(oldname, hostname, sizeof(oldname)) != 0) {
		r = sethostname(hostname, strlen(hostname));
		if (r < 0)
			pam_syslog(pamh, LOG_ERR, "Failed to set hostname to %s:%s", hostname, strerror(errno));
	}
	return r;
}
