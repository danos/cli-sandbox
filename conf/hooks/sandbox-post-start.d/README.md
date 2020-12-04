Executable files in this directory are executed by `run-parts` by means of an
`ExecStartPost` attribute in `cli-sandbox@.service`.

Execution takes place in the root namespaces after `systemd-nspawn` notifies
that the sandbox init process has been started.

The following notable variables are present in the environment:

 * `CLI_SANDBOX_NSPAWN_TEMPLATE` - path of the sandbox's systemd.nspawn settings file
 * `CLI_SANDBOX_ROOT` - path of the sandbox's filesystem root
 * `CLI_SANDBOX_TOP` - path of the sandbox's working directory (containing the root)
 * `CLI_SANDBOX_UID` - UID of the user we are creating the sandbox for
 * `CLI_SANDBOX_USER` - name of the user we are creating the sandbox for
