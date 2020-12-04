Executable files in this directory are executed by `run-parts`, on request of
`cli-sandbox --create`, as the final step in the creation of a user sandbox.

Execution takes place in the root namespaces, with the following notable
additions to the environment:

 * `CLI_SANDBOX_NSPAWN_TEMPLATE` - path of the sandbox's systemd.nspawn settings file
 * `CLI_SANDBOX_ROOT` - path of the sandbox's filesystem root
 * `CLI_SANDBOX_TOP` - path of the sandbox's working directory (containing the root)
 * `CLI_SANDBOX_UID` - UID of the user we are creating the sandbox for
 * `CLI_SANDBOX_USER` - name of the user we are creating the sandbox for
