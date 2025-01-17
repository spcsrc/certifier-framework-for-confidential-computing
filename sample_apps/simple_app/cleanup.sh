#!/bin/bash
# ##############################################################################
# Helper script to clean-up running processes after a successful / failed
# execution of run_example.sh
#
# Arguments: <pid> of process to not kill (our calling process' pid)
# ##############################################################################

Me=$(basename "$0")

# Init to an illegal value, so we filter out nothing if $1 is not provided
parent_pid=-99999
if [ $# -eq 1 ]; then parent_pid="$1"; fi

# ##############################################################################
function cleanup_stale_procs() {

    # Find and kill processes that may be running. We cannot use pgrep to find the
    # pid, and / or use 'pgrep --signal pkill' to kill such processes, because in
    # case the process does not exist, 'pgrep' will exit with $rc=1. This will cause
    # this entire script to abort prematurely before cleanup is finished.
    for procname in simpleserver example_app.exe run_example.sh
    do
        # shellcheck disable=SC2046,SC2009
        if [ $(ps -ef | grep -E "${procname}" \
            | grep -c -v -w -E "grep|vi|vim|${parent_pid}") -ne 0 ];
        then
            echo
            ps -ef | grep -E "${procname}" | grep -v -w -E 'grep|vi|vim'
            set -x
            pid=$(pgrep "${procname}")

            # shellcheck disable=SC2086
            # kill -9 ${pid}
            kill -s SIGKILL ${pid} || :
            set +x
        fi
    done
}

# shellcheck disable=SC2086
if [ ${parent_pid} -gt 0 ]; then
   echo "${Me}: Cleanup stale processes (parent_pid=${parent_pid}) ..."
fi
cleanup_stale_procs
exit 0
