#!/usr/bin/env python

import subprocess

from cloudify import ctx
from cloudify.state import ctx_parameters as inputs
from cloudify.exceptions import OperationRetry


WAVE_UTILS_CMD = [
  'sudo curl -L git.io/weave -o /usr/local/bin/weave',
  'sudo chmod a+x /usr/local/bin/weave',
  'sudo curl -L git.io/scope -o /usr/local/bin/scope',
  'sudo chmod a+x /usr/local/bin/scope',
  '/usr/local/bin/scope launch',
]


def execute_command(_command):

    ctx.logger.info('_command {0}.'.format(_command))

    subprocess_args = {
        'args': _command.split(),
        'stdout': subprocess.PIPE,
        'stderr': subprocess.PIPE
    }

    ctx.logger.info('subprocess_args {0}.'.format(subprocess_args))

    process = subprocess.Popen(**subprocess_args)
    output, error = process.communicate()

    ctx.logger.info('command: {0} '.format(_command))
    ctx.logger.info('output: {0} '.format(output))
    ctx.logger.info('error: {0} '.format(error))
    ctx.logger.info('process.returncode: {0} '.format(process.returncode))

    if process.returncode:
        ctx.logger.error('Running `{0}` returns error.'.format(_command))
        return False

    return output


def set_hostname():
    hostname = execute_command('hostname')
    # Re-try ``hostname`` command in case it failed
    if hostname is False:
        raise OperationRetry('Re-try running {0}'.format('hostname'))

    # Check ``hostname`` output
    hostname = hostname.rsplit('\n')
    if hostname:
        ctx.instance.runtime_properties['hostname'] = hostname[0]

    # In case ``hostname`` is empty then re-try again
    else:
        raise OperationRetry('hostname output is empty !!, re-try again')


if __name__ == '__main__':

    # echo 1 | sudo tee /proc/sys/net/bridge/bridge-nf-call-iptables
    status = execute_command(
        "sudo sysctl net.bridge.bridge-nf-call-iptables=1")
    if status is False:
        raise OperationRetry('Failed to set bridge-nf-call-iptables')

    # Set ``hostname`` as runtime properties for the current node
    set_hostname()

    private_master_ip = inputs.get('master_ip')
    public_master_ip = inputs.get('public_master_ip')
    bootstrap_token = inputs.get('bootstrap_token')
    bootstrap_hash = inputs.get('bootstrap_hash')
    master_port = inputs.get('master_port')

    # Set the ``public_master_ip`` as runtime property
    ctx.instance.runtime_properties['public_master_ip'] = public_master_ip

    # Join the cluster.
    join_command = (
        'sudo kubeadm join --token {0} --discovery-token-ca-cert-hash {1} '
        '{2}:{3} --skip-preflight-checks'
        .format(bootstrap_token, bootstrap_hash,
                private_master_ip, master_port)
    )
    ctx.logger.info("Join by {}".format(repr(join_command)))
    status = execute_command(join_command)
    if not status:
        raise OperationRetry(
            'Failed to execute join cluster command {0}'.format(join_command))

    # Install weave-related utils
    for cmd in WAVE_UTILS_CMD:
        status = execute_command(cmd)
        if status is False:
            raise OperationRetry('Failed to execute {0} command'.format(cmd))
