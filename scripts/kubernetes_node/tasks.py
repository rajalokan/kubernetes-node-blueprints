#!/usr/bin/env python

from fabric.api import run
from cloudify import ctx
from cloudify.exceptions import RecoverableError


def check_fabric_return_code(out, command):
    ctx.logger.info('command: {0} '.format(command))
    ctx.logger.info('output: {0} '.format(out.succeeded))
    ctx.logger.info('error: {0} '.format(out.stderr))
    ctx.logger.info('return_code: {0} '.format(out.return_code))

    return_code = int(out.return_code)
    if return_code:
        ctx.logger.error(
            'Running `{0}` returns {1} error: {2}.'.format(
                repr(command), out.return_code, repr(out.stderr)))

        raise RecoverableError('Re-try running {0}'.format(command))

    ctx.logger.info('Command: {0} executed successfully'.format(command))
    return


def label_node(**kwargs):
    hostname = kwargs.get('hostname') or\
               ctx.instance.runtime_properties.get('hostname')

    labels = kwargs.get('labels')

    if labels:
        label_list = []
        for key, value in labels.items():
            label_pair_string = '%s=%s' % (key, value)
            label_list.append(label_pair_string)
        label_string = ' '.join(label_list)
        command = 'kubectl label nodes %s %s' % (hostname, label_string)
        result = run(command)
        check_fabric_return_code(result, command)


def stop_node(**kwargs):
    hostname = kwargs.get('hostname') or\
               ctx.instance.runtime_properties.get('hostname')

    command = 'kubectl drain {0}' \
              ' --ignore-daemonsets --force' \
              ' --delete-local-data'.format(hostname)
    result = run(command)
    check_fabric_return_code(result, command)


def delete_node(**kwargs):
    hostname = kwargs.get('hostname') or\
               ctx.instance.runtime_properties.get('hostname')

    command = 'kubectl delete no {0}'.format(hostname)
    result = run(command)
    check_fabric_return_code(result, command)
