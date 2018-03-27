#!/usr/bin/env python
#
# Copyright (c) 2017 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import sys
import os
import platform
import socket
import ssl
import subprocess
import tempfile
import os.path

from cloudify import ctx
from cloudify.state import ctx_parameters as inputs
from cloudify import manager
from cloudify_rest_client.exceptions import CloudifyClientError
from cloudify.utils import exception_to_error_cause
from cloudify.exceptions import (
    HttpException,
    NonRecoverableError,
    OperationRetry
)

MOUNT = ('#!/bin/bash\n' +
         'echo $@ >> /var/log/mount-calls.log\n' +
         '/usr/bin/cfy-go kubernetes $1 $2 $3 -deployment "{0}" ' +
         '-instance "{1}" -tenant "{2}" -password "{3}" -user "{4}" ' +
         '-host "{5}" -agent-file "{6}"')

CERT_CLOUDIFY_FILE = '/etc/pki/ca-trust/source/anchors/cloudify.crt'
CERT_BUNDLE_FILE = '/etc/pki/tls/certs/ca-bundle.crt'

CERT_CLOUDIFY_HEADER = '# cloudify certificate'


def generate_traceback_exception():
    _, exc_value, exc_traceback = sys.exc_info()
    response = exception_to_error_cause(exc_value, exc_traceback)
    return response


def download_service(service_name):
    service_path = "/usr/bin/" + service_name
    if not os.path.isfile(service_path):
        try:
            cfy_binary = ctx.download_resource(
                'resources/{}'.format(service_name))
        except HttpException:
            raise NonRecoverableError(
                '{} binary not in resources.'.format(service_name))
        ctx.logger.debug('{} downloaded.'.format(service_name))
        if execute_command(['sudo', 'cp', cfy_binary, service_path]) is False:
            raise NonRecoverableError("Can't copy {}.".format(service_path))
    # fix file attributes
    if execute_command(['sudo', 'chmod', '555', service_path]) is False:
        raise NonRecoverableError("Can't chmod {}.".format(service_path))
    if execute_command(['sudo', 'chown', 'root:root', service_path]) is False:
        raise NonRecoverableError("Can't chown {}.".format(service_path))
    ctx.logger.debug('{} attributes fixed'.format(service_name))


def execute_command(command, extra_args=None):

    ctx.logger.debug('command: {0}.'.format(repr(command)))

    subprocess_args = {
        'args': command,
        'stdout': subprocess.PIPE,
        'stderr': subprocess.PIPE
    }
    if extra_args is not None and isinstance(extra_args, dict):
        subprocess_args.update(extra_args)

    ctx.logger.debug('subprocess_args {0}.'.format(subprocess_args))

    process = subprocess.Popen(**subprocess_args)
    output, error = process.communicate()

    ctx.logger.debug('command: {0} '.format(repr(command)))
    ctx.logger.debug('output: {0} '.format(output))
    ctx.logger.debug('error: {0} '.format(error))
    ctx.logger.debug('process.returncode: {0} '.format(process.returncode))

    if process.returncode:
        ctx.logger.error('Running `{0}` returns {1} error: {2}.'
                         .format(repr(command), process.returncode,
                                 repr(error)))
        return False

    return output


def start_check(service_name):
    status_string = ''
    systemctl_status = execute_command(['sudo', 'systemctl', 'status',
                                        '{}.service'.format(service_name)])
    if not isinstance(systemctl_status, basestring):
        raise OperationRetry(
            'check sudo systemctl status {}.service'.format(service_name))
    for line in systemctl_status.split('\n'):
        if 'Active:' in line:
            status = line.strip()
            zstatus = status.split(' ')
            ctx.logger.debug('{} status line: {}'
                             .format(service_name, repr(zstatus)))
            if len(zstatus) > 1:
                status_string = zstatus[1]

    ctx.logger.info('{} status: {}'.format(service_name, repr(status_string)))
    if 'active' != status_string:
        raise OperationRetry('Wait a little more.')
    else:
        ctx.logger.info('Service {} is started.'.format(service_name))


def get_instance_host(relationships, rel_type, target_type):
    for rel in relationships:
        if rel.type == rel_type or rel_type in rel.type_hierarchy:
            if target_type in rel.target.node.type_hierarchy:
                return rel.target.instance
            instance = get_instance_host(rel.target.instance.relationships,
                                         rel_type, target_type)
            if instance:
                return instance
    return None


def update_host_address(host_instance, hostname, fqdn, ip, public_ip):
    ctx.logger.info('Setting initial Kubernetes node data')

    if not public_ip:
        public_ip_prop = host_instance.runtime_properties.get(
            'public_ip')
        public_ip_address_prop = host_instance.runtime_properties.get(
            'public_ip_address')
        public_ip = public_ip_prop or public_ip_address_prop or ip

    new_runtime_properties = {
        'name': ctx.instance.id,
        'hostname': hostname,
        'fqdn': fqdn,
        'ip': ip,
        'public_ip': public_ip
    }

    for key, value in new_runtime_properties.items():
        ctx.instance.runtime_properties[key] = value

    ctx.logger.info(
        'Finished setting initial Kubernetes node data.')


def setup_kubernetes_node_data_type():
    ctx.logger.debug(
        'Setup kubernetes node data '
        'type for deployment id {0}'.format(ctx.deployment.id))

    cfy_client = manager.get_rest_client()
    try:
        response = cfy_client.deployments.outputs.get(ctx.deployment.id)

    except CloudifyClientError as ex:
        ctx.logger.debug(
            'Unable to parse outputs for deployment'
            ' {0}'.format(ctx.deployment.id))

        raise OperationRetry('Re-try getting deployment outputs again.')

    except Exception:
        response = generate_traceback_exception()

        ctx.logger.error(
            'Error traceback {0} with message {1}'.format(
                response['traceback'], response['message']))

        raise NonRecoverableError("Failed to get outputs")

    else:
        dep_outputs = response.get('outputs')
        ctx.logger.debug('Deployment outputs: {0}'.format(dep_outputs))
        node_data_type = dep_outputs.get('deployment-node-data-type')

        if node_data_type:
            os.environ['CFY_K8S_NODE_TYPE'] = node_data_type

        else:
            os.environ['CFY_K8S_NODE_TYPE'] =\
                'cloudify.nodes.ApplicationServer.kubernetes.Node'


def setup_certificate_authority(linux_distro):
    # certificate logic
    if not linux_distro:
        distro, _, _ = \
            platform.linux_distribution(full_distribution_name=False)
        linux_distro = distro.lower()

    ctx.logger.info("Set certificate as trusted")

    # cert config
    _, temp_cert_file = tempfile.mkstemp()

    with open(temp_cert_file, 'w') as cert_file:
        cert_file.write("{0}\n".format(CERT_CLOUDIFY_HEADER))
        try:
            cert_file.write(ssl.get_server_certificate((
                cfy_host, cfy_ssl_port)))
        except Exception as ex:
            ctx.logger.error("Check https connection to manager {}."
                             .format(str(ex)))

    if 'centos' in linux_distro:
        execute_command([
            'sudo', 'cp', temp_cert_file, CERT_CLOUDIFY_FILE
        ])
        execute_command([
            'sudo', 'update-ca-trust', 'extract'
        ])
        execute_command([
            'sudo', 'bash', '-c',
            'cat {0} >> {1}'.format(temp_cert_file, CERT_BUNDLE_FILE)
        ])
    else:
        raise NonRecoverableError('Unsupported platform.')


if __name__ == '__main__':

    plugin_directory = inputs.get('plugin_directory',
                                  '/usr/libexec/kubernetes/kubelet-plugins/'
                                  'volume/exec/cloudify~mount/')

    host_instance = get_instance_host(ctx.instance.relationships,
                                      'cloudify.relationships.contained_in',
                                      'cloudify.nodes.Compute')
    if not host_instance:
        raise NonRecoverableError('Ambiguous host resolution data.')

    cloudify_agent = host_instance.runtime_properties.get('cloudify_agent', {})

    linux_distro = cloudify_agent.get('distro')
    cfy_host = cloudify_agent.get('broker_ip')
    cfy_ssl_port = cloudify_agent.get('rest_port')
    agent_name = cloudify_agent.get('name')

    cfy_user = inputs.get('cfy_user', 'admin')
    cfy_pass = inputs.get('cfy_password', 'admin')
    cfy_tenant = inputs.get('cfy_tenant', 'default_tenant')
    agent_user = inputs.get('agent_user', 'centos')
    full_install = inputs.get('full_install', 'all')

    cfy_host_full = cfy_host if not cfy_ssl_port else (
        "https://" + cfy_host + ":" + str(cfy_ssl_port)
    )

    agent_file = "/root" if agent_user == "root" else (
        "/home/" + agent_user
    )

    if not os.path.isfile(os.path.join(plugin_directory, 'mount')):
        # volume mount support
        ctx.logger.info("Update create cfy-mount")
        _, temp_mount_file = tempfile.mkstemp()

        with open(temp_mount_file, 'w') as outfile:
            outfile.write(MOUNT.format(
                ctx.deployment.id,
                ctx.instance.id,
                cfy_tenant,
                cfy_pass,
                cfy_user,
                cfy_host_full,
                "{}/.cfy-agent/{}.json".format(agent_file, agent_name)))

        execute_command(['sudo', 'mkdir', '-p', plugin_directory])
        execute_command(['sudo', 'cp', temp_mount_file,
                         os.path.join(plugin_directory, 'mount')])
        execute_command(['sudo', 'chmod', '555',
                         os.path.join(plugin_directory, 'mount')])
        execute_command(['sudo', 'chown', 'root:root',
                         os.path.join(plugin_directory, 'mount')])

    if ctx.operation.retry_number == 0:
        # Allow user to provide specific values.
        update_host_address(
            host_instance=host_instance,
            hostname=inputs.get('hostname', socket.gethostname()),
            fqdn=inputs.get('fqdn', socket.getfqdn()),
            ip=inputs.get('ip', ctx.instance.host_ip),
            public_ip=inputs.get('public_ip'))

        # setup certificate logic
        setup_certificate_authority(linux_distro)

    # download cfy-go tools
    if full_install != "loadbalancer":
        # Update the os environment variable to be used by the cfy-go diag
        setup_kubernetes_node_data_type()

        # Download cfy-go service
        download_service("cfy-go")

        # Run the diag command with option ``-node`` which check the
        # kubernetes nodes
        try:
            output = execute_command([
                '/usr/bin/cfy-go', 'status', 'diag',
                '-node', '-deployment', ctx.deployment.id,
                '-tenant', cfy_tenant, '-password', cfy_pass,
                '-user', cfy_user, '-host', cfy_host_full,
                '-agent-file', "{}/.cfy-agent/{}.json"
                .format(agent_file, agent_name)])
            ctx.logger.info("Diagnostic: {}".format(output))

        except Exception:
            response = generate_traceback_exception()

            ctx.logger.error(
                'Error traceback {0} with message {1}'.format(
                    response['traceback'], response['message']))

            raise NonRecoverableError("Failed to run daig command")
