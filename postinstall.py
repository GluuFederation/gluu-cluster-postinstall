# -*- coding: utf-8 -*-
# The MIT License (MIT)
#
# Copyright (c) 2015 Gluu
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import logging
import os
import socket
import subprocess
import sys
import time
from getpass import getpass

PROMETHEUS_CONF = '''# Global default settings.
global:
  scrape_interval: 15s     # By default, scrape targets every 15 seconds.
  evaluation_interval: 15s # By default, evaluate rules every 15 seconds.

  # Attach these extra labels to all timeseries collected by this
  # Prometheus instance.
  labels:
    monitor: 'gluu-monitor'

  # Load and evaluate rules in this file every 'evaluation_interval' seconds.
  # This field may be repeated.
  # rule_files:
  #   - 'prometheus.rules'

scrape_configs:
  # A job definition containing exactly one endpoint to scrape:
  # Here it's prometheus itself.
  - job_name: 'prometheus'
    scrape_interval: 15s
    scrape_timeout: 30s
    target_groups:
      - targets: ['localhost:9090']
'''

MINION_CONF_FILE = '/etc/salt/minion'
PROMETHEUS_CONF_FILE = "/etc/gluu/prometheus/prometheus.yml"

logger = logging.getLogger("postinstall")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
fmt = logging.Formatter('[%(levelname)s] %(message)s')
ch.setFormatter(fmt)
logger.addHandler(ch)


def run(command, exit_on_error=True, cwd=None):
    try:
        return subprocess.check_output(
            command, stderr=subprocess.STDOUT, shell=True, cwd=cwd)
    except subprocess.CalledProcessError as exc:
        if exit_on_error:
            logger.error(exc)
            logger.error(exc.output)
            sys.exit(exc.returncode)


def configure_docker(host, password):
    logger.info("Configuring secure docker daemon protected by TLS")

    cert_exists = os.path.exists("/etc/docker/cert.pem")
    key_exists = os.path.exists("/etc/docker/key.pem")
    cacert_exists = os.path.exists("/etc/docker/ca.pem")

    if any([cert_exists, key_exists, cacert_exists]):
        while True:
            reconfigure = raw_input("Found existing docker certificate files. "
                                    "Re-configure? (y/n): ")
            reconfigure = reconfigure.lower()
            if reconfigure == "n":
                logger.info("Skipping docker configuration")
                return
            elif reconfigure == "y":
                break

    # cleanup existing ``/etc/docker`` directory
    run("mkdir -p /etc/docker")
    run("for f in `ls /etc/docker`; do rm /etc/docker/$f; done")

    logger.info("Generating Certificate Authority")
    run("openssl genrsa -aes256 -passout pass:{} "
        "-out ca-key.pem 2048".format(password))
    run("openssl req -new -x509 -days 365 -key ca-key.pem "
        "-passin pass:{} -sha256 -out ca.pem "
        "-subj '/C=NL/ST=./L=./O=./CN={}'".format(password, host))

    logger.info("Generating and signing server key")
    run("openssl genrsa -out server-key.pem 2048")
    run("openssl req -subj '/CN={}' -new -key server-key.pem "
        "-out server.csr".format(host))
    run("openssl x509 -req -days 365 -in server.csr -CA ca.pem "
        "-CAkey ca-key.pem -passin pass:{} "
        "-CAcreateserial -out server-cert.pem".format(password))

    logger.info("Generating and signing client key")
    run("openssl genrsa -out key.pem 2048")
    run("openssl req -subj '/CN=client' -new "
        "-key key.pem -out client.csr")
    run("echo 'extendedKeyUsage = clientAuth' > extfile.cnf")
    run("openssl x509 -req -days 365 -in client.csr -CA ca.pem "
        "-CAkey ca-key.pem -passin pass:{} -CAcreateserial "
        "-out cert.pem -extfile extfile.cnf".format(password))

    run("rm client.csr server.csr")
    run("chmod 0400 ca-key.pem key.pem server-key.pem")
    run("chmod 0444 ca.pem server-cert.pem cert.pem")

    generated_files = [
        "ca-key.pem", "ca.pem", "ca.srl", "cert.pem", "extfile.cnf",
        "key.pem", "server-cert.pem", "server-key.pem",
    ]
    for file_ in generated_files:
        run("cp {0} /etc/docker/{0}".format(file_))
        run("rm {}".format(file_))

    os_release = determine_os()
    if os_release == "centos":
        docker_conf = 'OPTIONS="--selinux-enabled --tlsverify ' \
                      '--tlscacert=/etc/docker/ca.pem ' \
                      ' --tlscert=/etc/docker/server-cert.pem ' \
                      '--tlskey=/etc/docker/server-key.pem ' \
                      '-H tcp://0.0.0.0:2376 ' \
                      '-H unix:///var/run/docker.sock"'
        run("echo '{}' >> /etc/sysconfig/docker".format(docker_conf))
    else:
        docker_conf = 'DOCKER_OPTS="--tlsverify ' \
                      '--tlscacert=/etc/docker/ca.pem ' \
                      ' --tlscert=/etc/docker/server-cert.pem ' \
                      '--tlskey=/etc/docker/server-key.pem ' \
                      '-H tcp://0.0.0.0:2376 ' \
                      '-H unix:///var/run/docker.sock"'
        run("echo '{}' >> /etc/default/docker".format(docker_conf))

    logger.info("Restarting docker")
    run('service docker restart')

    # wait docker daemon to run
    time.sleep(5)
    logger.info("docker with TLS protection has been configured")


def configure_salt(master_ipaddr):
    logger.info("Updating salt-minion configuration")
    minion_conf = 'master: ' + master_ipaddr

    with open(MINION_CONF_FILE, 'a') as fp:
        fp.write('\n' + minion_conf)

    logger.info("Restarting salt-minion")
    run('service salt-minion restart')
    logger.info("salt-minion configuration has been updated")


def configure_weave():
    logger.info("Updating weave; this may take a while")
    run('weave setup')
    logger.info("weave has been updated")


def configure_prometheus():
    logger.info("Updating prometheus; this may take a while")
    run('mkdir -p /etc/gluu/prometheus')

    conf_exists = os.path.exists(PROMETHEUS_CONF_FILE)
    if conf_exists:
        while True:
            overwrite = raw_input("Found existing prometheus config. "
                                  "Overwrite? (y/n): ")
            overwrite = overwrite.lower()
            if overwrite == "n":
                logger.info("Skipping prometheus configuration")
                return
            if overwrite == "y":
                break

    logger.info("Pulling prometheus image v0.15.1")
    run('docker pull prom/prometheus:0.15.1')
    time.sleep(30)

    with open(PROMETHEUS_CONF_FILE, 'w') as fp:
        fp.write(PROMETHEUS_CONF)
    volumes = "{}:/etc/prometheus/prometheus.yml".format(PROMETHEUS_CONF_FILE)

    run('docker rm -f prometheus', exit_on_error=False)
    run('docker run -d --name=prometheus -v {} '
        '-p 127.0.0.1:9090:9090 '
        'prom/prometheus:0.15.1'.format(volumes))
    logger.info("prometheus has been updated")


def validate_ip(addr):
    try:
        socket.inet_pton(socket.AF_INET, addr)
    except socket.error:
        return False
    else:
        return True


def main():
    print "=== Collecting configuration ==="
    host_type = raw_input(
        "Enter provider type (either 'master' or 'consumer') : ").lower()

    if host_type not in ['master', 'consumer']:
        logger.warn('Unsupported host type; exiting')
        sys.exit(1)

    master_ipaddr = raw_input("Enter master IP address (e.g. 10.10.10.10) : ")
    host = raw_input("IP address of this server: ")

    # validates IP addresses
    for addr in [master_ipaddr, host]:
        if not validate_ip(addr):
            logger.warn("IP address {} is not acceptable; "
                        "exiting".format(addr))
            sys.exit(1)

    password = getpass("Password for TLS certificate: ")
    password_confirm = getpass("Re-type password for TLS certificate: ")

    # validates passwords equality
    if password != password_confirm:
        logger.warn("Password and password confirmation "
                    "doesn't match; exiting")
        sys.exit(1)

    # openssl password requires 6 chars at minimum
    if len(password) < 6:
        logger.warn("Password must use 6 characters or more; exiting")
        sys.exit(1)

    print ""
    print "=== Configuration details ==="
    print "Provider type: {}".format(host_type)
    print "Master IP address: {}".format(master_ipaddr)
    print "Current server IP address: {}".format(host)
    print "TLS certificate password: {}".format("*" * len(password))

    print ""
    while True:
        proceed = raw_input("Proceed with current configuration? (y/n): ")
        proceed = proceed.lower()
        if proceed == "y":
            break
        elif proceed == "n":
            print ""
            logger.info("Installation stopped by user")
            sys.exit(0)
        else:
            continue

    configure_docker(host, password)
    configure_salt(master_ipaddr)
    configure_weave()
    if host_type == 'master':
        configure_prometheus()

    logger.info("Installation finished")
    sys.exit(0)


def determine_os():
    # default supported OS
    os_release = "ubuntu"

    with open("/etc/os-release") as fp:
        txt = fp.read()
        if "centos" in txt:
            os_release = "centos"
    return os_release


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print ""
        logger.info("Installation stopped by user")
