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
import subprocess
import sys
import time
from getpass import getpass

PROMETHEUS_CONF = '''# Global default settings.
global {
    # By default, scrape targets every 15 seconds.
    scrape_interval: "15s"

    # By default, evaluate rules every 15 seconds.
    evaluation_interval: "15s"

    # Attach these extra labels to all timeseries collected by
    # this Prometheus instance.
    labels: {
        label: {
            name: "monitor"
            value: "gluu-monitor"
        }
    }

    # Load and evaluate rules in this file every 'evaluation_interval' seconds.
    # This field may be repeated.
    #rule_file: "prometheus.rules"
}

# A job definition containing exactly one endpoint
# to scrape: Here it's prometheus itself.
job: {
    # The job name is added as a label `job={job-name}` to any timeseries
    # scraped from this job.
    name: "prometheus"

    # Override the global default and scrape targets from this job
    # every 5 seconds.
    scrape_interval: "5s"

    # Let's define a group of targets to scrape for this job.
    # In this case, only one.
    target_group: {
        # These endpoints are scraped via HTTP.
        target: "http://localhost:9090/metrics"
    }
}'''

MINION_CONF_FILE = '/etc/salt/minion'
PROMETHEUS_CONF_FILE = "/etc/gluu/prometheus/prometheus.conf"

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
        logger.error(exc)
        logger.error(exc.output)
        if exit_on_error:
            sys.exit(exc.returncode)
        else:
            raise


def configure_docker(host, password):
    logger.info("Configuring secure docker daemon protected by TLS")

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

    docker_conf = 'DOCKER_OPTS="--tlsverify ' \
                  '--tlscacert=/etc/docker/ca.pem ' \
                  ' --tlscert=/etc/docker/server-cert.pem ' \
                  '--tlskey=/etc/docker/server-key.pem ' \
                  '-H tcp://0.0.0.0:2375 ' \
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

    with open(PROMETHEUS_CONF_FILE, 'w') as fp:
        fp.write(PROMETHEUS_CONF)

    volumes = "{}:/etc/prometheus/prometheus.conf".format(PROMETHEUS_CONF_FILE)
    cid_file = "/var/run/prometheus.cid"
    run('rm -f ' + cid_file)
    time.sleep(30)
    run('docker pull prom/prometheus')
    run('docker run -d --name=prometheus -v {} --cidfile="{}" '
        'prom/prometheus'.format(volumes, cid_file))
    logger.info("prometheus has been updated")


def main():
    host_type = raw_input(
        "Enter host type (ex. master or consumer) : ").lower()

    if host_type not in ['master', 'consumer']:
        logger.warn('Unsupported host type; exiting')
        sys.exit(1)

    master_ipaddr = raw_input("Enter MASTER_IPADDR (ex xxx.xxx.xxx.xxx) : ")

    host = raw_input("IP address of this server: ")
    password = getpass("Password for TLS certificate: ")
    password_confirm = getpass("Re-type password for TLS certificate: ")

    if password != password_confirm:
        logger.warn("Password and password confirmation "
                    "doesn't match; exiting")
        sys.exit(0)

    configure_docker(host, password)
    configure_salt(master_ipaddr)
    configure_weave()
    if host_type == 'master':
        configure_prometheus()

    logger.info("Installation finished")
    sys.exit(0)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Installation stopped by user")
