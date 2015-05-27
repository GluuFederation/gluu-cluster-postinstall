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
import subprocess
import sys

PROMETHEUS_CONF = '''
# Global default settings.
global {
 scrape_interval: "15s"     # By default, scrape targets every 15 seconds.
 evaluation_interval: "15s" # By default, evaluate rules every 15 seconds.

 # Attach these extra labels to all timeseries collected by this Prometheus instance.
 labels: {
   label: {
     name: "monitor"
     value: "gluu-monitor"
   }
 }

 # Load and evaluate rules in this file every 'evaluation_interval' seconds. This field may be repeated.
 #rule_file: "prometheus.rules"
}

# A job definition containing exactly one endpoint to scrape: Here it's prometheus itself.
job: {
 # The job name is added as a label `job={job-name}` to any timeseries scraped from this job.
 name: "prometheus"
 # Override the global default and scrape targets from this job every 5 seconds.
 scrape_interval: "5s"

 # Let's define a group of targets to scrape for this job. In this case, only one.
 target_group: {
   # These endpoints are scraped via HTTP.
   target: "http://localhost:9090/metrics"
 }
}
'''

DOCKER_CONF_FILE = '/etc/default/docker'
MINION_CONF_FILE = '/etc/salt/minion'
PROMETHEUS_CONF_FILE = "/etc/gluu/prometheus/prometheus.conf"


def run(command, exit_on_error=True, cwd=None):
    try:
        return subprocess.check_output(
            command, stderr=subprocess.STDOUT, shell=True, cwd=cwd)
    except subprocess.CalledProcessError, e:
        if exit_on_error:
            sys.exit(e.returncode)
        else:
            raise


def configure_docker():
    print "updating docker configuration"
    docker_conf = 'DOCKER_OPTS="-H tcp://0.0.0.0:2375 -H unix:///var/run/docker.sock"'
    with open(DOCKER_CONF_FILE, 'a') as fp:
        fp.write('\n' + docker_conf)

    print "restarting docker"
    run('service docker restart')
    print "docker configuration has been updated"


def configure_salt(master_ipaddr):
    print "updating salt-minion configuration"
    minion_conf = 'master: ' + master_ipaddr

    with open(MINION_CONF_FILE, 'a') as fp:
        fp.write('\n' + minion_conf)

    print "restarting salt-minion"
    run('service salt-minion restart')
    print "salt-minion configuration has been updated"


def configure_weave(host_type, master_ipaddr):
    print "updating weave"
    run('weave setup')
    run('weave launch ' + master_ipaddr)
    print "weave has been updated"


def configure_prometheus():
    print "updating prometheus"
    run('mkdir -p /etc/gluu/prometheus')

    with open(PROMETHEUS_CONF_FILE, 'w') as fp:
        fp.write(PROMETHEUS_CONF)

    volumes = "{}:/etc/prometheus/prometheus.conf".format(PROMETHEUS_CONF_FILE)
    cid_file = "/var/run/prometheus.cid"
    run('docker run -d --name=prometheus -v {} --cidfile="{}" prom/prometheus'.format(volumes, cid_file))
    print "prometheus has been updated"


def main():
    host_type = raw_input("Enter host type (ex. master or consumer) : ").lower()

    if host_type not in ['master', 'consumer']:
        print 'Info: unsupported host type, exiting'
        sys.exit(1)

    master_ipaddr = raw_input("Enter MASTER_IPADDR (ex xxx.xxx.xxx.xxx) : ")

    configure_docker()
    configure_salt(master_ipaddr)
    configure_weave(host_type, master_ipaddr)
    if host_type == 'master':
        configure_prometheus()
    sys.exit(0)


if __name__ == '__main__':
    main()
