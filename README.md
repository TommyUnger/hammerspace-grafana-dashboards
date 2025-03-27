# grafana dashboards for Hammerspace
Grafana dashboards for use with the prometheus exporters built into Hammerspace

The 5.1 directory is used for Hammerspace releases 5.1 and newer
The 5.0 directory is used for Hammerspace release 5.0

Original dashboards are exported from Grafana 11.4


# Overview

Typical deployment has Prometheus and Grafana running on the same node.
Grafana talks to Prometheus so traffic between the two stays within the node in
this configuration.

Prometheus reaches out to each of the exporters on the nodes to be monitored
and pulls the metrics, storing the metrics in its time series DB.  Grafana
queries the Prometheus DB and generates the graphs.

The exporters are provided on the Hammerspace nodes, but do need to be enabled.

```
                            +--------------------------+
                            |     Monitoring Node      |
                            |          Grafana         |
                            |             |            |
                            |        Prometheus        |
                            |             |            |
                            +-------------+------------+
                                          |
                                          |
                                          |
               Hammerspace1               |             Hammerspace2
                  Anvil 1          <------|------>         Anvil 1
           Prometheus Exporters           |          Prometheus Exporters
                                          |
                                          |
                Hammerspace1              |              Hammerspace2
                  Anvil 2          <------|------>         Anvil 2
           Prometheus Exporters           |          Prometheus Exporters
                                          |
                                          |
                                          |
                Hammerspace1              |              Hammerspace2
                   DSX 1           <------|------>          DSX 1
           Prometheus Exporters           |          Prometheus Exporters
                                          |
                                          |
                    ...                   |                  ...
                                          |
                                          |
                Hammerspace1              |              Hammerspace2
                   DSX $n          <------|------>          DSX $n
           Prometheus Exporters           |          Prometheus Exporters

```

# Configuration / install scripts

For some linux distributions or docker/podmain there are scripts that will
install the needed packages to run prometheus and grafana on the same node. Use
these as documents for setting up your own.  See the installers/


# Configuring prometheus and grafana

The installers/config.py script will assist setting up grafana dashboards as
well as generating a prometheus config file.  Once the install script is run
all dependencies needed to run this config script will be in place on the
prometheus/grafana node.  Build a default config by
```
cd installers
./config.py --sample_config
```

This will generate a `config_tooling.ini` file.

Edit this and add any anvil IPs and keep open for the following steps

## Setting up grafana with config.py tool

### Login to Grafana, generate service account token

Go to http://<grafana_host>:3000/ and login to grafana, default is typically admin/admin and set your own password

Go to _Administration -> Users and Access -> Service Accounts_ and add a service account with _Admin_ role

Now click on the new service account, then click _Add service account token_ (a blue button).
Add the generated token in to the `token` in `config_tooling.ini` file generated in the previous step

### Upload dashboards

To set up the prometheus data source and auto upload the hammerspace provided dashboards, use
```
$ ./config.py --dashboards
```

If you already have the dashboards installed this method will prompt you on each of them to know if you would like to replace the current dashboard.  If you know you would like to replace any existing dashboard without prompting, use --force
```
$ ./config.py --dashboards --force
```

## Grafana: Add 3rd party dashboards

In grafana, click _New -> Import_

To add node exporter, use id method with id 1860


## Setting up grafana manually

### Setup data source

Under the settings icon, add a prometheus data source. It shows a default URL
of http://localhost:9090, assuming promethus is running on the same host, that
is the correct address but you have to type this in. Leave the name as the
default, "Prometheus".

### Add (or update) Hammerspace dashboards

If you have existing hammerspace dashboards, please delete them.  if you have
made changes you may want to do a dashboards_page->settings->save_as and save
with a new name then delete.

click New->import.  Use the upload from my computer.  Sadly they must each be
added indvidually.  On the second page you MUST select the prometheus data
source configured above.


## Setting up Prometheus

Add the hostname or IP ip address associated with the cluster ip (not host ip)
to the config_tooling.ini file, each with it's own `hammerspaceX = <host>`
entry.  Make sure to use an hostname/IP that is configured for management and
has port 443 open, a data only configured interface will throw an error.

Generate a prometheus.yml file with
```
./config.py --prometheus
```

Copy this file into your prometheus server, which if you are following this guide is:
```
cp prometheus.yml /etc/prometheus/
systemctl restart prometheus
```

Log into the active anvil and enable exporters on the cluster with the following command: `cluster-config --prometheus-exporters-enable`

## Troubleshooting

In grafana,

go to the global datasources, select Prometheus.
1) Verify it is the default data source
2) At the bottom do _Save & Test_ to make sure grafana can talk to prometheus

Go to a dashboard that is having issues, on newer versions of grafna click _Edit_ on the top right corner, click _Settings -> Variables_
1) Ensure the DS_PROMETHEUS has the value "Prometheus" in it, this is the name of the data source to use.
2) Work through each variable and make sure it has the Prometheus data source selected.. these should come from $DS_PROMETHEUS

Check that data is arriving at prometheus, it can be reached at http://<grafana_prometheus_hostname>:9090


See grafana logs, may be in /var/log/grafana/* may also change log in grafana.ini to `level = debug`
