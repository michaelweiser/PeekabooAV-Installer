Kubernetes
==========

This directory provides a helm chart which implements a simple testing pipeline
setup for PeekabooAV including Cortex with FileInfo analyzer as analysis
backend. Postfix and rspamd are used for email ingress.

Installation
------------

Install using helm:

``` shell
helm upgrade --install --namespace pipeline --create-namespace pipeline . --values=values.yaml
```

**_NOTE:_**: Unfortunately there's a helm convention of prepending resource
names with the release name.
Unfortunately again, the chosen release name can not be automatically
interpolated in `values.yaml`.
So if you change the release name from `pipeline` to something else, be sure to
change all occurences of `pipeline` in `values.yaml` as well.

**_NOTE:_**: Helm's convention of prepending resource names with the release
name has an exception for when the release name starts with the chart name.
Therefore the chosen release name must not start with peekabooav, cortex,
mariadb, postfix or rspamd or the assumptions of the main` values.yaml` as well
as those of subcharts such as `cortex-setup` and `peekabooav` about service
names will no longer apply.
They can be overridden from the main `values.yaml`, of course, but a lot of
hassle can be avoided by naming the release carefully.
