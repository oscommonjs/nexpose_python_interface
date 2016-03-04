Nexpose Python Interface
=====
A simple python interface to interact with the Nexpose API.

### Getting Started:
```python
from nexpose import Nexpose
user_vars = {
    "nexpose_user": "<username>",
    "nexpose_passwd": "<password>",
    "nexpose_ip": "<ip_address>",
    "nexpose_port": "3780"
} 

nex = Nexpose(user_vars)
```

### Create Site:
* The hosts_strings variable can support a comma separted list of hosts or a /24 CIDR.
* The template_id is the Nexpose scan type.
```python
nex.create_site(site_name, hosts_string, template_id)
```

### List Site:
```python
nex.list_site()
```

### Delete Site:
```python
nex.delete_site()
```
* Optionally you may pass a siteID to delete_site that is not part of the current session.

### Scan Site:
```python
nex.scan_site()
```
* Optionally you may pass a siteID to scan_site that is not part of the current session.

### Check Scan Staus:
```python
nex.check_scan()
```
* Optionally you may pass a siteID to check_scan that is not part of the current session.

### Generate Report:

