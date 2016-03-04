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
### Create Site
```python
nex.create_site(site_name, hosts_string, template_id)
```
