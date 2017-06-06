python-zenoss ![Build Status](https://travis-ci.org/iamseth/python-zenoss.png)
=============

Python module to work with the Zenoss JSON API (Fork)


Installation
=============

### PyPi
```bash
pip install zenoss-fork
```

### Manually
```bash
python setup.py test
python setup.py build
sudo python setup.py install
```


Usage
=============

### List all devices in Zenoss
```python
from zenoss import Zenoss

zenoss = Zenoss('http://zenoss:8080/', username = 'admin', password = 'password')

for device in zenoss.get_devices()['devices']:
    print(device['name'])
```

### Get event detail (use client cert for authentication)
```python
from zenoss import Zenoss

# create Zenoss instance (ssl_verify = False is optional)
zenoss = Zenoss('https://zenoss.host.com', cert = '/home/user/cert.pem', ssl_verify = False)

print zenoss.get_event_detail("e4115bd1-2290-a6f3-11e6-0568d53d97e4")
```
