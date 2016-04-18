#!/usr/local/bin/python2.7

from zenoss import Zenoss

# create Zenoss instance
zenoss = Zenoss(
            host = 'https://zenoss.host.com',
            cert = '/home/user/cert.pem',
            ssl_verify = False
            )

print zenoss.get_event_detail("e4115bd1-2290-a6f3-11e6-0568d53d97e4")
