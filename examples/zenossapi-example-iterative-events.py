#!/usr/local/env python

from zenoss import Zenoss

HOST = 'https://server.domain.com'
CERT = '/path/to/cert.pem'
SSL_VERIFY = False

# create Zenoss instance
zenoss = Zenoss(host = HOST, cert = CERT, ssl_verify = SSL_VERIFY)

#print zenoss.get_event_detail("e4115bd1-2290-a6f3-11e6-0568d53d97e4")
events =  zenoss.get_events(
        limit = 10000,
        params = dict(severity=[5], eventState=[0,1,3,4,5,6], Systems='/ReleaseEnvironment/Live')
            )

print 'len(events):', len(events)
