#!/usr/local/env python

from zenoss import Zenoss, EventState, EventSeverity
import json

# create Zenoss instance
zenoss = Zenoss(
            host = 'https://zenoss.host.com',
            cert = '/path/to/cert.pem',
            ssl_verify = False
            )

# get events
params = dict(
        eventState = [EventState.new],
        severity = [EventSeverity.critical],
        Systems = '/ReleaseEnvironment/Live'
        )
events = zenoss.get_events(limit=1, sort='firstTime', dir='ASC', params=params, detailFormat=False)

# display JSON
print json.dumps(events, indent=2)
