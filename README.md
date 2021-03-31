# rtcpxr_collector
A python library for Collecting RTCP-XR (RFC 3611) SIP quality packets

## Predecessor
Much thank to the project at: https://github.com/pbertera/vq-collector
The core concepts and processing core were taken from there. 
Most code has been refactored and stripped down.

# Basic usage
This is meant to be part of a larger project (hence a library.)
I highly suggest you configure your phones to send to your collector 
with the "name" set to the mac address of the handset. This is the only way to uniquely identify a handset.

To run the code with all the defaults:
```
#!/usr/bin/python3

from rtcpxr_collector import vqcollector
vqs = vqcollector.CollectorServer()
vqs.listen()
```

Generally you will use a custom handler, so here's an example:
```
#!/usr/bin/python3
import datetime
from rtcpxr_collector import vqcollector

def logHandler(r):
    print("%s %s %s CQ:%s LQ:%s Local:%s Remote:%s"%(datetime.datetime.now(), 
                                             r['Handset']['MAC'],
                                             r['CallID'],
                                             r['QualityEst']['MOSCQ'],
                                             r['QualityEst']['MOSLQ'],
                                             "%s %s"%(r['LocalID']['name'],r['LocalID']['desc']),
                                             "%s %s"%(r['RemoteID']['name'],r['RemoteID']['desc']) ))

vqs = vqcollector.CollectorServer(handler=logHandler)
vqs.listen()
```

Maybe you want to run on a non-stadard IP or port:
```
#!/usr/bin/python3

from rtcpxr_collector import vqcollector
vqs = vqcollector.CollectorServer(local_ip=10.10.10.15, port=5061)
vqs.listen()
```

