# node-passivedns

## About

Passive DNS monitoring as a node-addon.  It monitors pcap devices
for DNS traffic. 

Monitoring is done in a separate thread with its own event loop 
to minimize performance impact.

## Installation

npm install passivedns

## Usage

```
var PassiveDns = require('passivedns');

var p = new PassiveDns({
    interface: 'eth0'
});

p.on('data', function(data) {

  // dns object
  // { answer: 'ie-in-f138.1e100.net.',
  //   timestamp: 1375910292,
  //   ttl: 75235,
  //   query: '138.142.125.74.in-addr.arpa.',
  //   type: 'PTR',
  //   class: 'IN',
  //   server: '10.0.1.1',
  //   src: '10.0.1.17' 
  //   } 
});

p.start();

// p.stop(); //  stop collecting
```

## Credits

Code is based heavily on passivedns by Edward Bjarte Fjellskål
http://github.com/gamelinux/passivedns

## TODO
- mad code cleanup
