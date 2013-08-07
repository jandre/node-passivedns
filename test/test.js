
var PassiveDns = require('../lib/index');

var dns = new PassiveDns({
  interface: "eth0",
  pcap_filter: "port 53"
});

dns.on('data',function(data) {

  console.log("XXX got data", data);

});

dns.start();

setTimeout(function() {
  console.log("XXX STOPPING");
  dns.stop();
}, 5000);
