
try {
  PassiveDns = require('../build/Debug/passivedns.node').PassiveDns;
} catch (err) {
  PassiveDns = require('../build/Release/passivedns.node').PassiveDns;
}

var dns = new PassiveDns(function(data) {

  console.log("XXX got data", data);

});

dns.start();

setTimeout(function() {
  console.log("XXX STOPPING");
  dns.stop();
}, 5000);
