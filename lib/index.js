
try {
  var _PassiveDns = require('../build/Release/passivedns.node').PassiveDns;
} catch (err) {
  var _PassiveDns = require('../build/Debug/passivedns.node').PassiveDns;
}

var EventEmitter = require('events').EventEmitter;
var util = require('util');
var _ =  require('underscore');

var FILTERS = {
  AAAA   :    0x0001,
  A      :    0x0002,
  PTR    :    0x0004,
  CNAME  :    0x0008,
  DNAME  :    0x0010,
  NAPTR  :    0x0020,
  RP     :    0x0040,
  SRV    :    0x0080,
  TXT    :    0x0100,
  SOA    :    0x0200,
  MX     :    0x0400,
  NS     :    0x0800,
  ALL    :    0x8000,
};

function lookup(filter) {
  var tmp = null;
  var filter = options.filter;
  tmp = FILTERS[filter];
  if (!tmp) {
      throw "Invalid filter:" + filter;
  }

  return tmp;
};

function validate(options) {

  if (!options.interface) 
    throw "You must supply a pcap interface (e.g. 'eth0')";

  options.pcap_filter = options.pcap_filter || "port 53";

  options.filter = options.filter || FILTERS.all;
  
  if (typeof options.filter == 'string') {
      options.filter = lookup(options.filter);
  } else if (options.filter instanceof Array) {
    var result = 0;
    _.each(options.filter, function(filter) {
        result |= lookup(filter);
    });
    options.filter = result;
  };

};

/**
 */
function PassiveDns(options) {
  var self = this;

  validate(options);

  self._dns = new _PassiveDns(options, function(data) {
    self.emit('data', data);
  });
};

util.inherits(PassiveDns, EventEmitter);

PassiveDns.prototype.stop = function() {
  this._dns.stop();
};

PassiveDns.prototype.start = function() {
  var self = this;
  this._dns.start();
};

PassiveDns.FILTERS = FILTERS;



module.exports = PassiveDns;
