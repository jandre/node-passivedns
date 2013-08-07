#ifndef _INCLUDE_DNS_CALLBACK
#define _INCLUDE_DNS_CALLBACK

#include "passivedns.h"


class DnsCallback {

    public: 
        DnsCallback(PassiveDns * d) : dns(d) {};

        ~DnsCallback() {};
    
        void Callback(OutputRecord * record) {
            dns->OnDnsRecord(record);
        };

    private:
        PassiveDns *dns;

};

#endif
