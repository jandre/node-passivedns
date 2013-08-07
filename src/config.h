#ifndef _CONFIG_H
#define _CONFIG_H

#include <node.h>
#include <string>
#include "defines.h"

using namespace v8;


#define SET_STRING_VALUE(options, k, dst) \
    do {\
        Local<String> key = String::New(k);\
        if (options->HasOwnProperty(key) && options->Get(key)->IsString()) {\
            String::AsciiValue val(options->Get(key)->ToString());\
            dst.assign(*val);\
        }\
    } while (0)


#define SET_UINT32_VALUE(options, k, dst) \
    do {\
        Local<String> key = String::New(k);\
        if (options->HasOwnProperty(key) && options->Get(key)->IsNumber()) {\
            dst = options->Get(key)->ToUint32()->Value();\
        }\
    } while (0)


#define SET_UINT8_VALUE(options, k, dst) \
    do {\
        Local<String> key = String::New(k);\
        if (options->HasOwnProperty(key) && options->Get(key)->IsNumber()) {\
            dst = (uint8_t)(options->Get(key)->ToInt32());\
        }\
    } while (0)



class globalconfig {

    public:

        struct pcap_stat    ps;              /* libpcap stats */
        pdns_stat           p_s;             /* pdns stats */
        uint8_t     intr_flag;
        uint8_t     inpacket;

        time_t       dnslastchk;             /* Timestamp for last dns cache expiration check */
        struct timeval tstamp;               /* Current timestamp from packet-header */
        uint8_t      cflags;                 /* config flags */
        uint8_t      verbose;                /* Verbose or not */
        uint8_t      print_updates;          /* Prints updates */
        uint8_t      use_syslog;             /* Use syslog or not */
        uint8_t      setfilter;
        uint32_t     dns_filter;             /* Flags for DNS RR Type checks to do */
        uint32_t     dns_filter_error;       /* Flags for DNS Server Error Types to check */
        uint32_t     payload;                /* dump how much of the payload ?  */
        uint32_t     curcxt;
        uint32_t     llcxt;
        uint64_t     mem_limit_max;          /* Try soft limit memory use */
        uint64_t     mem_limit_size;         /* Current memory size */
        uint32_t     dns_records;            /* total number of DNS records in memory */
        uint32_t     dns_assets;             /* total number of DNS assets in memory */
        uint64_t     cxtrackerid;            /* cxtracker ID counter */
        char        *user_filter;            /**/
        char        *net_ip_string;          /**/
        char        *pcap_file;              /* Filename to pcap too read */
        char        *dpath;                  /* ... ??? seriously ???... */
        uint32_t     dnsprinttime;           /* Minimum time between printing duplicate dns info */
        uint32_t     dnscachetimeout;        /* Time before a dns record/asset times out if not updated */

        std::string interface;
        std::string pcap_filter;

        virtual ~globalconfig() {
            
        };

        void SetDnsFilter(v8::Object * options) {
 
            dns_filter = 0;
            dns_filter |= DNS_CHK_A;
            dns_filter |= DNS_CHK_AAAA;
            dns_filter |= DNS_CHK_PTR;
            dns_filter |= DNS_CHK_CNAME;
            dns_filter |= DNS_CHK_DNAME;
            dns_filter |= DNS_CHK_NAPTR;
            dns_filter |= DNS_CHK_RP;
            dns_filter |= DNS_CHK_SRV;

            SET_UINT32_VALUE(options, "filter", dns_filter); 
       
        };

        globalconfig(v8::Object * options) :
            pcap_filter("port 53"),
            dns_records(0)
        {

            HandleScope scope;

            memset(&ps, 0, sizeof(struct pcap_stat));
            memset(&p_s, 0, sizeof(pdns_stat));
            memset(&tstamp, 0, sizeof(struct timeval));
            intr_flag = 0;        
            inpacket = 0;         
            dnslastchk = 0;      
            cflags = 0;          
            verbose = 0;         
            print_updates = 0;   
            use_syslog = 0;      
            setfilter = 0;       
            dns_filter = 0;      
            dns_filter_error = 0;
            payload = 0;         
            curcxt = 0;          
            llcxt = 0;           
            mem_limit_max = 0;   
            mem_limit_size = 0;  
            dns_records = 0;     
            dns_assets = 0;      
            cxtrackerid = 0;     
            dnsprinttime = 0;    
            dnscachetimeout = 0; 

            SET_STRING_VALUE(options, "interface", interface);
            SET_STRING_VALUE(options, "pcap_filter", pcap_filter);
            SetDnsFilter(options);

            inpacket = intr_flag = 0;
            dnslastchk = 0;
            mem_limit_max = (256 * 1024 * 1024); // 256 MB - default try to limit dns caching to this
            dnsprinttime = DNSPRINTTIME;
            dnscachetimeout =  DNSCACHETIMEOUT;


        }; 



};

#endif
