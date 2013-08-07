#ifndef SESSION_H 
#define SESSION_H 

#include <node.h>
#include "defines.h"
#include "queue.h"
#include "pcap.h"
#include "dns.h"
#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h> 
#include <signal.h>
#include <pcap.h>
//#include <resolv.h>
#include <getopt.h>
#include <time.h>
#include <sys/types.h>
#include <grp.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>

using namespace v8;
using namespace node;

class Sessions {

    private:

        connection   * _bucket[BUCKET_SIZE];
        globalconfig * _config; 
        DnsWorker * _dns;

    public:

        Sessions(globalconfig * config, void * context, DnsCallback callback) {
            _config = config;
            memset(&_bucket, 0, sizeof(_bucket));
            _dns = new DnsWorker(config, context, callback);
        };

        ~Sessions() { 
            Flush();
            dlog("[*] Deleting sessions \n");
            delete _dns;
        };

        void Flush() { 

            time_t now_t;
            now_t = _config->tstamp.tv_sec;

            set_end_sessions();

            if ( (now_t - _config->dnslastchk) >= 600) {
                set_end_dns_records();
            }
        };

        void OnPacket(const struct pcap_pkthdr *pheader,
                const u_char * packet)

            // XXX: count elsewhere? _config->p_s.got_packets++;
            packetinfo pstruct = {0};
            packetinfo *pi = &pstruct;
            pi->packet = packet;
            pi->pheader = pheader;
            set_pkt_end_ptr (pi);
            _config->tstamp = pi->pheader->ts; // Global
            _config->inpacket = 1;
            prepare_eth(pi);
            check_vlan(pi);
            //parse_eth(pi);

            if (pi->eth_type == ETHERNET_TYPE_IP) {
                prepare_ip4(pi);
                parse_ip4(pi);
            } else if (pi->eth_type == ETHERNET_TYPE_IPV6) {
                prepare_ip6(pi);
                parse_ip6(pi);
            } else {
                _config->p_s.otherl_recv++;
                vlog(0x3, "[*] ETHERNET TYPE : %x\n",pi->eth_hdr->eth_ip_type);
            }
            _config->inpacket = 0;
            return;
        }

        void prepare_eth (packetinfo *pi)
        {
            if (pi->packet + ETHERNET_HEADER_LEN > pi->end_ptr) return;
            _config->p_s.eth_recv++;
            pi->eth_hdr  = (ether_header *) (pi->packet);
            pi->eth_type = ntohs(pi->eth_hdr->eth_ip_type);
            pi->eth_hlen = ETHERNET_HEADER_LEN;
            return;
        }

        void check_vlan (packetinfo *pi)
        {
            if (pi->eth_type == ETHERNET_TYPE_8021Q) {
                vlog(0x3, "[*] ETHERNET TYPE 8021Q\n");
                _config->p_s.vlan_recv++;
                pi->vlan = pi->eth_hdr->eth_8_vid;
                pi->eth_type = ntohs(pi->eth_hdr->eth_8_ip_type);
                pi->eth_hlen += 4;

                /* This is b0rked - kwy and ebf fix */
            } else if (pi->eth_type ==
                    (ETHERNET_TYPE_802Q1MT | ETHERNET_TYPE_802Q1MT2 |
                     ETHERNET_TYPE_802Q1MT3 | ETHERNET_TYPE_8021AD)) {
                vlog(0x3, "[*] ETHERNET TYPE 802Q1MT\n");
                pi->mvlan = pi->eth_hdr->eth_82_mvid;
                pi->eth_type = ntohs(pi->eth_hdr->eth_82_ip_type);
                pi->eth_hlen += 8;
            }
            return;
        }

        void prepare_ip4 (packetinfo *pi)
        {
            _config->p_s.ip4_recv++;
            pi->af = AF_INET;
            pi->ip4 = (ip4_header *) (pi->packet + pi->eth_hlen);
            pi->packet_bytes = (pi->ip4->ip_len - (IP_HL(pi->ip4) * 4));

            //vlog(0x3, "Got IPv4 Packet...\n");
            return;
        }

        void parse_ip4 (packetinfo *pi)
        {
            /* Paranoia */
            if (((pi->packet + pi->eth_hlen) + (IP_HL(pi->ip4) * 4)) > pi->end_ptr) {
                dlog("[D] Refusing to parse IPv4 packet: IPv4-hdr passed end_ptr\n");
                return;
            }

            switch (pi->ip4->ip_p) {
                case IP_PROTO_TCP:
                    prepare_tcp(pi);
                    parse_tcp(pi);
                    break;            
                case IP_PROTO_UDP:
                    prepare_udp(pi);
                    parse_udp(pi);
                    break;
                case IP_PROTO_IP4:
                    prepare_ip4ip(pi);
                    break;
                case IP_PROTO_IP6:
                    prepare_ip4ip(pi);
                    break;

                default:
                    break;
            }
            return;
        }

        void prepare_ip6ip (packetinfo *pi)
        {
            packetinfo pipi;
            memset(&pipi, 0, sizeof(packetinfo));
            _config->p_s.ip6ip_recv++;
            pipi.pheader = pi->pheader;
            pipi.packet = (pi->packet + pi->eth_hlen + IP6_HEADER_LEN);
            pipi.end_ptr = pi->end_ptr;
            if (pi->ip6->next == IP_PROTO_IP4) {
                prepare_ip4(&pipi);
                parse_ip4(&pipi);
                return;
            } else {
                prepare_ip6(&pipi);
                parse_ip6(&pipi);
                return;
            }
        }

        void prepare_ip4ip (packetinfo *pi)
        {
            packetinfo pipi;
            memset(&pipi, 0, sizeof(packetinfo));
            _config->p_s.ip4ip_recv++;
            pipi.pheader = pi->pheader;
            pipi.packet = (pi->packet + pi->eth_hlen + (IP_HL(pi->ip4) * 4));
            pipi.end_ptr = pi->end_ptr;
            if (pi->ip4->ip_p == IP_PROTO_IP4) {
                prepare_ip4(&pipi);
                parse_ip4(&pipi);
                return;
            } else {
                prepare_ip6(&pipi);
                parse_ip6(&pipi);
                return;
            }
        }

        void prepare_ip6 (packetinfo *pi)
        {
            _config->p_s.ip6_recv++;
            pi->af = AF_INET6;
            pi->ip6 = (ip6_header *) (pi->packet + pi->eth_hlen);
            pi->packet_bytes = pi->ip6->len;
            //vlog(0x3, "Got IPv6 Packet...\n");
            return;
        }

        void parse_ip6 (packetinfo *pi)
        {
            switch (pi->ip6->next) {
                case IP_PROTO_TCP:
                    prepare_tcp(pi);
                    parse_tcp(pi);
                    break;
                case IP_PROTO_UDP:
                    prepare_udp(pi);
                    parse_udp(pi);
                    break;
                case IP_PROTO_IP4:
                    prepare_ip6ip(pi);
                    break;
                case IP_PROTO_IP6:
                    prepare_ip6ip(pi);
                    break;

                default:
                    break;
            }
            return;
        }

        void parse_arp (packetinfo *pi)
        {
            vlog(0x3, "[*] Got ARP packet...\n");
            _config->p_s.arp_recv++;
            //if (!IS_CSSET(&config,CS_ARP)) return;
            pi->af = AF_INET;
            pi->arph = (ether_arp *) (pi->packet + pi->eth_hlen);
        }

        void set_pkt_end_ptr (packetinfo *pi)
        {
            /* Paranoia! */
            if (pi->pheader->len <= SNAPLENGTH) {
                pi->end_ptr = (pi->packet + pi->pheader->len);
            } else {
                pi->end_ptr = (pi->packet + SNAPLENGTH);
            }
            return;
        }

        void prepare_tcp (packetinfo *pi)
        {
            _config->p_s.tcp_recv++;
            if (pi->af==AF_INET) {
                vlog(0x3, "[*] IPv4 PROTOCOL TYPE TCP:\n");
                pi->tcph = (tcp_header *) (pi->packet + pi->eth_hlen + (IP_HL(pi->ip4) * 4));
                pi->plen = (pi->pheader->caplen - (TCP_OFFSET(pi->tcph)) * 4 - (IP_HL(pi->ip4) * 4) - pi->eth_hlen);
                pi->payload = (pi->packet + pi->eth_hlen + (IP_HL(pi->ip4) * 4) + (TCP_OFFSET(pi->tcph) * 4));
            } else if (pi->af==AF_INET6) {
                vlog(0x3, "[*] IPv6 PROTOCOL TYPE TCP:\n");
                pi->tcph = (tcp_header *) (pi->packet + pi->eth_hlen + IP6_HEADER_LEN);
                pi->plen = (pi->pheader->caplen - (TCP_OFFSET(pi->tcph)) * 4 - IP6_HEADER_LEN - pi->eth_hlen);
                pi->payload = (pi->packet + pi->eth_hlen + IP6_HEADER_LEN + (TCP_OFFSET(pi->tcph)*4));
            }
            pi->proto  = IP_PROTO_TCP;
            pi->s_port = pi->tcph->src_port;
            pi->d_port = pi->tcph->dst_port;
            connection_tracking(pi);
            return;
        }

        void prepare_udp (packetinfo *pi)
        {
            _config->p_s.udp_recv++;
            if (pi->af==AF_INET) {
                vlog(0x3, "[*] IPv4 PROTOCOL TYPE UDP:\n");
                pi->udph = (udp_header *) (pi->packet + pi->eth_hlen + (IP_HL(pi->ip4) * 4));
                pi->plen = pi->pheader->caplen - UDP_HEADER_LEN -
                    (IP_HL(pi->ip4) * 4) - pi->eth_hlen;
                pi->payload = (pi->packet + pi->eth_hlen +
                        (IP_HL(pi->ip4) * 4) + UDP_HEADER_LEN);

            } else if (pi->af==AF_INET6) {
                vlog(0x3, "[*] IPv6 PROTOCOL TYPE UDP:\n");
                pi->udph = (udp_header *) (pi->packet + pi->eth_hlen + + IP6_HEADER_LEN);
                pi->plen = pi->pheader->caplen - UDP_HEADER_LEN -
                    IP6_HEADER_LEN - pi->eth_hlen;
                pi->payload = (pi->packet + pi->eth_hlen +
                        IP6_HEADER_LEN + UDP_HEADER_LEN);
            }
            pi->proto  = IP_PROTO_UDP;
            pi->s_port = pi->udph->src_port;
            pi->d_port = pi->udph->dst_port;
            connection_tracking(pi);
            return;
        }

        void parse_tcp (packetinfo *pi)
        {
            if (pi->plen <= 0) return;

            /* Reliable traffic comes from the servers (normally on port 53 or 5353)
             * and the client has sent at least one package on that
             * connecton (Maybe asking for an aswer :) */
            //    if ( pi->sc == SC_SERVER && pi->cxt->s_total_pkts > 0 ) {
            dlog("[D] Parsing TCP packet...\n");
            _dns->dns_parser(pi);
            //    }   
            return;
        }

        void parse_udp (packetinfo *pi)
        {
            if (pi->plen <= 0) return;

            /* Reliable traffic comes from the servers (normally on port 53 or 5353)
             * and the client has sent at least one package on that
             * connecton (Maybe asking for an aswer :) */
            //if ( pi->sc == SC_SERVER && pi->cxt->s_total_pkts > 0 ) {
            dlog("[D] Parsing UDP packet...\n");
            _dns->dns_parser(pi);
            //}
            return;
        }

        int connection_tracking(packetinfo *pi) {
            struct in6_addr *ip_src;
            struct in6_addr *ip_dst;
            struct in6_addr ips;
            struct in6_addr ipd;
            uint16_t src_port = pi->s_port;
            uint16_t dst_port = pi->d_port;
            int af = pi->af;
            connection *cxt = NULL;
            connection *head = NULL;
            uint32_t hash;

            if(af== AF_INET6){
                ip_src = &PI_IP6SRC(pi);
                ip_dst = &PI_IP6DST(pi);
            }else {
                ips.s6_addr32[0] = pi->ip4->ip_src;
                ipd.s6_addr32[0] = pi->ip4->ip_dst;
                ip_src = &ips;
                ip_dst = &ipd;
            }

            // find the right connection bucket
            if (af == AF_INET) {
                hash = CXT_HASH4(IP4ADDR(ip_src),IP4ADDR(ip_dst),src_port,dst_port,pi->proto);
            } else if (af == AF_INET6) {
                hash = CXT_HASH6(ip_src,ip_dst,src_port,dst_port,pi->proto);
            } else {
                return -1;
            }

            cxt = _bucket[hash];
            head = cxt;

            // search through the bucket
            while (cxt != NULL) {
                // Two-way compare of given connection against connection table
                if (af == AF_INET) {
                    if (CMP_CXT4(cxt,IP4ADDR(ip_src),src_port,IP4ADDR(ip_dst),dst_port)){
                        // Client sends first packet (TCP/SYN - UDP?) hence this is a client
                        return cxt_update_client(cxt, pi);
                    } else if (CMP_CXT4(cxt,IP4ADDR(ip_dst),dst_port,IP4ADDR(ip_src),src_port)) {
                        // This is a server (Maybe not when we start up but in the long run)
                        return cxt_update_server(cxt, pi);
                    }
                } else if (af == AF_INET6) {
                    if (CMP_CXT6(cxt,ip_src,src_port,ip_dst,dst_port)){
                        return cxt_update_client(cxt, pi);
                    } else if (CMP_CXT6(cxt,ip_dst,dst_port,ip_src,src_port)){
                        return cxt_update_server(cxt, pi);
                    }
                }
                cxt = cxt->next;
            }
            // bucket turned upside down didn't yeild anything. new connection
            cxt = cxt_new(pi);

            /* New connections are pushed on to the head of _bucket[s_hash] */
            cxt->next = head;
            if (head != NULL) {
                // are we doubly linked?
                head->prev = cxt;
            }
            _bucket[hash] = cxt;
            pi->cxt = cxt;
            return cxt_update_client(cxt, pi);
        }

        /* freshly smelling connection :d */
        connection *cxt_new(packetinfo *pi)
        {
            struct in6_addr ips;
            struct in6_addr ipd;
            connection *cxt;
            _config->cxtrackerid++;
            cxt = (connection *) calloc(1, sizeof(connection));
            //assert(cxt);
            cxt->cxid = _config->cxtrackerid;

            cxt->af = pi->af;
            if(pi->tcph) cxt->s_tcpFlags |= pi->tcph->t_flags;
            cxt->start_time = pi->pheader->ts.tv_sec;
            cxt->last_pkt_time = pi->pheader->ts.tv_sec;

            if(pi-> af== AF_INET6){
                cxt->s_ip = PI_IP6SRC(pi);
                cxt->d_ip = PI_IP6DST(pi);
            }else {
                ips.s6_addr32[0] = pi->ip4->ip_src;
                ipd.s6_addr32[0] = pi->ip4->ip_dst;
                cxt->s_ip = ips;
                cxt->d_ip = ipd;
            }

            cxt->s_port = pi->s_port;
            cxt->d_port = pi->d_port;
            cxt->proto = pi->proto;

            cxt->check = 0x00;
            cxt->reversed = 0;
            _config->curcxt++;

            return cxt;
        }

        int cxt_update_client(connection *cxt, packetinfo *pi)
        {
            cxt->last_pkt_time = pi->pheader->ts.tv_sec;

            if(pi->tcph) cxt->s_tcpFlags |= pi->tcph->t_flags;
            cxt->s_total_bytes += pi->packet_bytes;
            cxt->s_total_pkts += 1;

            pi->cxt = cxt;
            pi->sc = SC_CLIENT;
            if (cxt->s_total_bytes > MAX_BYTE_CHECK
                    || cxt->s_total_pkts > MAX_PKT_CHECK) {
                return 0;   // Dont Check!
            }
            return SC_CLIENT;
        }

        int cxt_update_server(connection *cxt, packetinfo *pi)
        {
            cxt->last_pkt_time = pi->pheader->ts.tv_sec;

            if(pi->tcph) cxt->d_tcpFlags |= pi->tcph->t_flags;
            cxt->d_total_bytes += pi->packet_bytes;
            cxt->d_total_pkts += 1;

            pi->cxt = cxt;
            pi->sc = SC_SERVER;
            if (cxt->d_total_bytes > MAX_BYTE_CHECK
                    || cxt->d_total_pkts > MAX_PKT_CHECK) {
                return 0;   // Dont check!
            }
            return SC_SERVER;
        }

        void end_all_sessions()
        {
            connection *cxt;
            int cxkey;
            _config->llcxt = 0;

            for (cxkey = 0; cxkey < BUCKET_SIZE; cxkey++) {
                cxt = _bucket[cxkey];
                while (cxt != NULL) {
                    _config->llcxt++;
                    if (cxt->prev)
                        cxt->prev->next = cxt->next;
                    if (cxt->next)
                        cxt->next->prev = cxt->prev;
                    connection *tmp = cxt;

                    cxt = cxt->next;
                    del_connection(tmp, &_bucket[cxkey]);
                    if (cxt == NULL) {
                        _bucket[cxkey] = NULL;
                    }
                }
            }
            dlog("CXT in list before cleaning: %10u\n", _config->llcxt);
            dlog("CXT in list after  cleaning: %10u\n", _config->curcxt);
        }

        void end_sessions()
        {
            connection *cxt;
            time_t check_time;
            check_time = _config->tstamp.tv_sec;
            //time(&check_time);
            int ended, expired = 0;
            _config->llcxt = 0;

            int iter;

            for (iter = 0; iter < BUCKET_SIZE; iter++) {
                cxt = _bucket[iter];
                while (cxt != NULL) {
                    ended = 0;
                    _config->llcxt++;
                    /* TCP */
                    if (cxt->proto == IP_PROTO_TCP) {
                        /* * FIN from both sides */
                        if (cxt->s_tcpFlags & TF_FIN && cxt->d_tcpFlags & TF_FIN
                                && (check_time - cxt->last_pkt_time) > 5) {
                            ended = 1;
                        } /* * RST from either side */
                        else if ((cxt->s_tcpFlags & TF_RST
                                    || cxt->d_tcpFlags & TF_RST)
                                && (check_time - cxt->last_pkt_time) > 5) {
                            ended = 1;
                        }
                        else if ((check_time - cxt->last_pkt_time) > TCP_TIMEOUT) {
                            expired = 1;
                        }
                    }
                    /* UDP */
                    else if (cxt->proto == IP_PROTO_UDP
                            && (check_time - cxt->last_pkt_time) > UDP_TIMEOUT) {
                        expired = 1;
                    }
                    /* ICMP */
                    else if (cxt->proto == IP_PROTO_ICMP
                            || cxt->proto == IP6_PROTO_ICMP) {
                        if ((check_time - cxt->last_pkt_time) > ICMP_TIMEOUT) {
                            expired = 1;
                        }
                    }
                    /* All Other protocols */
                    else if ((check_time - cxt->last_pkt_time) > OTHER_TIMEOUT) {
                        expired = 1;
                    }

                    if (ended == 1 || expired == 1) {
                        /* remove from the hash */
                        if (cxt->prev)
                            cxt->prev->next = cxt->next;
                        if (cxt->next)
                            cxt->next->prev = cxt->prev;
                        connection *tmp = cxt;
                        connection *tmp_pre = cxt->prev;

                        ended = expired = 0;

                        cxt = cxt->next;

                        del_connection(tmp, &_bucket[iter]);
                        if (cxt == NULL && tmp_pre == NULL) {
                            _bucket[iter] = NULL;
                        }
                    } else {
                        cxt = cxt->next;
                    }
                }
            }
            dlog("CXT in list before cleaning: %10u\n", _config->llcxt);
            dlog("CXT in list after  cleaning: %10u\n", _config->curcxt);
        }

        void del_connection(connection * cxt, connection ** bucket_ptr)
        {
            connection *prev = cxt->prev;       /* OLDER connections */
            connection *next = cxt->next;       /* NEWER connections */

            if (prev == NULL) {
                // beginning of list
                *bucket_ptr = next;
                // not only entry
                if (next)
                    next->prev = NULL;
            } else if (next == NULL) {
                // at end of list!
                prev->next = NULL;
            } else {
                // a node.
                prev->next = next;
                next->prev = prev;
            }

            // Free and set to NULL 
            free(cxt);
            cxt = NULL;
            _config->curcxt--;
        }
        const char *u_ntop_src(packetinfo *pi, char *dest)
        {
            if (pi->af == AF_INET) {
                if (!inet_ntop
                        (AF_INET,
                         &pi->ip4->ip_src,
                         dest, INET_ADDRSTRLEN + 1)) {
                    perror("Something died in inet_ntop");
                    return NULL;
                }
            } else if (pi->af == AF_INET6) {
                if (!inet_ntop(AF_INET6, &pi->ip6->ip_src, dest, INET6_ADDRSTRLEN + 1)) {
                    perror("Something died in inet_ntop");
                    return NULL;
                }
            }
            return dest;
        }

        // void check_interrupt()
        // {
            // dlog("[D] In interrupt. Flag: %d\n",_config->intr_flag);
            // if (ISSET_INTERRUPT_END(config)) {
                // game_over();
            // } else if (ISSET_INTERRUPT_SESSION(config)) {
                // set_end_sessions();
            // } else if (ISSET_INTERRUPT_DNS(config)) {
                // set_end_dns_records();
            // } else {
                // _config->intr_flag = 0;
            // }
        // }

        // void sig_alarm_handler()
        // {
            // time_t now_t;
            // //_config->tstamp = time(); // _config->tstamp will stand still if there is no packets
            // now_t = _config->tstamp.tv_sec;

            // dlog("[D] Got SIG ALRM: %lu\n", now_t);
            // [> Each time check for timed out sessions <]
            // set_end_sessions();

            // [> Only check for timed-out dns records each 10 minutes <]
            // if ( (now_t - _config->dnslastchk) >= 600 ) {
                // set_end_dns_records();
            // }
            // alarm(TIMEOUT);
        // }

        void set_end_dns_records()
        {
            _config->intr_flag |= INTERRUPT_DNS;

            if (_config->inpacket == 0) {
                _dns->expire_dns_records();
                _config->dnslastchk = _config->tstamp.tv_sec;
                _config->intr_flag &= ~INTERRUPT_DNS;
            }
        }

        void set_end_sessions()
        {
            _config->intr_flag |= INTERRUPT_SESSION;

            if (_config->inpacket == 0) {
                end_sessions();
                _config->intr_flag &= ~INTERRUPT_SESSION;
            }
        }



};
#endif

