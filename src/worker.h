
#ifndef WORKER_H 
#define WORKER_H 

#include <node.h>
#include "queue.h"
#include "pcap.h"
#include "session.h"
#include "defines.h"

using namespace v8;
using namespace node;

#define _WORKER_STATE_STOPPED          0x1
#define _WORKER_STATE_STARTED          0x2
#define _WORKER_STATE_STOP_REQUESTED   0x3

#define _WORKER_MSG_STOP     0x1
#define _WORKER_MSG_FLUSH    0x2


class PassiveDns;
class PcapWorker;


struct worker_message_t {
    int event;
    PcapWorker *worker;
};

class PcapWorker {

    public:

        PcapWorker(PassiveDns * main, globalconfig *config);
        virtual ~PcapWorker();
        
        int IsStopped();
        void GetPackets();
        void Start(); 
        void TimerLoop();
        void Stop(); 
        void Signal(int event, void *data);
        void OnMessage(worker_message_t * message);
        
    private:

        PassiveDns * _main;
        globalconfig * _config;
        int _state;
        Sessions _sessions;
        uv_async_t _pcap_loop_signal;
        uv_loop_t * _pcap_loop;
        uv_poll_t * _poll_handle;
        pcap_t * _pcap_handle;
        worker_message_t _pcap_worker_message;

        uv_timer_t _flush_timer;

        char * _berkeley_filter;
        char * _device;

        void Flush();
        void StartTimer();
        void StopTimer();

        void MsgStateStarted(worker_message_t * msg) {
            switch (msg->event) {
            }
        };

        void MsgStateStopped(worker_message_t * msg) {
        
        };

};

#endif

