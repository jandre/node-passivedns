
#ifndef PASSIVEDNS_H 
#define PASSIVEDNS_H 

#include <node.h>
#include "defines.h"
#include "queue.h"
#include "pcap.h"
#include "worker.h"
#include "dns.h"
#include "config.h"

using namespace v8;
using namespace node;


class PassiveDns;

struct PassiveDnsMessage {
    int event; // not used
    PassiveDns * context;

    PassiveDnsMessage(PassiveDns * c) : context(c) {}
}; 

class PassiveDns : public node::ObjectWrap {

    public:

        PassiveDns(globalconfig *); 

        virtual ~PassiveDns() {
            delete _config;
        };

        static void Init(v8::Handle<v8::Object> exports);
        void Start();
        void Stop();
        void Work();
        void Flush();
        void MainLoopOnSignal();
        void OnDnsRecord(OutputRecord *);

        void Signal(int event = 0) { 
          uv_async_send(&main_loop_signal);
        };

        Persistent<v8::Function> callback;

    private:
        globalconfig * _config;
        Queue<OutputRecord *> _queue;
        PcapWorker * _worker;

        uv_thread_t _thread;
      
        PassiveDnsMessage _passive_dns_message;
        uv_async_t main_loop_signal;

        int IsStarted();
        void EmitDataToCallback(OutputRecord * rec);

        /* v8 static methods */

        static v8::Handle<v8::Value> _RegisterListener(const v8::Arguments& args);
        static v8::Handle<v8::Value> _Stop(const v8::Arguments& args);
        static v8::Handle<v8::Value> _Start(const v8::Arguments& args);
        static v8::Handle<v8::Value> New(const v8::Arguments& args);
};
#endif

