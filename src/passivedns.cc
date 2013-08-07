#include "passivedns.h"
#include <node.h>
#include <cstring>
#include <sys/time.h>
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


#define _RECORD_QUEUE_SIZE 512

// Pcap Callbacks

void launch_thread(void * context) {
  PassiveDns * dns = (PassiveDns *)context;
  dns->Work();
};


void main_loop_on_signal(uv_async_t *handle, int status /*UNUSED*/) {
   PassiveDnsMessage * message = (PassiveDnsMessage *)handle->data;
   PassiveDns * dns = (PassiveDns *)message->context;
   dns->MainLoopOnSignal();
};


 

// Passive Dns Definitions

PassiveDns::PassiveDns(globalconfig * options) : _config(options),
  _queue(_RECORD_QUEUE_SIZE), 
  _worker(NULL),
  _passive_dns_message(this)
{
  main_loop_signal.data = (void *)&(this->_passive_dns_message);  
};


// flush any queued events
void PassiveDns::Flush() {
  int empty = _queue.empty();

  while (!empty) {
    OutputRecord * rec = NULL;
    if (_queue.get_nowait(&rec)) {
      EmitDataToCallback(rec);
      delete rec;
    }
    empty = _queue.empty();
  };
};

void PassiveDns::MainLoopOnSignal() {
  Flush();
};

void PassiveDns::EmitDataToCallback(OutputRecord *rec) {

  HandleScope scope;
  Local<Object> obj = Object::New();

  obj->Set(String::New("answer"), String::New(rec->answer));
  obj->Set(String::New("timestamp"), Number::New(rec->timestamp));
  obj->Set(String::New("ttl"), Number::New(rec->ttl));
  obj->Set(String::New("query"), String::New(rec->qname));
  obj->Set(String::New("type"), String::New(rec->getType()));
  obj->Set(String::New("class"), String::New(rec->getClass()));
  obj->Set(String::New("server"), String::New(rec->ip_addr_s));
  obj->Set(String::New("src"), String::New(rec->ip_addr_c));

  Handle<Value> args[] = {
    obj
  };
  
  TryCatch try_catch;

  this->callback->Call(Context::GetCurrent()->Global(), 1, args);

  if (try_catch.HasCaught()) {
    node::FatalException(try_catch);
  }
};


void PassiveDns::Work() {
  if (_worker != NULL) {
    _worker->Start();
  }
};

int PassiveDns::IsStarted() {
  return (_worker != NULL);
}

void PassiveDns::Start() {
  this->_worker = new PcapWorker(this, this->_config);
  Ref();
  uv_async_init(uv_default_loop(), &main_loop_signal, main_loop_on_signal);
  uv_thread_create(&_thread, launch_thread, this);
};

void PassiveDns::Stop() {

  if (IsStarted()) {
    Unref();
    _worker->Stop();
    uv_thread_join(&_thread);
    uv_close((uv_handle_t *) &main_loop_signal, NULL);
    delete _worker;
    _worker = NULL;
  };

};

void PassiveDns::OnDnsRecord(OutputRecord * record) {
  // push it to the queue, make sure you wait if queue is busy
  //
  int ret = 0;
  while (!ret) {
    ret = _queue.put(record, true, 60);
  };
  // signal main thread that we have data
  Signal();
};

void PassiveDns::Init(v8::Handle<v8::Object> exports) {
  // Prepare constructor template
    Local<FunctionTemplate> tpl = FunctionTemplate::New(New);

    tpl->SetClassName(String::NewSymbol("PassiveDns"));
    tpl->InstanceTemplate()->SetInternalFieldCount(1);

    // Your methods here (Object.prototype.<method>)
    tpl->PrototypeTemplate()->Set(String::NewSymbol("stop"),
            FunctionTemplate::New(_Stop)->GetFunction());

    tpl->PrototypeTemplate()->Set(String::NewSymbol("start"),
            FunctionTemplate::New(_Start)->GetFunction());

    Persistent<Function> constructor = Persistent<Function>::New(tpl->GetFunction());
    exports->Set(String::NewSymbol("PassiveDns"), constructor);
};


v8::Handle<v8::Value> PassiveDns::_RegisterListener(const v8::Arguments& args) {
  HandleScope scope;
  return scope.Close(v8::Undefined());
};

v8::Handle<v8::Value> PassiveDns::_Stop(const v8::Arguments& args) {
  HandleScope scope;
  PassiveDns * obj = PassiveDns::Unwrap<PassiveDns>(args.This()); 
  obj->Stop();
  return scope.Close(v8::Undefined());
};

v8::Handle<v8::Value> PassiveDns::_Start(const v8::Arguments& args) {
  HandleScope scope;
  PassiveDns * obj = PassiveDns::Unwrap<PassiveDns>(args.This()); 
  obj->Start();
  return scope.Close(v8::Undefined());
};


v8::Handle<v8::Value> PassiveDns::New(const v8::Arguments& args) {

  HandleScope scope;

  if (args.Length() == 2 && args[0]->IsObject() && args[1]->IsFunction()) {
    globalconfig * config = new globalconfig(*(args[0]->ToObject()));
    PassiveDns * obj = new PassiveDns(config); 
    obj->callback = Persistent<Function>::New(Handle<Function>::Cast(args[1]));
    obj->Wrap(args.This());
  } else {
    return ThrowException(Exception::Error(String::New("Invalid arguments")));
  }

  return scope.Close(args.This());
}


using namespace node;
using namespace v8;


extern "C" {

  static void init(Handle<Object> target)
  {
      PassiveDns::Init(target);
  }

  NODE_MODULE(passivedns, init);
}
