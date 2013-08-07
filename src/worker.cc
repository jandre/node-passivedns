#include "worker.h"
#include <uv.h>
#include "passivedns.h"

#define OLD_UV_RUN_SIGNATURE 1

void pcap_loop_on_signal(uv_async_t *handle, int status /*UNUSED*/) {
    worker_message_t* message = (worker_message_t *)handle->data;
    message->worker->OnMessage(message);
};

void pcap_worker_timer_loop(uv_timer_t* handle, int status) {
    PcapWorker * worker = (PcapWorker *)handle->data;
    worker->TimerLoop();
};

void on_poll_packet_event(uv_poll_t * handle, int status, int events) {
    PcapWorker * worker = (PcapWorker *)handle->data;
    worker->GetPackets();
};

void on_dns_callback(void * context, OutputRecord * record) {
    PassiveDns *main = (PassiveDns *)context;
    main->OnDnsRecord(record);
};


PcapWorker::PcapWorker(PassiveDns *main, globalconfig *config) : 
    _main(main), _config(config), _state(_WORKER_STATE_STOPPED),
    _sessions(config, (void *)main, on_dns_callback),
    _poll_handle(NULL),
    _pcap_handle(NULL)
{
    _device = (char *)"eth0";
    _berkeley_filter = (char *)"port 53";

    _pcap_loop = uv_loop_new();
    _pcap_worker_message.worker = this;
    _pcap_loop_signal.data = &_pcap_worker_message; 

};

PcapWorker::~PcapWorker() {
    uv_loop_delete(_pcap_loop);
};

int PcapWorker::IsStopped() {
    return (this->_state == _WORKER_STATE_STOPPED ||
            this->_state == _WORKER_STATE_STOP_REQUESTED);
};

void PcapWorker::GetPackets() {

    if (IsStopped()) return;

    struct pcap_pkthdr phdr;
    const u_char * packet;

    packet = pcap_next(_pcap_handle, &phdr);

    if (packet != NULL) {
        _sessions.OnPacket(&phdr, packet);
    }

};

void PcapWorker::StartTimer() {
    this->_flush_timer.data = (void *) this;
    uv_timer_init(_pcap_loop, &(this->_flush_timer));
    uv_timer_start(&(this->_flush_timer), pcap_worker_timer_loop, 2000, 2000);
};


void PcapWorker::StopTimer() {
   uv_timer_stop(&(this->_flush_timer));
};


void PcapWorker::TimerLoop() {
    if (IsStopped()) return;
    _sessions.Flush();
};

void PcapWorker::Start() {

    char error[PCAP_ERRBUF_SIZE];

    _pcap_handle = pcap_open_live(_device, SNAPLENGTH, 1, 500, &error[0]);

    if (_pcap_handle == NULL) {
        printf("[XXX] Unable to open pcap\n");
        return;
    }
    
    // int res = pcap_datalink(_pcap_handle);

    int fd = pcap_get_selectable_fd((pcap_t*)_pcap_handle);

    int err;

    _poll_handle = new uv_poll_t;

    _poll_handle->data = this;

    err = uv_poll_init(_pcap_loop, _poll_handle, fd);

    err = uv_poll_start(_poll_handle, UV_READABLE, on_poll_packet_event);

    // notify main loop that we are ready to accept messages. 

    _state = _WORKER_STATE_STARTED;

    uv_async_init(_pcap_loop, &_pcap_loop_signal, pcap_loop_on_signal);

    _main->Signal();

    StartTimer();

    #ifdef OLD_UV_RUN_SIGNATURE
        uv_run(_pcap_loop);
    #else
        uv_run(_pcap_loop, UV_RUN_DEFAULT);
    #endif

    printf("XXX Worker ended\n");
};


void PcapWorker::Stop() {

    if (_state == _WORKER_STATE_STARTED) {
        _state = _WORKER_STATE_STOP_REQUESTED;
    }
    this->Signal(_WORKER_STATE_STOP_REQUESTED, (void *)NULL);
};


void PcapWorker::Signal(int event, void *data) {
    uv_async_send(&_pcap_loop_signal);
};

void PcapWorker::OnMessage(worker_message_t * message) {

    switch (this->_state) {

        case _WORKER_STATE_STARTED:
            MsgStateStarted(message);
            break;
        case _WORKER_STATE_STOP_REQUESTED:

            if (_poll_handle != NULL) {
                uv_poll_stop(_poll_handle);  
                _poll_handle = NULL;
            }

            if (_pcap_handle != NULL) {
                pcap_close(_pcap_handle);
                _pcap_handle = NULL;
            }

            uv_close((uv_handle_t*) &_pcap_loop_signal,NULL);
            StopTimer();
            _state = _WORKER_STATE_STOPPED;
            break;
        default: 
            printf("Invalid worker state: %d\n", this->_state);
            // XXX exception
    }
};


