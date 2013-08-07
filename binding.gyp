{
  "targets": [
  {
    "target_name": "passivedns",
      "sources": [  "src/hash.cc", "src/worker.cc", "src/module.cc", "src/passivedns.cc", "src/session.cc", "src/dns.cc" ],
      "link_settings": {
        "libraries": [
          "-lldns -lpcap"
          ]
      }
  }]
}
