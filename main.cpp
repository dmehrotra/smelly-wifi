#include <vector>
#include <tins.h>
//g++ main.cpp -o test -O3 -std=c++11 -lpthread -ltins
using namespace Tins;
using namespace std;


string get_header_from_raw(string header, const RawPDU& rawpdu){
    
    string payL = "";
    string content = "";
    const RawPDU::payload_type& payload = rawpdu.payload();
    for (const auto& bit : payload) {
        payL += (char) bit;
    }
    
    int pos_header = (int) payL.find(header);
    
    if(pos_header != -1){
        content = payL.substr(pos_header);
        int endHeader = (int) content.find("\n");
        content = content.substr(0, endHeader - 1);
    }

    
    return payL;
}

int main() {

    SnifferConfiguration config;

    config.set_rfmon(true);
    config.set_promisc_mode(true);
    Sniffer sniffer("en0", config);
  
    while (Packet packet = sniffer.next_packet()) {
                if (packet.pdu()->find_pdu<Dot11Data>()) {
                    try{
                        const PDU& pdu = *packet.pdu();
                        const RawPDU &raw = pdu.rfind_pdu<RawPDU>();
                        string header = "GET";
                        cout << get_header_from_raw(header, raw) << endl;
                    }
                    catch(...){}
                    
                }
    
    }

}
