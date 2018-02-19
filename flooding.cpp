#include <iostream>
#include <memory>
#include <thread>
#include <chrono>
#include <vector>

#include <csignal>
#include <cstdint>

#include <tins/tins.h>

using namespace std;
using namespace Tins;

void usage();

bool setSignal(uint32_t sig, sighandler_t handler);
void SignalHandler(int signo);

bool run = true;

template <typename Type>
class MgtFrame {
private:
	Type mac;
	unique_ptr< char > ssid;
	uint32_t channel;

public:
	MgtFrame(Type mac, const char *ssid, uint32_t channel) : mac(mac), channel(channel) {
		size_t ssidlen = strlen(ssid);
		this->ssid = unique_ptr< char >(new char[ssidlen + 1]);
		strncpy(this->ssid.get(), ssid, ssidlen);
		this->ssid.get()[ssidlen] = 0 ;
	}

	Type getMac() const { return mac; }
	char *getSsid() const { return ssid.get(); }
	uint32_t getChannel() const { return channel; }
};

template <typename Type>
thread *BeaconFlooding(const char *dev, MgtFrame<Type> *frame, uint32_t cnt);

template <typename Type>
void BeaconFloodingR(const char *dev, MgtFrame<Type> *frame, uint32_t cnt);

template <typename Type>
thread *ProbeResponse(const char *dev, MgtFrame<Type> *frame, uint32_t cnt);

template <typename Type>
void ProbeResponseR(const char *dev, MgtFrame<Type> *frame, uint32_t cnt);

int main(int argc, char *argv[]){
	if(argc < 2)
		usage();
	
	setSignal(SIGINT, SignalHandler);

	vector< shared_ptr<thread> > vthread;
	
	thread *th;
	
	MgtFrame<Dot11Beacon::address_type> beacon[] = {
		{ "00:01:02:03:04:05", "nekop", 1 },
		{ "10:11:12:13:14:15", "WebHacker", 2 },
		{ "20:21:22:23:24:25", "Pwnabler", 3 }
	};

	MgtFrame<Dot11ProbeResponse::address_type> probe[] = {
		{ "00:01:02:03:04:05", "nekop", 1 },
		{ "10:11:12:13:14:15", "WebHacker", 2 },
		{ "20:21:22:23:24:25", "Pwnabler", 3 }
	};

	th = BeaconFlooding(argv[1], beacon, sizeof(beacon) / sizeof(MgtFrame<Dot11Beacon::address_type>));
	vthread.push_back(shared_ptr<thread>(th));
	th = ProbeResponse(argv[1], probe, sizeof(probe) / sizeof(MgtFrame<Dot11ProbeResponse::address_type>));
	vthread.push_back(shared_ptr<thread>(th));
	
	for(auto item : vthread){
		item->join();
	}

	cout << "done." << endl;

	return 0;
}

void usage(){
	puts("[Usage] ./flooding [interfaces...]");
	exit(-1);
}

template<typename Type>
thread *BeaconFlooding(const char *dev, MgtFrame<Type> *frame, uint32_t cnt){
	return new thread(&BeaconFloodingR<Type>, dev, frame, cnt);
}

template<typename Type>
void BeaconFloodingR(const char *dev, MgtFrame<Type> *frame, uint32_t cnt){
	while(run){
		for(uint32_t i = 0; i < cnt; i++){
			Dot11Beacon beacon;

			beacon.addr1(Dot11::BROADCAST);
			beacon.addr2(frame[i].getMac());
			beacon.addr3(beacon.addr2());

			beacon.ssid(frame[i].getSsid());
			beacon.ds_parameter_set(frame[i].getChannel());
			beacon.supported_rates({ 1.0f, 5.5f, 11.0f });

			beacon.rsn_information(RSNInformation::wpa2_psk());

			PacketSender sender;
			RadioTap packet = RadioTap() / beacon;

			sender.send(packet, dev);
		}
		this_thread::sleep_for(chrono::milliseconds(100));
	}
}

template<typename Type>
thread *ProbeResponse(const char *dev, MgtFrame<Type> *frame, uint32_t cnt){
	return new thread(&ProbeResponseR<Type>, dev, frame, cnt);
}

template<typename Type>
void ProbeResponseR(const char *dev, MgtFrame<Type> *frame, uint32_t cnt){
	SnifferConfiguration config;
	config.set_filter("type mgt subtype probe-req");
	config.set_promisc_mode(true);

	Sniffer sniffer(dev, config);

	while(run){
		unique_ptr<PDU> pdu(sniffer.next_packet());
		
		const Dot11ProbeRequest &request = pdu->rfind_pdu<Dot11ProbeRequest>();
		for(uint32_t i = 0; i < cnt; i++){
			if(request.ssid() == frame[i].getSsid()
				&& request.ds_parameter_set() == frame[i].getChannel())
			{
				Dot11ProbeResponse response;

				response.addr1(request.addr2());
				response.addr2(frame[i].getMac());
				response.addr3(response.addr2());

				response.ssid(frame[i].getSsid());
				response.ds_parameter_set(frame[i].getChannel());
				response.supported_rates({ 1.0f, 5.5f, 11.0f });

				response.rsn_information(RSNInformation::wpa2_psk());

				PacketSender sender;
				RadioTap packet = RadioTap() / response;
				sender.send(packet, dev);
			}
		}
	}
}

bool setSignal(uint32_t sig, sighandler_t handler){
	struct sigaction sigact;

	sigact.sa_handler = handler;
	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags = 0;

	sigaction(sig, &sigact, NULL);
	return true;
}

void SignalHandler(int signo){
	run = false;
	cout << "Wait for thread" << endl;
}
