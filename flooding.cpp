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

thread *BeaconFlooding(const char *dev, Dot11Beacon::address_type mac, const char *ssid, uint32_t channel);
void BeaconFloodingR(const char *dev, Dot11Beacon::address_type mac, char *ssid, uint32_t channel);
thread *ProbeResponse(const char *dev, Dot11ProbeRequest::address_type mac, const char *ssid, uint32_t channel);
void ProbeResponseR(const char *dev, Dot11ProbeResponse::address_type mac, char *ssid, uint32_t channel);

bool setSignal(uint32_t sig, sighandler_t handler);
void SignalHandler(int signo);

bool run = true;

int main(int argc, char *argv[]){
	if(argc < 2)
		usage();
	
	setSignal(SIGINT, SignalHandler);

	vector< shared_ptr<thread> > vthread;
	
	thread *th;
	
	th = BeaconFlooding(argv[1], "00:01:02:03:04:05", "nekop", 1);
	vthread.push_back(shared_ptr<thread>(th));
	th = ProbeResponse(argv[1], "00:01:02:03:04:05", "nekop", 1);
	vthread.push_back(shared_ptr<thread>(th));

	th = BeaconFlooding(argv[1], "10:11:12:13:14:15", "WebHacker", 2);
	vthread.push_back(shared_ptr<thread>(th));
	th = ProbeResponse(argv[1], "10:11:12:13:14:15", "WebHacker", 2);
	vthread.push_back(shared_ptr<thread>(th));

	th = BeaconFlooding(argv[1], "20:21:22:23:24:25", "Pwnabler", 3);
	vthread.push_back(shared_ptr<thread>(th));
	th = ProbeResponse(argv[1], "20:21:22:23:24:25", "Pwnabler", 3);
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

thread *BeaconFlooding(const char *dev, Dot11Beacon::address_type mac, const char *ssid, uint32_t channel){
	return new thread(&BeaconFloodingR, dev, mac, (char *)ssid, channel);
}

void BeaconFloodingR(const char *dev, Dot11Beacon::address_type mac, char *ssid, uint32_t channel){
	Dot11Beacon beacon;

	beacon.addr1(Dot11::BROADCAST);
	beacon.addr2(mac);
	beacon.addr3(beacon.addr2());

	beacon.ssid(ssid);
	beacon.ds_parameter_set(channel);
	beacon.supported_rates({ 1.0f, 5.5f, 11.0f });

	beacon.rsn_information(RSNInformation::wpa2_psk());

	PacketSender sender;
	RadioTap packet = RadioTap() / beacon;
	
	while(run){
		sender.send(packet, dev);
		this_thread::sleep_for(chrono::milliseconds(100));
	}
}

thread *ProbeResponse(const char *dev, Dot11ProbeResponse::address_type mac, const char *ssid, uint32_t channel){
	return new thread(&ProbeResponseR, dev, mac, (char *)ssid, channel);
}

void ProbeResponseR(const char *dev, Dot11ProbeResponse::address_type mac, char *ssid, uint32_t channel){
	SnifferConfiguration config;
	config.set_filter("type mgt subtype probe-req");
	config.set_promisc_mode(true);

	Sniffer sniffer(dev, config);

	while(run){
		unique_ptr<PDU> pdu(sniffer.next_packet());
		
		const Dot11ProbeRequest &request = pdu->rfind_pdu<Dot11ProbeRequest>();
		if(request.ssid() == ssid && request.ds_parameter_set() == channel){
			Dot11ProbeResponse response;
			
			response.addr1(request.addr2());
			response.addr2(mac);
			response.addr3(mac);

			response.ssid(ssid);
			response.ds_parameter_set(channel);
			response.supported_rates({ 1.0f, 5.5f, 11.0f });

			response.rsn_information(RSNInformation::wpa2_psk());

			PacketSender sender;
			RadioTap packet = RadioTap() / response;
			sender.send(packet, dev);
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
