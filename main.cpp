#include <iostream>
#include "stdlib.h"
#include "Packet.h"
#include "SystemUtils.h"
#include "Layer.h"
#include "EthLayer.h"
#include "VlanLayer.h"
#include "VlanLayer.h"
#include "PcapFileDevice.h"
#include "ProtocolType.h"
#include "IPv4Layer.h"

std::string getProtocolTypeAsString(pcpp::ProtocolType protocolType)
{
    switch (protocolType)
    {
    case pcpp::Ethernet:
        return "Ethernet";
    case pcpp::VLAN:
        return "VLAN";
    case pcpp::IPv4:
        return "IPv4";
    case pcpp::IPv6:
        return "IPv6";
    case pcpp::TCP:
        return "TCP";
    case pcpp::UDP:
        return "UDP";
    default:
        return "Other";
    }
}

int main(int argc, char *argv[])
{

    // pcpp::IFileReaderDevice *reader = pcpp::IFileReaderDevice::getReader("QinQ.pcap.cap");
    pcpp::IFileReaderDevice *reader = pcpp::IFileReaderDevice::getReader("dns_tcp.pcapng");

    if (reader == NULL || !reader->open())
    {
        std::cerr << "Error in Reading file" << std::endl;
        return 1;
    }

    int packets = 0;
    pcpp::RawPacket rawPacket;

    // if(!reader->getNextPacket(rawPacket)){
    //     std::cerr << "Can't read first packet in the file" << std::endl;
    //     return 2;
    // }

    while (reader->getNextPacket(rawPacket))
    {
        packets++;
        pcpp::Packet parsedPacket(&rawPacket);

        // Layer 2
        // Data Link Layer is not Ethernet drop!
        pcpp::EthLayer* ethernetLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
        if (ethernetLayer == NULL)
        {
            std::cerr << "Something went wrong, couldn't find Ethernet layer" << std::endl;
            return 1;
        }

        std::cout << std::endl
                  << "Src  MAC address " << ethernetLayer->getSourceMac() << std::endl
                  << "Dest MAC address " << ethernetLayer->getDestMac() << std::endl
                  << "Ethernet type = 0x" << pcpp::netToHost16(ethernetLayer->getEthHeader()->etherType) << std::endl;

        // Drop all packets except coming from vlanID
        // pcpp::VlanLayer* vlanLayer = parsedPacket.getLayerOfType<pcpp::VlanLayer>();
        // if (vlanLayer == NULL)
        // {
        //     std::cerr << "Vlan layer doesn't exist" << std::endl;
        //     continue;
        // }

        // std::cout << "Vlan ID " << vlanLayer->getVlanID() << std::endl;


        // Layer 3
        // if packet ip version != argsIPVersion drop

        pcpp::IPv4Layer* ipv4Layer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();

        if(ipv4Layer == NULL){
            std::cerr << "Ipv4 Layer is missing" << std::endl;
            continue;
        }

        std::cout 
            << "Src  IP: " << ipv4Layer->getSrcIPAddress() << std::endl 
            << "Dest IP: " << ipv4Layer->getDstIPAddress() << std::endl 
            << "TTL: " << (int)ipv4Layer->getIPv4Header()->timeToLive << std::endl
            << "IP Id: " << pcpp::netToHost16(ipv4Layer->getIPv4Header()->ipId) << std::endl; 

        // If L4 = ICMP Drop

        // If L4 = UDP && DNS
        // Then packet craft serverAddress & port replace by args fields

        // for (pcpp::Layer *curLayer = parsedPacket.getFirstLayer(); curLayer != NULL; curLayer = curLayer->getNextLayer())
        // {
        //     std::cout << "\t"
        //         << "Layer type: " << getProtocolTypeAsString(curLayer->getProtocol()) << "; " // get layer type
        //         << "Total data: " << curLayer->getDataLen() << " [bytes]; "                   // get total length of the layer
        //         << "Layer data: " << curLayer->getHeaderLen() << " [bytes]; "                 // get the header length of the layer
        //         << "Layer payload: " << curLayer->getLayerPayloadSize() << " [bytes]"         // get the payload length of the layer (equals total length minus header length)
        //         << std::endl;
        // }
    }

    reader->close();

    std::cout
        << "File Read Successfully "
        << "PacketCount = " << packets
        << std::endl;
}