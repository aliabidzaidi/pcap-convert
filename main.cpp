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

    pcpp::IFileReaderDevice *reader = pcpp::IFileReaderDevice::getReader("QinQ.pcap.cap");
    // pcpp::IFileReaderDevice *reader = pcpp::IFileReaderDevice::getReader("dns_tcp.pcapng");

    if (reader == NULL || !reader->open())
    {
        std::cerr << "Error in Reading file" << std::endl;
        return 1;
    }

    int packets = 0;
    pcpp::RawPacket rawPacket;


    while (reader->getNextPacket(rawPacket))
    {
        packets++;
        std::cout << "-------------------Packet " << packets << "-------------------" << std::endl;
        pcpp::Packet parsedPacket(&rawPacket);

        // Layer 2
        // Data Link Layer is not Ethernet drop!
        pcpp::EthLayer *ethernetLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
        if (ethernetLayer == NULL)
        {
            std::cerr << "Something went wrong, couldn't find Ethernet layer" << std::endl;
            std::cout << "-----------------------------------------------\n"
                      << std::endl;
            continue;
        }

        std::cout
            << "Src  MAC address " << ethernetLayer->getSourceMac() << std::endl
            << "Dest MAC address " << ethernetLayer->getDestMac() << std::endl
            << "Ethernet type = 0x" << pcpp::netToHost16(ethernetLayer->getEthHeader()->etherType) << std::endl;

        // bool hasVlan = parsedPacket.isPacketOfType<pcpp::VLAN>();
        if (!parsedPacket.isPacketOfType(pcpp::VLAN))
        {
            std::cerr << "Doesn't contain a VLAN, pass!" << std::endl;
            std::cout << "-----------------------------------------------\n"
                      << std::endl;
            continue;
        }

        // Drop all packets except coming from vlanID

        pcpp::VlanLayer *vlanLayer = parsedPacket.getLayerOfType<pcpp::VlanLayer>();
        if (vlanLayer == NULL)
        {
            std::cerr << "Vlan layer doesn't exist" << std::endl;
            std::cout << "-----------------------------------------------\n"
                      << std::endl;
            continue;
        }

        std::cout << "Vlan ID " << vlanLayer->getVlanID() << std::endl;

        // Layer 3
        // if packet ip version != argsIPVersion drop

        pcpp::IPv4Layer *ipv4Layer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();

        if (ipv4Layer == NULL)
        {
            std::cerr << "Ipv4 Layer is missing" << std::endl;
            std::cout << "-----------------------------------------------\n"
                      << std::endl;
            continue;
        }

        std::cout
            << "Src  IP: " << ipv4Layer->getSrcIPAddress() << std::endl
            << "Dest IP: " << ipv4Layer->getDstIPAddress() << std::endl
            << "TTL: " << (int)ipv4Layer->getIPv4Header()->timeToLive << std::endl
            << "IP Id: " << pcpp::netToHost16(ipv4Layer->getIPv4Header()->ipId) << std::endl;

        // TODO: ALter TTL to 60

        // If L4 = ICMP Drop
        // bool hasICMP = parsedPacket.isPacketOfType<pcpp::ICMP>();
        if (parsedPacket.isPacketOfType(pcpp::ICMP))
        {
            std::cerr << "Is an ICMP Packet, pass!" << std::endl;
            std::cout << "-----------------------------------------------\n"
                      << std::endl;
            continue;
        }

        // If L4 = UDP && DNS
        if (parsedPacket.isPacketOfType(pcpp::UDP) && parsedPacket.isPacketOfType(pcpp::DNS))
        {
            // Then packet craft serverAddress & port replace by args fields
        }

        std::cout << "-----------------------------------------------\n"
                  << std::endl;
    }

    reader->close();

    std::cout
        << "File Read Successfully "
        << "PacketCount = " << packets
        << std::endl;
}