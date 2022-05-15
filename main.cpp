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
#include "getopt.h"
#include "DnsLayer.h"

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

void printUsage()
{
    std::cout
        << "-i              : Path of the input pcap file" << std::endl
        << "-o              : Path of the output pcap file" << std::endl
        << "--vlan          : VLAN ID (e.g 10000)" << std::endl
        << "--ip-version    : Version of IP either e.g IPv4 or IPv6" << std::endl
        << "--ttl           : Decrease ttl for TCP packets (e.g 60)" << std::endl
        << "--dns-addr      : DNS Address with this value, if UDP+DNS Packet (e.g www.anuvu.com)" << std::endl
        << "--dns-port      : DNS Port to be replaced by this value, if UDP+DNS Packet (e.g 4500)" << std::endl
        << std::endl;
}

int num = -1;
bool is_beep = false;
float sigma = 2.034;
std::string write_file = "default_file.txt";
std::string inputFile = "in_file.pcap";
std::string outputFile = "out_file.pcap";
std::string ipVersion = "IPv4";
std::string dnsAddress = "";
uint16_t vlanId = 0;
int ttl = 0;
int dnsPort = 0;

void ProcessArgs(int argc, char **argv)
{
    const char *const short_opts = "i:o:V:tdpIh";
    const option long_opts[] = {
        {"input-file", required_argument, nullptr, 'i'},
        {"output-file", required_argument, nullptr, 'o'},
        {"vlan", required_argument, nullptr, 'V'},
        {"ip-version", required_argument, nullptr, 'I'},
        {"ttl", required_argument, nullptr, 't'},
        {"dns-addr", required_argument, nullptr, 'd'},
        {"dns-port", required_argument, nullptr, 'p'},
        {"help", no_argument, nullptr, 'h'},
        {0, 0, 0, 0}
        // {"", optional_argument, 0, ''},
    };

    while (true)
    {
        const auto opt = getopt_long(argc, argv, short_opts, long_opts, nullptr);

        if (-1 == opt)
            break;

        switch (opt)
        {
        case 'i':
            inputFile = std::string(optarg);
            std::cout << "Input file set to: " << inputFile << std::endl;
            break;

        case 'o':
            outputFile = std::string(optarg);
            std::cout << "Input file set to: " << outputFile << std::endl;
            break;

        case 'V':
            vlanId = std::stoi(optarg);
            std::cout << "VLAN ID set to: " << vlanId << std::endl;
            break;

        case 'I':
            ipVersion = std::string(optarg);
            std::cout << "IP Version set to: " << ipVersion << std::endl;
            break;

        case 't':
            ttl = std::stoi(optarg);
            std::cout << "TTL set to:" << ttl << std::endl;
            break;

        case 'd':
            dnsAddress = std::string(optarg);
            std::cout << "DNS Address set to: " << dnsAddress << std::endl;
            break;

        case 'p':
            dnsPort = std::stoi(optarg);
            std::cout << "DNS Port set to: " << dnsPort << std::endl;
            break;

        case 'h': // -h or --help
        case '?': // Unrecognized option
        default:
            printUsage();
            break;
        }
    }
}

int main(int argc, char *argv[])
{
    ProcessArgs(argc, argv);

    // TODO: Add inputFile and outputFile name

    pcpp::IFileReaderDevice *reader = pcpp::IFileReaderDevice::getReader("QinQ.pcap.cap");
    // pcpp::IFileReaderDevice *reader = pcpp::IFileReaderDevice::getReader("dns_tcp.pcapng");
    pcpp::PcapFileWriterDevice pcapWriter("output.pcap", pcpp::LINKTYPE_ETHERNET);


    if (reader == NULL || !reader->open())
    {
        std::cerr << "Error in Reading file" << std::endl;
        return 1;
    }

    if (!pcapWriter.open()){
        std::cerr << "Error opening output pcap file" << std::endl;
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
        
        vlanLayer->setVlanID(vlanId);


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

        if (ttl != 0)
            ipv4Layer->getIPv4Header()->timeToLive = ttl;

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
            pcpp::DnsLayer *dnsLayer = parsedPacket.getLayerOfType<pcpp::DnsLayer>();

            if (dnsAddress != "")
            {
                dnsLayer->addQuery(dnsAddress, pcpp::DNS_TYPE_A, pcpp::DNS_CLASS_IN);
            }
        }

        std::cout << "-----------------------------------------------\n"
                  << std::endl;


        pcapWriter.writePacket(rawPacket);
    }

    
    pcpp::IPcapDevice::PcapStats stats;

    reader->getStatistics(stats);
    std::cout << "Read " << stats.packetsRecv << " packets successfully and " << stats.packetsDrop << " packets could not be read" << std::endl;

    // read stats from pcap writer and print them
    pcapWriter.getStatistics(stats);
    std::cout << "Written " << stats.packetsRecv << " packets successfully to pcap writer and " << stats.packetsDrop << " packets could not be written" << std::endl;


    reader->close();
    pcapWriter.close();

    std::cout
        << "File Read Successfully "
        << "PacketCount = " << packets
        << std::endl;

    delete reader;
}