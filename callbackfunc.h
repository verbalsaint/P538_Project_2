#ifndef CALLBACKFUNC_H
#define CALLBACKFUNC_H
#include "p538project2.h"
#include "project2report.h"
#include "vsgeneralexception.h"


Project2Begin

using namespace std;
UV(VSEXCEPTION)

class CallBack{
    private:

    static void DHCPHeader(ReportObj* reportObj,const u_char *packet){

    }



    static void TCPHeader(ReportObj* reportObj,const u_char *packet){

    }

    static void UDPHeader(ReportObj* reportObj,const u_char *packet){

    }

    //------------------


    /**
      * ShuoHuan
      */
    //Unique source and destination TCP and UDP ports, along with the total number of packets containing each port number.
    //**For TCP, report the number of packets containing each flag.
    static void VSTCPUDPHeader(ReportObj* reportObj,const u_char *packet){
        struct ether_header* EtherHeader = (struct ether_header*)(packet);
        uint16_t frameType = ntohs(EtherHeader->ether_type);
        if(frameType != ETHERTYPE_IP) return;
        struct iphdr* IpHeader = (struct iphdr*)(packet + ETH_HLEN);
        uint16_t protocolType = IpHeader->protocol;
        if(protocolType == IPPROTO_TCP){
            //            u_int16_t fin:1;
            //            u_int16_t syn:1;
            //            u_int16_t rst:1;
            //            u_int16_t psh:1;
            //            u_int16_t ack:1;
            //            u_int16_t urg:1;
            struct tcphdr* TcpHeader =(struct tcphdr*)(packet + ETH_HLEN + ((unsigned int)(IpHeader->ihl) << 2));
            if(TcpHeader->urg)reportObj->vsTcpUdpData.setTcpFlag("URG");
            if(TcpHeader->ack)reportObj->vsTcpUdpData.setTcpFlag("ACK");
            if(TcpHeader->psh)reportObj->vsTcpUdpData.setTcpFlag("PSH");
            if(TcpHeader->rst)reportObj->vsTcpUdpData.setTcpFlag("RST");
            if(TcpHeader->syn)reportObj->vsTcpUdpData.setTcpFlag("SYN");
            if(TcpHeader->fin)reportObj->vsTcpUdpData.setTcpFlag("FIN");
            reportObj->vsTcpUdpData.setTcpSrcPort(ntohs(TcpHeader->source));
            reportObj->vsTcpUdpData.setTcpDestPort(ntohs(TcpHeader->dest));
        }

        if(protocolType == IPPROTO_UDP){
            struct udphdr* UdpHeader =(struct udphdr*)(packet + ETH_HLEN+ ((IpHeader->ihl) << 2));
            reportObj->vsTcpUdpData.setUdpSrcPort(ntohs(UdpHeader->source));
            reportObj->vsTcpUdpData.setUdpDestPort(ntohs(UdpHeader->dest));
        }

    }


    /**
      * ShuoHuan
      */
    //Unique source and destination IP addresses, along with the total number of packets containing each address. Represent IPv4 addresses in the standard a.b.c.d notation.
    static void IPHeader(ReportObj* reportObj,const u_char *packet){
        struct ether_header* EtherHeader = (struct ether_header*)(packet);
        uint16_t frameType = ntohs(EtherHeader->ether_type);
        if(frameType != ETHERTYPE_IP) return;
        struct iphdr* IpHeader = (struct iphdr*)(packet + ETH_HLEN);
        char SRCIP[INET_ADDRSTRLEN];

        if(inet_ntop(AF_INET,(void*)&IpHeader->saddr,SRCIP,INET_ADDRSTRLEN)==NULL)
            throw VSGeneralExcaption("inet_ntop src ip convert error");
        reportObj->ipData.setSrcIP(SRCIP);


        char DESTIP[INET_ADDRSTRLEN];
        if(inet_ntop(AF_INET,(void*)&IpHeader->daddr,DESTIP,INET_ADDRSTRLEN)==NULL)
            throw VSGeneralExcaption("inet_ntop dest ip convert error");
        reportObj->ipData.setDestIP(DESTIP);
    }


    /**
      * ShuoHuan
      */
    static void PackerHeader(ReportObj* reportObj,const struct pcap_pkthdr *header){
        reportObj->packetHeaderData.setDate(header->ts.tv_sec);
        reportObj->packetHeaderData.setPacket(header->len);
    }

    /**
      * ShuoHuan
      */
    static void EthernetHeader(ReportObj* reportObj,const u_char *packet){
        struct ether_header* EtherHeader = (struct ether_header*)(packet);
        struct ether_addr host;
        memcpy(&host, EtherHeader->ether_dhost, sizeof(host));
        reportObj->etherData.addDesMac(ether_ntoa(&host));
        memcpy(&host, EtherHeader->ether_shost, sizeof(host));
        reportObj->etherData.addSrcMac(ether_ntoa(&host));
        uint16_t frameType = ntohs(EtherHeader->ether_type);
        reportObj->etherData.addProtoMac(frameType);
//        reportObj->etherData.addProtoMac(EtherHeader->ether_type);
    }

    /**
      * ShuoHuan
      */
    static void ArpHeader(ReportObj* reportObj,const u_char *packet){
        struct ether_header* EtherHeader = (struct ether_header*)(packet);
        uint16_t frameType = ntohs(EtherHeader->ether_type);
        if(frameType == ETHERTYPE_ARP){
            struct vsarphdr* ArpHeader = (struct vsarphdr*)(packet + ETH_HLEN);
            if(ntohs(ArpHeader->ar_hrd) ==ARPHRD_ETHER && ntohs(ArpHeader->ar_pro) == ETH_P_IP && ArpHeader->ar_hln == 6 && ArpHeader->ar_pln == 4){
                uint16_t aropno = ntohs(ArpHeader->ar_op);
                if(aropno == ARPOP_REQUEST){
                    struct ether_addr ea;
                    memcpy(&ea,ArpHeader->__ar_sha,ETH_ALEN);
                    struct in_addr ia;
                    memcpy(&ia,ArpHeader->__ar_sip,sizeof(ArpHeader->__ar_sip));
                    reportObj->arpData.addMacIp(ether_ntoa(&ea),inet_ntoa(ia));
                }
                if(aropno == ARPOP_REPLY){
                    struct ether_addr ea;
                    memcpy(&ea,ArpHeader->__ar_sha,ETH_ALEN);
                    struct in_addr ia;
                    memcpy(&ia,ArpHeader->__ar_sip,sizeof(ArpHeader->__ar_sip));
                    reportObj->arpData.addMacIp(ether_ntoa(&ea),inet_ntoa(ia));

                    struct ether_addr ea2;
                    memcpy(&ea2,ArpHeader->__ar_tha,ETH_ALEN);
                    struct in_addr ia2;
                    memcpy(&ia2,ArpHeader->__ar_tip,sizeof(ArpHeader->__ar_sip));
                    reportObj->arpData.addMacIp(ether_ntoa(&ea2),inet_ntoa(ia2));
                }
            }
        }
    }

    public:
    static void giveme_fun(u_char *args, const struct pcap_pkthdr *header,
    const u_char *packet){
        using namespace std;

        ReportObj* reportObj = (ReportObj*)(args);

        /*
            Packets Header (ShuoHuan)
          */
        PackerHeader(reportObj,header);

        /*
            Ethernet Header (ShuoHuan)
          */
        EthernetHeader(reportObj,packet);

        /*
            Arp Header (ShuoHuan)
          */
        ArpHeader(reportObj,packet);

        /*
            IP Header (ShuoHuan)
          */
        IPHeader(reportObj,packet);

        /*
            TCP UDP Header (ShuoHuan)
          */
        VSTCPUDPHeader(reportObj,packet);


        /*
            TCP Header (Joshi)
          */
        TCPHeader(reportObj,packet);

        /*
            UDP Header (Joshi)
          */
        UDPHeader(reportObj,packet);

        /*
            DHCP Header (Joshi)
          */
        DHCPHeader(reportObj,packet);

        //        struct ether_header* EtherHeader;
        //        struct arphdr* ArpHeader;
        //        struct ip* IpHeader;

    }
};


Project2End
#endif // CALLBACKFUNC_H
