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
    /**
      * (Sachin)
      */
    static void DHCPHeader(ReportObj* reportObj,const u_char *packet)
    {
        struct ether_header* EtherHeader = (struct ether_header*)(packet);
        uint16_t frameType = ntohs(EtherHeader->ether_type);

        if(frameType == ETHERTYPE_IP)
        {
            struct ip* IPHeader = (struct ip*)(packet + ETH_HLEN);

            if (IPHeader->ip_p == IPPROTO_UDP)
            {
                struct udphdr *UDPHeader = (struct udphdr*)(packet + sizeof(struct ether_header) + (IPHeader->ip_hl)*4) ;

                struct dhcp_packet *DHCPHeader = (struct dhcp_packet*)(packet + ETH_HLEN + (IPHeader->ip_hl)*4 + sizeof(struct udphdr));

                if (ntohs(UDPHeader->dest) == 68 || ntohs(UDPHeader->dest) == 67)		// destination port
                {
                    if (DHCPHeader->op == 1)	// if client requests
                    {
                        struct ether_addr host;
                        memcpy(&host, DHCPHeader->chaddr, sizeof(host));
                        reportObj->dhcpData.addClientMacIDs(ether_ntoa(&host));
                    }

                    if (DHCPHeader->op == 2)	// when server responds
                    {
                        string strServerIP = inet_ntoa(DHCPHeader->siaddr) ;
                        if(strServerIP != "0.0.0.0")
                            reportObj->dhcpData.addServerIp(inet_ntoa(DHCPHeader->siaddr));
                        else
                            reportObj->dhcpData.addServerIp(inet_ntoa(IPHeader->ip_src));
                    }
                }

                for(int i=0;i<255;i++)
                {
                    if(DHCPHeader->options[i] == 53 && DHCPHeader->options[i+2] == 1)
                    {

                        reportObj->dhcpData.addFlags("DHCPDISCOVER");
                    }

                    else if(DHCPHeader->options[i] == 53 && DHCPHeader->options[i+2] == 2)
                    {
                        reportObj->dhcpData.addFlags("DHCPOFFER") ;
                    }

                    else if(DHCPHeader->options[i] == 53 && DHCPHeader->options[i+2] == 3)
                    {
                        reportObj->dhcpData.addFlags("DHCPREQUEST");
                    }

                    else if(DHCPHeader->options[i] == 53 && DHCPHeader->options[i+2] == 5)
                    {
                        reportObj->dhcpData.addFlags("DHCPACK");
                    }
                }

            }

        }

    }

    /**
      * (Sachin)
      */
    static void TCPHeader(ReportObj* reportObj,const u_char *packet)
    {
        struct ether_header* EtherHeader = (struct ether_header*)(packet);
        uint16_t frameType = ntohs(EtherHeader->ether_type);

        if(frameType == ETHERTYPE_IP)
        {
            struct ip* IPHeader = (struct ip*)(packet + ETH_HLEN);
            struct tcphdr *TCPHeader = (struct tcphdr*)(packet + sizeof(struct ether_header) + (IPHeader->ip_hl)*4) ;

            // find out transport layer protocols
            if (IPHeader->ip_p == IPPROTO_UDP)
            {
                reportObj->tcpData.addTLProtocols("UDP") ;
            }

            else if (IPHeader->ip_p == IPPROTO_TCP)
            {
                reportObj->tcpData.addTLProtocols("TCP") ;	// add to list of protocols

                reportObj->tcpData.addSrcPort(ntohs(TCPHeader->source)) ;
                reportObj->tcpData.addDesPort(ntohs(TCPHeader->dest)) ;

            }
            else
            {
                stringstream s ;
                s << (int)IPHeader->ip_p ;
                string strp = s.str() ;
                reportObj->tcpData.addTLProtocols(strp) ;
            }
        }
    }

    /**
      * (Sachin)
      */
    static void UDPHeader(ReportObj* reportObj,const u_char *packet)
    {
        struct ether_header* EtherHeader = (struct ether_header*)(packet);
        uint16_t frameType = ntohs(EtherHeader->ether_type);

        if(frameType == ETHERTYPE_IP)
        {
            struct ip* IPHeader = (struct ip*)(packet + ETH_HLEN);
            struct udphdr *UDPHeader = (struct udphdr*)(packet + sizeof(struct ether_header) + (IPHeader->ip_hl)*4);

            char *s,*d;
            in_addr_t ip_s, ip_d ;

            s = inet_ntoa(IPHeader->ip_src);
            d = inet_ntoa(IPHeader->ip_dst);
            ip_s = inet_addr(s);
            ip_d = inet_addr(d);

            unsigned short *source_ip = (unsigned short*) &ip_s ;
            unsigned short *destination_ip = (unsigned short*) &ip_d ;

            // find out transport layer protocols
            if (IPHeader->ip_p == IPPROTO_UDP)
            {
                if (UDPHeader-> check == 0)	// is checksum used?
                    reportObj->udpData.nUnused ++ ;
                else	// yes, checksum is used
                {
                    unsigned short need_padding = 0 ;
                    unsigned short udp_length = ntohs(UDPHeader->len) ;
                    unsigned short udp_protocol_number = 17 ;
                    unsigned short intermediate_sum =  0 ;
                    unsigned long final_sum = 0 ;
                    int i ;

                    if (UDPHeader->check == 0xFFFF )
                        UDPHeader->check  = 0x0000 ;

                    unsigned short *buf = (unsigned short *)UDPHeader ;

                    if((udp_length & 1) == 1)
                    {
                        need_padding = 1 ;
                        *(buf+udp_length) = 0 ;
                    }

                    // make 16 bit words out of every two adjacent 8 bit words and
                    // calculate the sum of all 16 bit words
                    for ( i=0; i< (udp_length+need_padding) ;i=i+2)
                    {
                        intermediate_sum = ((*(buf+i)<<8) & 0xFF00) + ((*(buf+i+1)) & 0xFF) ;
                        final_sum += (unsigned long)intermediate_sum ;
                    }

                    // add the UDP pseudo header which contains the IP source and destination addresses
                    for ( i=0;i<4;i=i+2)
                    {
                        intermediate_sum =((*(source_ip + i)<<8) & 0xFF00) + (*(source_ip+i+1) & 0xFF);
                        final_sum += intermediate_sum ;
                    }

                    for ( i=0;i<4;i=i+2)
                    {
                        intermediate_sum =((*(destination_ip + i)<<8) & 0xFF00) + (*(destination_ip+i+1)&0xFF);
                        final_sum += intermediate_sum ;
                    }

                    // the protocol number and the length of the UDP packet
                    final_sum += udp_protocol_number + udp_length;

                    // keep only the last 16 bits of the 32 bit calculated sum and add the carries
                    while (final_sum>>16)
                    {
                        final_sum = (final_sum & 0xFFFF) + (final_sum >> 16);
                    }

                    // Take the one's complement of sum
                    final_sum = ~final_sum;

                    int chk = (uint16_t)(~final_sum) ;

                    if (chk)
                        reportObj->udpData.nCorrrectCC ++ ;
                    else
                        reportObj->udpData.nInCorrectCC ++ ;
                }

                reportObj->udpData.addSrcPort(ntohs(UDPHeader->source)) ;
                reportObj->udpData.addDesPort(ntohs(UDPHeader->dest)) ;
            }
        }

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
