#ifndef PROJECT2REPORT_H
#define PROJECT2REPORT_H
#include "p538project2.h"


Project2Begin

using namespace std;

namespace{
    string LongDash(101,'-');
    string ShortDash(51,'-');
    string SpaceDilimiter(8,' ');
    string getDilimiter(int t){
        return string(t,'\t');
    }
    string ShuoHuan("(ShuoHuan)");
    string Sachin("(Sachin)");
}

class IRoll{
public:    
    virtual string getData() = 0;
    virtual string getData2(){
        return string("");
    }
};

//-----Code below-----
class DHCPData : public IRoll{
private:
    stringstream _data;
public:
    virtual string getData(){
        return _data.str();
    }
};

class UDPData : public IRoll{
private:
    stringstream _data;
public:
    virtual string getData(){
        return _data.str();
    }
};

class TCPData : public IRoll{
private:
    stringstream _data;
public:
    virtual string getData(){
        return _data.str();
    }
};


//------Below is DONE------

class VSTCP_UDPData : public IRoll{
private:
    stringstream _data;
    map<int,int> _TcpDestPort;
    map<int,int> _TcpSrcPort;
    map<int,int> _UdpDestPort;
    map<int,int> _UdpSrcPort;
    map<string,int> _TcpFlags;

private:
    template <typename T> void genData(T& mapData){
        typename T::iterator it;
        for ( it=mapData.begin() ; it != mapData.end(); ++it )
            _data << (*it).first << getDilimiter(1) << (*it).second << endl;
        _data << endl << endl;
    }


public:
    void setTcpDestPort(int port){
        map<int,int>::iterator it;
        it = _TcpDestPort.find(port);
        if(it == _TcpDestPort.end()){
            _TcpDestPort[port] = 1;
        }
        else{
            ++_TcpDestPort[port];
        }
    }
    void setTcpSrcPort(int port){
        map<int,int>::iterator it;
        it = _TcpSrcPort.find(port);
        if(it == _TcpSrcPort.end()){
            _TcpSrcPort[port] = 1;
        }
        else{
            ++_TcpSrcPort[port];
        }
    }
    void setUdpDestPort(int port){
        map<int,int>::iterator it;
        it = _UdpDestPort.find(port);
        if(it == _UdpDestPort.end()){
            _UdpDestPort[port] = 1;
        }
        else{
            ++_UdpDestPort[port];
        }
    }
    void setUdpSrcPort(int port){
        map<int,int>::iterator it;
        it = _UdpSrcPort.find(port);
        if(it == _UdpSrcPort.end()){
            _UdpSrcPort[port] = 1;
        }
        else{
            ++_UdpSrcPort[port];
        }
    }
    void setTcpFlag(string flag){
        map<string,int>::iterator it;
        it = _TcpFlags.find(flag);
        if(it == _TcpFlags.end()){
            _TcpFlags[flag] = 1;
        }
        else{
            ++_TcpFlags[flag];
        }
    }

    virtual string getData(){
        _data << ShuoHuan << endl;
        _data<< "TCP Flag" << endl;
        _data<< "Flag	#packets" << endl;
        _data<< LongDash << endl;        
        genData(_TcpFlags);

        _data << ShuoHuan << endl;
        _data<< "TCP source port" << endl;
        _data<< "Port	#packets" << endl;
        _data<< LongDash << endl;
        genData(_TcpSrcPort);

        _data << ShuoHuan << endl;
        _data<< "TCP destination port" << endl;
        _data<< "Port	#packets" << endl;
        _data<< LongDash << endl;
        genData(_TcpDestPort);

        _data << ShuoHuan << endl;
        _data<< "UDP source port" << endl;
        _data<< "Port	#packets" << endl;
        _data<< LongDash << endl;
        genData(_UdpSrcPort);

        _data << ShuoHuan << endl;
        _data<< "UDP destination port" << endl;
        _data<< "Port	#packets" << endl;
        _data<< LongDash << endl;
        genData(_UdpDestPort);

        return _data.str();
    }
};


/**
  * ARP Data Collection
  * ShuoHuan
  */
class IPData : public IRoll{
private:
    stringstream _data;
    map<string,int> _destIpPackets;
    map<string,int> _srcIpPackets;
public:
    void setDestIP(string IP){
        map<string,int>::iterator it;
        it = _destIpPackets.find(IP);
        if(it == _destIpPackets.end()){
            _destIpPackets[IP] = 1;
        }
        else{
            ++_destIpPackets[IP];
        }
    }
    void setSrcIP(string IP){
        map<string,int>::iterator it;
        it = _srcIpPackets.find(IP);
        if(it == _destIpPackets.end()){
            _srcIpPackets[IP] = 1;
        }
        else{
            ++_srcIpPackets[IP];
        }
    }
    virtual string getData(){
        _data << ShuoHuan << endl;
        _data << "Source IP Address" << endl;
        _data << "IP Address		#packets" << endl;
        _data << LongDash << endl;
        map<string,int>::iterator it;
        for ( it=_srcIpPackets.begin() ; it != _srcIpPackets.end(); ++it )
            _data << (*it).first << getDilimiter(2) << (*it).second << endl;
        _data << endl << endl;
        _data << ShuoHuan << endl;
        _data << "Destination IP Address" << endl;
        _data << "IP Address		#packets" << endl;
        _data << LongDash << endl;
        for ( it=_destIpPackets.begin() ; it != _destIpPackets.end(); ++it )
            _data << (*it).first << getDilimiter(2) << (*it).second << endl;
        return _data.str();
    }
};


/**
  * ARP Data Collection
  * ShuoHuan
  */
class ArpData : public IRoll{
private:
    map<string,string> _macIP;
    stringstream _data;
private:
    void genData(){
        map<string,string>::iterator it;
        for ( it=_macIP.begin() ; it != _macIP.end(); ++it )
            _data << (*it).first << (((*it).first.length() < 16) ? getDilimiter(2) : getDilimiter(1)) << (*it).second << endl;
    }
public:
    void addMacIp(string amac,string aip){
        map<string,string>::iterator it;
        it = _macIP.find(amac);
        if(it == _macIP.end()){
            _macIP[amac] = aip;
        }
    }
    virtual string getData(){
        _data << ShuoHuan << endl;
        _data << "Unique ARP participants" << endl;
        _data << "MAC Address		IP Address" <<endl;
        _data << LongDash << endl;
        genData();
        return _data.str();
    }
};



/**
  * PacketHeader Data Collection
  * ShuoHuan
  */
class PacketHeaderData : public IRoll{
private:
    stringstream _data;
    time_t _startDate;
    time_t _endDate;
    time_t _duration;
    int _anchor;
    bpf_u_int32 _totalPacket;
    bpf_u_int32 _maxPacket;
    bpf_u_int32 _minPacket;
    bpf_u_int32 _avgPacket;
public:
    PacketHeaderData():_startDate(0),_endDate(0),_duration(0),_anchor(0),_totalPacket(0),_maxPacket(0),_minPacket(0),_avgPacket(0){}

    void setDate(time_t secs){
        ++_anchor;
        if(_anchor==1){
            _startDate = secs;
        }
        else{
            _endDate = secs;
        }
    }

    void setPacket(bpf_u_int32 _packetlen){
        _totalPacket+=_packetlen;
        if(_maxPacket < _packetlen)
            _maxPacket = _packetlen;
        if(_minPacket > _packetlen)
            _minPacket = _packetlen;
    }

    virtual string getData(){
        struct tm* StartTime =  localtime (&_startDate);

        _data.str("");
        _data << ShuoHuan << endl;
        _data << "Packet capture summary:" << endl;
        _data << "Capture start date - " << 1900 +StartTime->tm_year << "-" << StartTime->tm_mon << "-" << StartTime->tm_mday << " " << StartTime->tm_hour << ":" << StartTime->tm_min << ":" << StartTime->tm_sec << " " << StartTime->tm_zone << endl;
        //        cout << "_endDate " << _endDate << endl;
        //        cout << "_endDate - _startDate " << _endDate - _startDate << endl;
        _data << "Capture duration   - " << _endDate - _startDate << " seconds" <<  endl;
        _data << "Packets in capture - " << _anchor <<" packets"<<endl;
        return _data.str();
    }

    virtual string getData2(){
        _data.str("");
        _data << ShuoHuan << endl;
        _data<< "Packet Summary:" << endl;
        _data<< "Minimum Packet Size: " << _minPacket << endl;
        _data<< "Maximum Packet Size: " << _maxPacket << endl;
        _data<< "Average Packet Size: " << (_avgPacket ? _avgPacket : (_avgPacket = _totalPacket/_anchor)) << endl;

        return _data.str();
    }
};

/**
  * Ethernet Data Collection
  * ShuoHuan
  */
class EthernetData : public IRoll{
private:
    stringstream _data;
    map<string,unsigned int> SrcMacPackets;
    map<string,unsigned int> DesMacPackets;
    map<string,unsigned int> ProtoPackets;
    template<typename ET,typename IN>void addMac(ET& et, IN inMac){
        typename ET::iterator it;
        it = et.find(inMac);
        if(it == et.end()){
            et[inMac] = 1;
        }
        else{
            et[inMac] = ++et[inMac];
        }
    }

    template<int SD,typename ET>void genData(ET& et){
        typename ET::iterator it;
        if(SD == 0){/*dynamic*/
            for ( it=et.begin() ; it != et.end(); ++it )
                _data << (*it).first << (((*it).first.length() < 16) ? getDilimiter(2) : getDilimiter(1)) << (*it).second << endl;
        }
        else{
            string DILIMITER = getDilimiter(SD);
            for ( it=et.begin() ; it != et.end(); ++it )
                _data << (*it).first << DILIMITER << (*it).second << endl;
        }
    }

public:
    void addSrcMac(string inMac){
        addMac(SrcMacPackets,inMac);
    }
    void addDesMac(string inMac){
        addMac(DesMacPackets,inMac);
    }
    void addProtoMac(uint16_t inProto){
        if(inProto == ETHERTYPE_IP){
            addMac(ProtoPackets,string("IP"));
            return;
        }
        if(inProto == ETHERTYPE_ARP){
            addMac(ProtoPackets,string("ARP"));
            return;
        }
        if(inProto == ETHERTYPE_REVARP){
            addMac(ProtoPackets,string("RARP"));
            return;
        }
        stringstream ss;
        ss << inProto;
        cout << "SHIH" << ss.str() << endl;
        addMac(ProtoPackets,ss.str());
    }

    virtual string getData(){
        _data << ShuoHuan << endl;
        _data << "Source Ethernet Address" << endl;
        _data << "MAC Address		#packets" << endl;
        _data << LongDash << endl;
        genData<0>(SrcMacPackets);
        _data << endl;
        _data << ShuoHuan << endl;
        _data << "Destination Ethernet Address" << endl;
        _data << "MAC Address		#packets" << endl;
        _data << LongDash << endl;
        genData<0>(DesMacPackets);
        _data << endl;
        _data << ShuoHuan << endl;
        _data << "Network Layer Protocol Summary" << endl;
        _data << "Protocol	#packets" << endl;
        _data << LongDash << endl;
        genData<2>(ProtoPackets);
        _data << endl;
        return _data.str();
    }
};





class Report{
private:
    filebuf _reportFb;
    ostream _feedMe;
public:
    Report(string whichFile):_reportFb(),_feedMe(&_reportFb)
    {
        stringstream filename;
        string tmps = whichFile.substr(0,whichFile.length()-5);
        std::transform(tmps.begin(), tmps.begin()+1,tmps.begin(), ::toupper);
        filename << "output" << tmps << ".txt";
        _reportFb.open(filename.str().c_str(),ios_base::out | ios_base::app);
    }
    void writeData(IRoll& ir){
        _feedMe << ir.getData() << endl;
        if(typeid(PacketHeaderData) == typeid(ir) ){
            _feedMe << ir.getData2() << endl;
        }
        _feedMe.flush();

    }
    ~Report(){
        _reportFb.close();
    }
};


struct ReportObj{
    PacketHeaderData packetHeaderData; /*ShuoHuan*/
    EthernetData etherData;/*ShuoHuan*/
    ArpData arpData;/*ShuoHuan*/
    IPData ipData;
    TCPData tcpData;
    UDPData udpData;
    DHCPData dhcpData;
    VSTCP_UDPData vsTcpUdpData;
};



//ostream& PacketSummary(ostream& _ost){
//    _ost << "Packet capture summary: " << endl;

//    time_t _time = time(NULL);
//    struct tm * timeinfo = localtime( &_time );

//    return _ost;
//}


Project2End
#endif // PROJECT2REPORT_H
