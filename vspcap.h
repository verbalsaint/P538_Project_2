#ifndef VSPCAP_H
#define VSPCAP_H
#include "p538project2.h"
#include "verbalsaint.h"
#include "vsgeneralexception.h"
#include "callbackfunc.h"


VERBALSAINTNS(VSPCAP)
UV(VSEXCEPTION)

using namespace PROJECT2;
using std::string;
using std::stringstream;
using std::cout;
using std::endl;

class VSPcap{
private:
    string _fileName;
    pcap_t* _handle;
    Report _rp;
    ReportObj reportObj;
    char errbuf[PCAP_ERRBUF_SIZE];


private:
    bool check(){
        if(_handle == NULL || _handle == 0) return false;
        else return true;
    }

    void doReport(){
        _rp.writeData(reportObj.packetHeaderData);
        _rp.writeData(reportObj.etherData);
        _rp.writeData(reportObj.arpData);
        _rp.writeData(reportObj.ipData);
        _rp.writeData(reportObj.tcpData);
        _rp.writeData(reportObj.udpData);
        _rp.writeData(reportObj.dhcpData);
        _rp.writeData(reportObj.vsTcpUdpData);
    }

public:
    VSPcap(string fileName):_fileName(fileName),_handle(NULL),_rp(fileName){
        _handle = pcap_open_offline(_fileName.c_str(),errbuf);        
    }

    int checkPcap_datalink(){
        if(!check()) return -1;        
        int linklayerType = 0;
        linklayerType = pcap_datalink(_handle);
        return linklayerType;
    }

    //net * ether arp ip tcp udp
    //1. ip proto tcp
    //2. ether proto ip
    //3. ether proto arp
    //4. ether proto tcp
    int compile(string cpstring/* pcap-filter */){
        if(checkPcap_datalink() !=1) throw VSGeneralExcaption("It's not ethernet!");
        if(!check()) return -1;
        struct bpf_program bpf;
        bpf_u_int32 netmask = 0xFFFFFFFF;
        int errnop = 0;
        errnop = pcap_compile(_handle, &bpf , cpstring.c_str(), 0,/*netmask*/PCAP_NETMASK_UNKNOWN);
        if(errnop!=0){
            stringstream sserr;
            sserr << "pcap_compile error : " ;
            sserr << pcap_geterr(_handle) << endl;
            throw VSGeneralExcaption(sserr.str());
        }
        errnop = pcap_setfilter(_handle, &bpf);
        if(errnop!=0){
            stringstream sserr;
            sserr << "pcap_setfilter error : " ;
            sserr << pcap_geterr(_handle) << endl;
            throw VSGeneralExcaption(sserr.str());
        }
        return 0;
    }

    int Start(){
        if(!check()) return -1;
        int errorno=0;
        errorno = pcap_loop(_handle,/*infinite*/0,CallBack::giveme_fun,(u_char*)(&reportObj));
        if(errorno != 0){
            /*
             * -1 for errorno
             * -2 for pcap_breakloop()
             */

            stringstream sserr;
            sserr << "pcap_loop error , ErrorNo : " ;
            sserr << errorno << ", Error message : " ;
            sserr << pcap_geterr(_handle) << endl;
            throw VSGeneralExcaption(sserr.str());
        }
        doReport();
        return 0;
    }
    ~VSPcap(){
        if(check()) pcap_close(_handle);
    }
};

VERBALSAINTNSEND
#endif // VSPCAP_H
