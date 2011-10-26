/*
  P538 Project 2
  2011 Oct 17
  Team member : ShuoHuan Chang , Sachin Joshi

  FrameWork : ShuoHuan Chang
  Please refer to README to see the task dispatch for each team member.
*/

#include "verbalsaint.h"
#include "vsgeneralexception.h"
#include "p538project2.h"
#include "inputfiles.h"
#include "vspcap.h"

UV(VSPCAP)
UV(VSEXCEPTION)
using namespace PROJECT2;

int main()
{
    using namespace std;
    P2Files Test;
    cout << Test.cFile_Dhcp << endl;
    cout << Test.cFile_Tracerout << endl;
    cout << Test.cFile_Wget << endl;
    //------------
    VSPcap PcapWget(P2Files().cFile_Wget);
    cout << "Check with pcap_datalink for file " << P2Files().cFile_Wget << " : " << PcapWget.checkPcap_datalink() << endl;

    // and \\tcp or \\udp
//    PcapWget.compile("arp or ip or tcp or udp");
    PcapWget.compile("");
    PcapWget.Start();

    //------------
    VSPcap PcapTracerout(P2Files().cFile_Tracerout);
    cout << "Check with pcap_datalink for file " << P2Files().cFile_Tracerout << " : " << PcapTracerout.checkPcap_datalink() << endl;

    // and \\tcp or \\udp
    PcapTracerout.compile("");
    PcapTracerout.Start();

    //------------
    VSPcap PcapDhcp(P2Files().File_Dhcp);
    cout << "Check with pcap_datalink for file " << P2Files().File_Dhcp << " : " << PcapDhcp.checkPcap_datalink() << endl;


    // and \\tcp or \\udp
    PcapDhcp.compile("");
    PcapDhcp.Start();
    //------------
    return 0;
}

