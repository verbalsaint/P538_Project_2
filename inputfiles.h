#ifndef INPUTFILES_H
#define INPUTFILES_H

#include <string>
#include "p538project2.h"

Project2Begin

using namespace std;

struct P2Files{
private:
    P2Files& operator =(const P2Files&);
    P2Files(const P2Files&);
public:
    string File_Tracerout;
    string File_Wget;
    string File_Dhcp;
    const char* cFile_Tracerout;
    const char* cFile_Wget;
    const char* cFile_Dhcp;    
    P2Files():File_Tracerout("traceroute.pcap"),File_Wget("wget.pcap"),File_Dhcp("dhcp.pcap"),cFile_Tracerout(File_Tracerout.c_str ()),cFile_Wget(File_Wget.c_str ()),cFile_Dhcp(File_Dhcp.c_str())
    {
    }
};


Project2End
#endif // INPUTFILES_H
