#ifndef VSGENERALEXCEPTION_H
#define VSGENERALEXCEPTION_H
#include "verbalsaint.h"
#include <exception>
#include <string>

VERBALSAINTNS(VSEXCEPTION)

using std::string;

class VSGeneralExcaption : public std::exception{
private:
    string errorstr;
public:
    VSGeneralExcaption(string errorm):errorstr(errorm){}
    virtual ~VSGeneralExcaption() throw(){

    }
    virtual const char* what() const throw(){
        return errorstr.c_str();
    }
};

VERBALSAINTNSEND
#endif // VSGENERALEXCEPTION_H
