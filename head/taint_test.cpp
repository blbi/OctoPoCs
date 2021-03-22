//
//  Jonathan Salwan - Copyright (C) 2013-08
// 
//  http://shell-storm.org
//  http://twitter.com/JonathanSalwan
//
//  Note: Example 3 - http://shell-storm.org/blog/Taint-analysis-with-Pin/
//        Spread the taint in memory/registers and follow your data.
//

#include "pin.H"
//#include "/home/circuit/mypin/pin-3.13-98189-g60a6ef199-gcc-linux/source/include/pin/pin.H"
#include <asm/unistd.h>
#include <fstream>
#include <iostream>
#include <list>
#include <bits/stdc++.h> 
#include <string>
#include <typeinfo>
#include <unistd.h>
#include <time.h>

using namespace std;



struct Address_{
    UINT64 addr;
    UINT64 origin;
};
struct candidateAddress{
    UINT64 addr;
    UINT64 origin;
};
struct REG_{
    REG reg;
    std::vector<UINT64> originlist;
    // UINT64 origin;

    // REG_();
    // REG_(REG r, UINT64 o) : reg(r), origin(o) {}
};
struct Mappedfile{
        UINT64 memory_addr;
        UINT64 file_offset;
        UINT64 size;
};

//bool taintReg(REG, string, UINT64);
//bool taintReg(REG, std::vector<UINT64>);
bool taintReg(REG, string, UINT64, UINT8);
bool taintReg(REG, std::vector<UINT64>);
Address_* isMonitoredMem(UINT64, int);

std::list<Address_> taintedAddress;
std::list<Address_> candidateAddress;
std::list<REG_> taintedRegs;
std::list<UINT64> taintedFile;
std::list<Mappedfile> Mappinglist;
KNOB<string> KnobVulnFunc(KNOB_MODE_WRITEONCE, "pintool", "v", "", "specify vulnerable function name");
KNOB<string> KnobPoCName(KNOB_MODE_WRITEONCE, "pintool", "i", "ori", "specify input poc name");
// std::string filename = "p14"; // pdfinfo 
// std::string filename = "ooo"; //avconv
std::string filename = "ori"; //gif2png

UINT64 filesize;
// UINT64 filesize = 0x568; // pdfinfo
// UINT64 filesize = 0x70; //mupdf
// UINT64 filesize = 0xe2c; //git2png
// UINT64 filesize = 0x18; //avconv
clock_t start_time, end_time;






// const char* vulnfunc = "_ZN7Catalog7getPageEi"; // pdfinfo
// const char* vulnfunc = "opj_j2k_read_header"; // mupdf
// const char* vulnfunc = "ReadImage"; // gif2png
// const char* vulnfunc = "avcodec_decode_audio4"; //avconv

const char* vulnfunc;

//=========temp vari=========
int ffff=0;
UINT64 prev;
UINT64 p;
UINT64 pp;
UINT64 ppp;
UINT64 pppp;
//===========================
FILE* inputfilestream;
UINT64 input_fd;
ADDRINT input_stream;
UINT64 syscall_number;
UINT64 start, size, buf, offset;
UINT64 cur_read_pos = 0;
UINT64 vulnflag = 0;
UINT64 first_flag = 1;
std::list<UINT64> arglist;
std::list<std::list<UINT64> > vuln_arg;
std::list<UINT64> context_list;

INT32 Usage()
{
    cerr << "Ex 3" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}
/*
bool checkAlreadyRegTainted(REG reg)
{
    list<REG>::iterator i;

  for(i = taintedRegs.begin(); i != taintedRegs.end(); i++){
    if (*i == reg){
      return true;
    }
  }
  return false;
}
*/
std::vector<string> split(string str, char delimiter) {
    vector<string> internal;
    stringstream ss(str);
    string temp;
 
    while (getline(ss, temp, delimiter)) {
        internal.push_back(temp);
    }
 
    return internal;
}

VOID removeMemTainted(UINT64 addr)
{
    list<Address_>::iterator i;
    for (i = taintedAddress.begin(); i != taintedAddress.end();){
        Address_ tempaddr = *i;
        if (tempaddr.addr == addr){
            taintedAddress.erase(i++);
            // std::cout << std::hex << "[TAINT]  0x" << addr << " is now freed" << std::endl;
            // return;
        }
        else i++;
    }
    // std::cout << "error on remove tainted address" << std::endl;
}

VOID addMemTainted(UINT64 addr, std::vector<UINT64> origlist)
{   

    for (UINT32 i = 0; i < origlist.size(); i++){
        // Address_ saddr = {addr+i, origlist[origlist.size()-i-1]};
        Address_ saddr = {addr+i, origlist[i]};
        // std::cout << std::hex << "[TAINT]  0x" << addr+i << " is now tainted with " << origlist[i] << std::endl;
        taintedAddress.push_back(saddr);
    }
}
VOID removeMemCandidate(UINT64 addr)
{
    list<Address_>::iterator i;
    for (i = candidateAddress.begin(); i != candidateAddress.end();){
        Address_ tempaddr = *i;
        if (tempaddr.addr == addr){
            candidateAddress.erase(i++);
            // std::cout << std::hex << "[CANDI]  0x" << addr << " is now freed" << std::endl;
            // return;
        }
        else i++;
    }
    // std::cout << "error on remove candidate address" << std::endl;
}
Address_ * isCandidateMem(UINT64 addr){
    list<Address_>::iterator i;
    for (i = candidateAddress.begin(); i != candidateAddress.end();i++){
        Address_ tempaddr = *i;
        if ((tempaddr.addr == addr)){
            // std::cout << &*i << std::endl;
            return &*i;
        }
    }
    return NULL;
}

Address_ * isTaintedMem(UINT64 addr){
    list<Address_>::iterator i;
    for (i = taintedAddress.begin(); i != taintedAddress.end();i++){
        Address_ tempaddr = *i;
        if ((tempaddr.addr == addr)){
            // std::cout << &*i << std::endl;
            return &*i;
        }
    }
    return NULL;
}

Address_ * isMonitoredMem(UINT64 addr, UINT8 flag){
    if (flag == 0){
        Address_ * mem = isCandidateMem(addr);

        return mem;
    }
    else if (flag == 1){
        Address_ * mem = isTaintedMem(addr);

        return mem;
    }
    else{
        // std::cout << hex << flag << std::endl;
        // std::cout << "Wrong Flag in monitoredMem" << std::endl;
        return NULL;
    }
}

VOID addMemCandidate(UINT64 addr, std::vector<UINT64> origlist)
{
    for (UINT64 i = 0; i < origlist.size(); i++){
        // if (!isCandidateMem(addr+i, origlist[i])){
        Address_ * tempaddr;
        tempaddr = isCandidateMem(addr+i);
        if (tempaddr){
            // std::cout << "[CANDI]  0x" << hex << tempaddr->addr << " is already canded with " << origlist[i] << std::endl;
            tempaddr->origin = origlist[i];
        }
        else{
            Address_ saddr = {addr+i, origlist[i]};
            candidateAddress.push_back(saddr);
            // std::cout << "[CANDI]  0x" << hex << addr+i << " is now tainted with " << origlist[i] << std::endl;             
        }
        // if (!isCandidateMem(addr+i)){
        //     // Address_ saddr = {addr+i, origlist[origlist.size()-i-1]};
        // }
        // else{

        //     // std::cout << std::hex << "[CANDI]  0x" << hex(addr) << " is already candidate with " << orig << std::endl;   
        // }
    }

    if(ffff){
    // sleep(1.5);
}
}
VOID pushOrigin(std::vector<UINT64> origlist){
    
    for (UINT32 i=0; i < origlist.size(); i++){
        list<UINT64>::iterator j = find(taintedFile.begin(), taintedFile.end(), origlist[i]);
        if (j == taintedFile.end()){
            taintedFile.push_back(origlist[i]);
        }
        
    }

}
VOID pushOrigin(UINT64 origin){
    
    list<UINT64>::iterator i = find(taintedFile.begin(), taintedFile.end(), origin);
    if (i == taintedFile.end()){
        taintedFile.push_back(origin);
    }
    
}
VOID pushOrigin(string insDis, UINT64 orig){
    std::vector<string> inssplit = split(insDis, ' ');
    string type = inssplit[2];

    pushOrigin(orig);
    if (type == "ptr"){
        return;
    }
    if (type == "byte"){
        return;
    }
    pushOrigin(orig+1);
    if (type == "word"){
        return;
    }
    pushOrigin(orig+2);
    pushOrigin(orig+3);
    if (type == "dword"){
        return;
    }
    pushOrigin(orig+4);
    pushOrigin(orig+5);
    pushOrigin(orig+6);
    pushOrigin(orig+7);
    if (type == "qword"){
        return;
    }
    pushOrigin(orig+8);
    pushOrigin(orig+9);
    pushOrigin(orig+10);
    pushOrigin(orig+11);
    pushOrigin(orig+12);
    pushOrigin(orig+13);
    pushOrigin(orig+14);
    pushOrigin(orig+15);
    if (type == "xmmword"){
        return;
    }

    // else{
    //     std::cout << "[ERROR] compromised push origin - unknown size type " << type << std::endl;
    // }

}

VOID pushOrigin_Mem(string insDis, UINT64 base_addr, UINT8 flag)
{
    std::vector<string> inssplit = split(insDis, ' ');
    string type = inssplit[2];
    Address_ * tempmem;

    
    tempmem = isMonitoredMem(base_addr, flag);
    pushOrigin(tempmem->origin);

    if (type == "ptr"){
        // char chtype[10];
        // strcpy(chtype, inssplit[1].c_str());
        return;

    }
    // byte.push_back(tempmem->origin);
    if (type == "byte"){ return;}

    if ((tempmem = isMonitoredMem(base_addr+1, flag))){ pushOrigin(tempmem->origin); }
    if (type == "word"){ return;}

    if ((tempmem = isMonitoredMem(base_addr+2, flag))){ pushOrigin(tempmem->origin); }
    if ((tempmem = isMonitoredMem(base_addr+3, flag))){ pushOrigin(tempmem->origin); }
    if (type == "dword"){ return;}

    if ((tempmem = isMonitoredMem(base_addr+4, flag))){ pushOrigin(tempmem->origin); }
    if ((tempmem = isMonitoredMem(base_addr+5, flag))){ pushOrigin(tempmem->origin); }
    if ((tempmem = isMonitoredMem(base_addr+6, flag))){ pushOrigin(tempmem->origin); }
    if ((tempmem = isMonitoredMem(base_addr+7, flag))){ pushOrigin(tempmem->origin); }
    if (type == "qword"){ return;}

    if ((tempmem = isMonitoredMem(base_addr+8, flag))){ pushOrigin(tempmem->origin); }
    if ((tempmem = isMonitoredMem(base_addr+9, flag))){ pushOrigin(tempmem->origin); }
    if ((tempmem = isMonitoredMem(base_addr+10, flag))){ pushOrigin(tempmem->origin); }
    if ((tempmem = isMonitoredMem(base_addr+12, flag))){ pushOrigin(tempmem->origin); }
    if ((tempmem = isMonitoredMem(base_addr+13, flag))){ pushOrigin(tempmem->origin); }
    if ((tempmem = isMonitoredMem(base_addr+14, flag))){ pushOrigin(tempmem->origin); }
    if ((tempmem = isMonitoredMem(base_addr+15, flag))){ pushOrigin(tempmem->origin); }
    if (type == "xmmword"){ return;}

    // else{
    //     std::cout << "[ERROR] compromised makeSizeList_Mem - unknown size type : " << type << std::endl;
    
    // }
}

/*VOID pushReg(REG reg, UINT64 orig){
    list<REG_>::iterator i;
    for (i = taintedRegs.begin(); i != taintedRegs.end(); i++){
        REG_ sreg = *i;
        if (sreg.reg == reg){
            (*i).origin = orig;
            // std::cout << REG_StringShort(reg) << " is re-origined" << std::endl;
            return;
        }
    }
    REG_ sreg = {reg, orig};
    taintedRegs.push_front(sreg);
    
}*/

VOID pushReg(REG reg, std::vector<UINT64> xmm, std::vector<UINT64> qword, std::vector<UINT64> dword, std::vector<UINT64> word, UINT64 base_offset){


    xmm.insert(xmm.begin(), qword.begin(), qword.end());
    xmm.insert(xmm.begin(), dword.begin(), dword.end());
    xmm.insert(xmm.begin(), word.begin(), word.end());
    xmm.insert(xmm.begin(), base_offset);
    
    list<REG_>::iterator i;
    for (i = taintedRegs.begin(); i != taintedRegs.end(); i++){
        REG_ sreg = *i;
        if (sreg.reg == reg){
            (*i).originlist = xmm;
            // std::cout << "push re-origin : ";
    //             for (uint i =0; i < xmm.size(); i++){
    //     std::cout << xmm[i] << ", ";
    // }
    // std::cout << "to " << REG_StringShort(reg) << std::endl;

            return;
        }
    }
        // std::cout << "push origin : ";

    // for (uint i =0; i < xmm.size(); i++){
    //     std::cout << xmm[i] << ", " ;
    // }
    // std::cout << "to " << REG_StringShort(reg) << std::endl;
    // std::cout << "[TAINTREG] " << REG_StringShort(reg) << " is now tainted with ";
    // for (UINT64 i =0; i < xmm.size(); i++){
    //     std::cout << xmm[i] << " ";
    // }
    // std::cout << std::endl;

    REG_ sreg = {reg, xmm};
    taintedRegs.push_front(sreg);
}
VOID pushReg(REG reg, std::vector<UINT64> qword, std::vector<UINT64> dword, std::vector<UINT64> word, UINT64 base_offset){

    qword.insert(qword.begin(), dword.begin(), dword.end());
    qword.insert(qword.begin(), word.begin(), word.end());
    qword.insert(qword.begin(), base_offset);
    list<REG_>::iterator i;
    for (i = taintedRegs.begin(); i != taintedRegs.end(); i++){
        REG_ sreg = *i;
        if (sreg.reg == reg){
            (*i).originlist = qword;
            // std::cout << "push re-origin : ";
    //             for (uint i =0; i < qword.size(); i++){
    //     std::cout << qword[i] << ", ";
    // }
    // std::cout << "to " << REG_StringShort(reg) << std::endl;
            return;
        }
    }
        // std::cout << "push origin : ";
    // for (uint i =0; i < qword.size(); i++){
    //     std::cout << qword[i] << ", ";
    // }
    // std::cout << "to " << REG_StringShort(reg) << std::endl;

    // std::cout << "[TAINTREG] " << REG_StringShort(reg) << " is now tainted with ";
    // for (UINT64 i =0; i < qword.size(); i++){
    //     std::cout << qword[i] << " ";
    // }
    // std::cout << std::endl;

    REG_ sreg = {reg, qword};
    taintedRegs.push_front(sreg);
}
VOID pushReg(REG reg, std::vector<UINT64> dword, std::vector<UINT64> word, UINT64 base_offset){

    
    dword.insert(dword.begin(), word.begin(), word.end());
    dword.insert(dword.begin(), base_offset);
    // for (uint i =0; i < dword.size(); i++){
    //     std::cout << i << ", ";
    // }
    // std::cout << base_offset << std::endl;
    list<REG_>::iterator i;
    for (i = taintedRegs.begin(); i != taintedRegs.end(); i++){
        REG_ sreg = *i;
        if (sreg.reg == reg){
            (*i).originlist = dword;
            // std::cout << "push re-origin : ";
    //             for (uint i =0; i < dword.size(); i++){
    //     std::cout << dword[i] << ", ";
    // }
    // std::cout << "to " << REG_StringShort(reg) << std::endl;
            return;
        }
    }
    
    // std::cout << "push origin : ";
    // for (uint i =0; i < dword.size(); i++){
    //     std::cout << dword[i] << ", ";
    // }
    // std::cout << "to " << REG_StringShort(reg) << std::endl;

    // std::cout << "[TAINTREG] " << REG_StringShort(reg) << " is now tainted with ";
    // for (UINT64 i =0; i < dword.size(); i++){
    //     std::cout << dword[i] << " ";
    // }
    // std::cout << std::endl;

    REG_ sreg = {reg, dword};
    taintedRegs.push_front(sreg);
}
VOID pushReg(REG reg, std::vector<UINT64> word, UINT64 base_offset){

    word.insert(word.begin(), base_offset);
    list<REG_>::iterator i;
    for (i = taintedRegs.begin(); i != taintedRegs.end(); i++){
        REG_ sreg = *i;
        if (sreg.reg == reg){
            (*i).originlist = word;
    //         std::cout << "push re-origin : ";
    //             for (uint i =0; i < word.size(); i++){
    //     std::cout <<word[i] << ", ";
    // }
    // std::cout << "to " << REG_StringShort(reg) << std::endl;
            return;
        }
    }
    // std::cout << "push origin : ";
    // for (uint i =0; i < word.size(); i++){
    //     std::cout << word[i] << ", ";
    // }
    // std::cout << "to " << REG_StringShort(reg) << std::endl;

    // std::cout << "[TAINTREG] " << REG_StringShort(reg) << " is now tainted with ";
    // for (UINT64 i =0; i < word.size(); i++){
    //     std::cout << word[i] << " ";
    // }
    // std::cout << std::endl;

    REG_ sreg = {reg, word};
    taintedRegs.push_front(sreg);
}
VOID pushReg(REG reg, std::vector<UINT64> byte){

    list<REG_>::iterator i;
    for (i = taintedRegs.begin(); i != taintedRegs.end(); i++){
        REG_ sreg = *i;
        if (sreg.reg == reg){
            (*i).originlist = byte;
            // std::cout << "push re-origin : "; 
            // for (uint i =0; i < byte.size(); i++){
            //     std::cout << byte[i] << ", ";
            // }
            // std::cout << " to " << REG_StringShort(reg) << std::endl;
            return;
        }
    }
    //     std::cout << "push origin : ";
    // for (uint i =0; i < byte.size(); i++){
    //     std::cout << byte[i] ;
    // }
    // std::cout << " to " << REG_StringShort(reg) << std::endl;

    // std::cout << "[TAINTREG] " << REG_StringShort(reg) << " is now tainted with ";
    // for (UINT64 i =0; i < byte.size(); i++){
    //     std::cout << byte[i] << " ";
    // }
    // std::cout << std::endl;

    REG_ sreg = {reg, byte};
    taintedRegs.push_front(sreg);
}
bool makeSizeList_File(string type, UINT64 base_offset, std::vector<UINT64>& xmm, std::vector<UINT64>& qword, std::vector<UINT64>& dword, std::vector<UINT64>& word, std::vector<UINT64>& byte){
    
    // std::cout << "makesizelist - baseoffset : " << base_offset << std::endl;
    byte.push_back(base_offset);
    if (type == "byte"){ return true; }
    
    word.push_back(base_offset+1);
    if (type == "word"){ return true;}

    dword.push_back(base_offset+2);
    dword.push_back(base_offset+3);
 
    if (type == "dword"){ return true;}
    // std::cout << "after dword return " << std::endl;
    qword.push_back(base_offset+4);
    qword.push_back(base_offset+5);
    qword.push_back(base_offset+6);
    qword.push_back(base_offset+7);
    if (type == "qword"){ return true;}
    
    xmm.push_back(base_offset+8);
    xmm.push_back(base_offset+9);
    xmm.push_back(base_offset+10);
    xmm.push_back(base_offset+11);
    xmm.push_back(base_offset+12);
    xmm.push_back(base_offset+13);
    xmm.push_back(base_offset+14);
    xmm.push_back(base_offset+15);
    if (type == "xmmword"){ return true;}
   
    else{
        // std::cout << "[ERROR] compromised makeSizeList_File - unknown size type" << type << std::endl;
        return false;
    }
}
// bool taintReg(REG reg, UINT64 orig)



bool makeSizeList_Mem(string type, UINT64 base_addr, UINT8 flag, std::vector<UINT64>& xmm, std::vector<UINT64>& qword, std::vector<UINT64>& dword, std::vector<UINT64>& word, std::vector<UINT64>& byte)
{
    Address_ * tempmem;
    
    tempmem = isMonitoredMem(base_addr, flag);
    byte.push_back(tempmem->origin);
    if (type == "ptr"){ return true;}
    if (type == "byte"){ return true;}

    if ((tempmem = isMonitoredMem(base_addr+1, flag))){ word.push_back(tempmem->origin); }
    if (type == "word"){ return true;}

    if ((tempmem = isMonitoredMem(base_addr+2, flag))){ dword.push_back(tempmem->origin); }
    if ((tempmem = isMonitoredMem(base_addr+3, flag))){ dword.push_back(tempmem->origin); }
    if (type == "dword"){ return true;}

    if ((tempmem = isMonitoredMem(base_addr+4, flag))){ qword.push_back(tempmem->origin); }
    if ((tempmem = isMonitoredMem(base_addr+5, flag))){ qword.push_back(tempmem->origin); }
    if ((tempmem = isMonitoredMem(base_addr+6, flag))){ qword.push_back(tempmem->origin); }
    if ((tempmem = isMonitoredMem(base_addr+7, flag))){ qword.push_back(tempmem->origin); }
    if (type == "qword"){ return true;}

    if ((tempmem = isMonitoredMem(base_addr+8, flag))){ xmm.push_back(tempmem->origin); }
    if ((tempmem = isMonitoredMem(base_addr+9, flag))){ xmm.push_back(tempmem->origin); }
    if ((tempmem = isMonitoredMem(base_addr+10, flag))){ xmm.push_back(tempmem->origin); }
    if ((tempmem = isMonitoredMem(base_addr+11, flag))){ xmm.push_back(tempmem->origin); }
    if ((tempmem = isMonitoredMem(base_addr+12, flag))){ xmm.push_back(tempmem->origin); }
    if ((tempmem = isMonitoredMem(base_addr+13, flag))){ xmm.push_back(tempmem->origin); }
    if ((tempmem = isMonitoredMem(base_addr+14, flag))){ xmm.push_back(tempmem->origin); }
    if ((tempmem = isMonitoredMem(base_addr+15, flag))){ xmm.push_back(tempmem->origin); }
    if (type == "xmmword"){ return true;}

    else{
        // std::cout << "[ERROR] compromised makeSizeList_Mem - unknown size type" << type << std::endl;
    return false;
    }

}

bool makeSizeList_File_Lea(string type, UINT64 base_offset, std::vector<UINT64>& xmm, std::vector<UINT64>& qword, std::vector<UINT64>& dword, std::vector<UINT64>& word, std::vector<UINT64>& byte){
    
    // std::cout << "makesizelist - baseoffset : " << base_offset << std::endl;
    if (type == "xmmword"){ xmm.push_back(base_offset); }
    else if(type == "qword"){ qword.push_back(base_offset); }
    else if(type == "dword"){ dword.push_back(base_offset); }
    else if(type == "word"){ word.push_back(base_offset); }
    else if(type == "byte"){ byte.push_back(base_offset); }
    else{ qword.push_back(base_offset); }
    
    return true;
}

bool taintReg(REG reg, string insDis, UINT64 base, UINT8 from_mem_flag)
{
    /*
    list<REG_>::iterator j;
    for (j = taintedRegs.begin(); j != taintedRegs.end(); j++){
        REG_ tempreg = *j;
        if (reg == tempreg.reg){
            // std::cout << "\t\t\t" << REG_StringShort(reg) << " is already tainted" << std::endl;
            return false;
        }
    }
    */

    std::vector<UINT64> xmm;
    std::vector<UINT64> qword;
    std::vector<UINT64> dword;
    std::vector<UINT64> word;
    std::vector<UINT64> byte;
    UINT64 base_offset;
    
    xmm.clear();
    qword.clear();
    dword.clear();
    word.clear();
    byte.clear();
    std::vector<UINT64> final;
    std::vector<string> inssplit = split(insDis, ' ');
    string type = inssplit[2];
    if (type == "ptr"){
        // std::vector<UINT64> tempvector;
        // tempvector.clear();
        // tempvector.push_back(base_offset);
        // taintReg(reg, tempvector);
        // return true;
        // std::cout << "[ERROR in taintReg]there are no size data in " << insDis << std::endl;
        return false;
    }
    //0 or 1 : from mem - taint or candi
    //2 : from file
    //3 : from lea
    if (from_mem_flag < 2){
        makeSizeList_Mem(type, base, from_mem_flag, xmm, qword, dword, word, byte);
        base_offset = isMonitoredMem(base, from_mem_flag)->origin;
    }
    else if (from_mem_flag == 2){
        makeSizeList_File(type, base, xmm, qword, dword, word, byte);
        base_offset = base;
    }
    // else if(from_mem_flag == 3){
    else 
    {
        makeSizeList_File_Lea(type, base, xmm, qword, dword, word, byte);
        base_offset = base;

    }

    // std::cout << "==in taint function==" <<std::endl;
    //     for (uint i =0; i < qword.size(); i++){
    //     std::cout << qword[i] << ", ";
    // }
    // std::cout << std::endl;
    //     for (uint i =0; i < dword.size(); i++){
    //     std::cout << dword[i] << ", ";
    // }
    // std::cout << std::endl;
    //     for (uint i =0; i < word.size(); i++){
    //     std::cout << word[i] << ", ";
    // }
    // std::cout << std::endl;
    //     for (uint i =0; i < byte.size(); i++){
    //     std::cout << byte[i] << ", ";
    // }
    // std::cout << "================" <<std::endl;

    switch(reg){

        case REG_RAX:  pushReg(REG_RAX, qword, dword, word, base_offset);
        case REG_EAX:  pushReg(REG_EAX, dword, word, base_offset);
        case REG_AX:   pushReg(REG_AX, word, base_offset);
        case REG_AH:   pushReg(REG_AH, byte);
        case REG_AL:   pushReg(REG_AH, byte);
             break;

        case REG_RBX:  pushReg(REG_RBX, qword, dword, word, base_offset);
        case REG_EBX:  pushReg(REG_EBX, dword, word, base_offset);
        case REG_BX:   pushReg(REG_BX, word, base_offset);
        case REG_BH:   pushReg(REG_BH, byte);
        case REG_BL:   pushReg(REG_BL, byte);
             break;

        case REG_RCX:  pushReg(REG_RCX, qword, dword, word, base_offset); 
        case REG_ECX:  pushReg(REG_ECX, dword, word, base_offset);
        case REG_CX:   pushReg(REG_CX, word, base_offset);
        case REG_CH:   pushReg(REG_CH, byte);
        case REG_CL:   pushReg(REG_CL, byte);
             break;

        case REG_RDX:  pushReg(REG_RDX, qword, dword, word, base_offset); 
        case REG_EDX:  pushReg(REG_EDX, dword, word, base_offset); 
        case REG_DX:   pushReg(REG_DX, word, base_offset); 
        case REG_DH:   pushReg(REG_DH, byte); 
        case REG_DL:   pushReg(REG_DL, byte); 
             break;

        case REG_RDI:  pushReg(REG_RDI, qword, dword, word, base_offset); 
        case REG_EDI:  pushReg(REG_EDI, dword, word, base_offset); 
        case REG_DI:   pushReg(REG_DI, word, base_offset); 
        case REG_DIL:  pushReg(REG_DIL, byte); 
             break;

        case REG_RSI:  pushReg(REG_RSI, qword, dword, word, base_offset); 
        case REG_ESI:  pushReg(REG_ESI, dword, word, base_offset); 
        case REG_SI:   pushReg(REG_SI, word, base_offset); 
        case REG_SIL:  pushReg(REG_SIL, byte); 
             break;
    /*
        case REG_RBP:  pushReg(REG_RBP, orig);
        case REG_EBP:  pushReg(REG_EBP, orig);
        case REG_BP:   pushReg(REG_BP, orig);
        case REG_BPL:   pushReg(REG_BPL, orig);
             break;

        case REG_RSP:  pushReg(REG_RSP, orig);
        case REG_ESP:  pushReg(REG_ESP, orig);
        case REG_SP:   pushReg(REG_SP, orig);
        case REG_SPL:   pushReg(REG_SPL, orig);
             break;
    //*/
        case REG_R8: pushReg(REG_R14, qword, dword, word, base_offset);
        case REG_R8D: pushReg(REG_R8D, dword, word, base_offset);
        case REG_R8W: pushReg(REG_R8W, word, base_offset);
        case REG_R8B: pushReg(REG_R8B, byte);
            break;
        
        case REG_R9: pushReg(REG_R9, qword, dword, word, base_offset);
        case REG_R9D: pushReg(REG_R9D, dword, word, base_offset);
        case REG_R9W: pushReg(REG_R9W, word, base_offset);
        case REG_R9B: pushReg(REG_R9B, byte);
            break;
        
        case REG_R10: pushReg(REG_R10, qword, dword, word, base_offset);
        case REG_R10D: pushReg(REG_R10D, dword, word, base_offset);
        case REG_R10W: pushReg(REG_R10W, word, base_offset);
        case REG_R10B: pushReg(REG_R10B, byte);
            break;
        
        case REG_R11: pushReg(REG_R11, qword, dword, word, base_offset);
        case REG_R11D: pushReg(REG_R11D, dword, word, base_offset);
        case REG_R11W: pushReg(REG_R11W, word, base_offset);
        case REG_R11B: pushReg(REG_R11B, byte);
            break;
        
        case REG_R12: pushReg(REG_R12, qword, dword, word, base_offset);
        case REG_R12D: pushReg(REG_R12D, dword, word, base_offset);
        case REG_R12W: pushReg(REG_R12W, word, base_offset);
        case REG_R12B: pushReg(REG_R12B, byte);
            break;
        
        case REG_R13: pushReg(REG_R13, qword, dword, word, base_offset);
        case REG_R13D: pushReg(REG_R13D, dword, word, base_offset);
        case REG_R13W: pushReg(REG_R13W, word, base_offset);
        case REG_R13B: pushReg(REG_R13B, byte);
            break;
        
        case REG_R14: pushReg(REG_R14, qword, dword, word, base_offset);
        case REG_R14D: pushReg(REG_R14D, dword, word, base_offset);
        case REG_R14W: pushReg(REG_R14W, word, base_offset);
        case REG_R14B: pushReg(REG_R14B, byte);
            break;

        case REG_R15: pushReg(REG_R15, qword, dword, word, base_offset);
        case REG_R15D: pushReg(REG_R15D, dword, word, base_offset);
        case REG_R15W: pushReg(REG_R15W, word, base_offset);
        case REG_R15B: pushReg(REG_R15B, byte);
            break;

        case REG_XMM0: pushReg(REG_XMM0, xmm, qword, dword, word, base_offset);
            break;

        case REG_XMM1: pushReg(REG_XMM1, xmm, qword, dword, word, base_offset);
            break;

        case REG_XMM2: pushReg(REG_XMM2, xmm, qword, dword, word, base_offset);
            break;

        case REG_XMM3: pushReg(REG_XMM3, xmm, qword, dword, word, base_offset);
            break;

        case REG_XMM4: pushReg(REG_XMM4, xmm, qword, dword, word, base_offset);
            break;

        case REG_XMM5: pushReg(REG_XMM5, xmm, qword, dword, word, base_offset);
            break;

        case REG_XMM6: pushReg(REG_XMM6, xmm, qword, dword, word, base_offset);
            break;

        case REG_XMM7: pushReg(REG_XMM7, xmm, qword, dword, word, base_offset);
            break;

        case REG_XMM8: pushReg(REG_XMM8, xmm, qword, dword, word, base_offset);
            break;

        case REG_XMM9: pushReg(REG_XMM9, xmm, qword, dword, word, base_offset);
            break;

        case REG_XMM10: pushReg(REG_XMM10, xmm, qword, dword, word, base_offset);
            break;

        case REG_XMM11: pushReg(REG_XMM11, xmm, qword, dword, word, base_offset);
            break;

        case REG_XMM12: pushReg(REG_XMM12, xmm, qword, dword, word, base_offset);
            break;

        case REG_XMM13: pushReg(REG_XMM13, xmm, qword, dword, word, base_offset);
            break;

        case REG_XMM14: pushReg(REG_XMM14, xmm, qword, dword, word, base_offset);
            break;

        case REG_XMM15: pushReg(REG_XMM15, xmm, qword, dword, word, base_offset);
            break;

        default:
            // std::cout << "[TAINT]  " << REG_StringShort(reg) << " can't be tainted" << std::endl;
          return false;
    }

  // std::cout << "[TAINT]" << REG_StringShort(reg) << " is now tainted - has size type" << std::endl;
  // sleep(3);
  return true;
}
bool taintReg(REG reg, std::vector<UINT64> orig){

    switch(reg){
        case REG_RAX:  pushReg(REG_RAX, orig);
        case REG_EAX:  pushReg(REG_EAX, orig);
        case REG_AX:   pushReg(REG_AX, orig);
        case REG_AH:   pushReg(REG_AH, orig);
        case REG_AL:   pushReg(REG_AL, orig);
             break;

        case REG_RBX:  pushReg(REG_RBX, orig);
        case REG_EBX:  pushReg(REG_EBX, orig);
        case REG_BX:   pushReg(REG_BX, orig);
        case REG_BH:   pushReg(REG_BH, orig);
        case REG_BL:   pushReg(REG_BL, orig);
             break;

        case REG_RCX:  pushReg(REG_RCX, orig); 
        case REG_ECX:  pushReg(REG_ECX, orig);
        case REG_CX:   pushReg(REG_CX, orig);
        case REG_CH:   pushReg(REG_CH, orig);
        case REG_CL:   pushReg(REG_CL, orig);
             break;

        case REG_RDX:  pushReg(REG_RDX, orig); 
        case REG_EDX:  pushReg(REG_EDX, orig); 
        case REG_DX:   pushReg(REG_DX, orig); 
        case REG_DH:   pushReg(REG_DH, orig); 
        case REG_DL:   pushReg(REG_DL, orig); 
             break;

        case REG_RDI:  pushReg(REG_RDI, orig); 
        case REG_EDI:  pushReg(REG_EDI, orig); 
        case REG_DI:   pushReg(REG_DI, orig); 
        case REG_DIL:  pushReg(REG_DIL, orig); 
             break;

        case REG_RSI:  pushReg(REG_RSI, orig); 
        case REG_ESI:  pushReg(REG_ESI, orig); 
        case REG_SI:   pushReg(REG_SI, orig); 
        case REG_SIL:  pushReg(REG_SIL, orig); 
             break;
    ///*
        case REG_RBP:  pushReg(REG_RBP, orig);
        case REG_EBP:  pushReg(REG_EBP, orig);
        case REG_BP:   pushReg(REG_BP, orig);
        case REG_BPL:   pushReg(REG_BPL, orig);
             break;
    
        case REG_RSP:  pushReg(REG_RSP, orig);
        case REG_ESP:  pushReg(REG_ESP, orig);
        case REG_SP:   pushReg(REG_SP, orig);
        case REG_SPL:   pushReg(REG_SPL, orig);
             break;
    //*/
        case REG_R8: pushReg(REG_R14, orig);
        case REG_R8D: pushReg(REG_R8D, orig);
        case REG_R8W: pushReg(REG_R8W, orig);
        case REG_R8B: pushReg(REG_R8B, orig);
            break;
        
        case REG_R9: pushReg(REG_R9, orig);
        case REG_R9D: pushReg(REG_R9D, orig);
        case REG_R9W: pushReg(REG_R9W, orig);
        case REG_R9B: pushReg(REG_R9B, orig);
            break;
        
        case REG_R10: pushReg(REG_R10, orig);
        case REG_R10D: pushReg(REG_R10D, orig);
        case REG_R10W: pushReg(REG_R10W, orig);
        case REG_R10B: pushReg(REG_R10B, orig);
            break;
        
        case REG_R11: pushReg(REG_R11, orig);
        case REG_R11D: pushReg(REG_R11D, orig);
        case REG_R11W: pushReg(REG_R11W, orig);
        case REG_R11B: pushReg(REG_R11B, orig);
            break;
        
        case REG_R12: pushReg(REG_R12, orig);
        case REG_R12D: pushReg(REG_R12D, orig);
        case REG_R12W: pushReg(REG_R12W, orig);
        case REG_R12B: pushReg(REG_R12B, orig);
            break;
        
        case REG_R13: pushReg(REG_R13, orig);
        case REG_R13D: pushReg(REG_R13D, orig);
        case REG_R13W: pushReg(REG_R13W, orig);
        case REG_R13B: pushReg(REG_R13B, orig);
            break;
        
        case REG_R14: pushReg(REG_R14, orig);
        case REG_R14D: pushReg(REG_R14D, orig);
        case REG_R14W: pushReg(REG_R14W, orig);
        case REG_R14B: pushReg(REG_R14B, orig);
            break;

        case REG_R15: pushReg(REG_R15, orig);
        case REG_R15D: pushReg(REG_R15D, orig);
        case REG_R15W: pushReg(REG_R15W, orig);
        case REG_R15B: pushReg(REG_R15B, orig);
            break;

        case REG_XMM0: pushReg(REG_XMM0, orig);
            break;

        case REG_XMM1: pushReg(REG_XMM1, orig);
            break;

        case REG_XMM2: pushReg(REG_XMM2, orig);
            break;

        case REG_XMM3: pushReg(REG_XMM3, orig);
            break;

        case REG_XMM4: pushReg(REG_XMM4, orig);
            break;

        case REG_XMM5: pushReg(REG_XMM5, orig);
            break;

        case REG_XMM6: pushReg(REG_XMM6, orig);
            break;

        case REG_XMM7: pushReg(REG_XMM7, orig);
            break;

        case REG_XMM8: pushReg(REG_XMM8, orig);
            break;

        case REG_XMM9: pushReg(REG_XMM9, orig);
            break;

        case REG_XMM10: pushReg(REG_XMM10, orig);
            break;

        case REG_XMM11: pushReg(REG_XMM11, orig);
            break;

        case REG_XMM12: pushReg(REG_XMM12, orig);
            break;

        case REG_XMM13: pushReg(REG_XMM13, orig);
            break;

        case REG_XMM14: pushReg(REG_XMM14, orig);
            break;

        case REG_XMM15: pushReg(REG_XMM15, orig);
            break;

        default:
            // std::cout << "\t\t\t" << REG_StringShort(reg) << " can't be tainted" << std::endl;
            return false;
    }
    // std::cout << "[TAINT]" << REG_StringShort(reg) << " is now tainted - has no size type" << std::endl;
    // sleep(3);
    return true;
}
VOID eraseReg(REG reg)
{
    list<REG_>::iterator j;
    for (j = taintedRegs.begin(); j != taintedRegs.end();){
        REG_ sreg = *j;

        if (reg == sreg.reg){
            taintedRegs.erase(j++);
            return;
        }
        else j++;
    }

    // std::cout << "already removed reg " << REG_StringShort(reg) << std::endl;
}
bool removeRegTainted(REG reg)
{
    switch(reg){

    case REG_RAX:  eraseReg(REG_RAX);
    case REG_EAX:  eraseReg(REG_EAX);
    case REG_AX:   eraseReg(REG_AX);
    case REG_AH:   eraseReg(REG_AH);
    case REG_AL:   eraseReg(REG_AL);
         break;

    case REG_RBX:  eraseReg(REG_RBX);
    case REG_EBX:  eraseReg(REG_EBX);
    case REG_BX:   eraseReg(REG_BX);
    case REG_BH:   eraseReg(REG_BH);
    case REG_BL:   eraseReg(REG_BL);
         break;

    case REG_RCX:  eraseReg(REG_RCX); 
    case REG_ECX:  eraseReg(REG_ECX);
    case REG_CX:   eraseReg(REG_CX);
    case REG_CH:   eraseReg(REG_CH);
    case REG_CL:   eraseReg(REG_CL);
         break;

    case REG_RDX:  eraseReg(REG_RDX); 
    case REG_EDX:  eraseReg(REG_EDX); 
    case REG_DX:   eraseReg(REG_DX); 
    case REG_DH:   eraseReg(REG_DH); 
    case REG_DL:   eraseReg(REG_DL); 
         break;

    case REG_RDI:  eraseReg(REG_RDI); 
    case REG_EDI:  eraseReg(REG_EDI); 
    case REG_DI:   eraseReg(REG_DI); 
    case REG_DIL:  eraseReg(REG_DIL); 
         break;

    case REG_RSI:  eraseReg(REG_RSI); 
    case REG_ESI:  eraseReg(REG_ESI); 
    case REG_SI:   eraseReg(REG_SI); 
    case REG_SIL:  eraseReg(REG_SIL); 
         break;

    ///*
    case REG_RBP:  eraseReg(REG_RBP);
    case REG_EBP:  eraseReg(REG_EBP);
    case REG_BP:   eraseReg(REG_BP);
    case REG_BPL:   eraseReg(REG_BPL);
         break;
    
    case REG_RSP:  eraseReg(REG_RSP);
    case REG_ESP:  eraseReg(REG_ESP);
    case REG_SP:   eraseReg(REG_SP);
    case REG_SPL:   eraseReg(REG_SPL);
         break;
    //*/
    case REG_R8: eraseReg(REG_R14);
    case REG_R8D: eraseReg(REG_R8D);
    case REG_R8W: eraseReg(REG_R8W);
    case REG_R8B: eraseReg(REG_R8B);
        break;
    
    case REG_R9: eraseReg(REG_R9);
    case REG_R9D: eraseReg(REG_R9D);
    case REG_R9W: eraseReg(REG_R9W);
    case REG_R9B: eraseReg(REG_R9B);
        break;
    
    case REG_R10: eraseReg(REG_R10);
    case REG_R10D: eraseReg(REG_R10D);
    case REG_R10W: eraseReg(REG_R10W);
    case REG_R10B: eraseReg(REG_R10B);
        break;
    
    case REG_R11: eraseReg(REG_R11);
    case REG_R11D: eraseReg(REG_R11D);
    case REG_R11W: eraseReg(REG_R11W);
    case REG_R11B: eraseReg(REG_R11B);
        break;
    
    case REG_R12: eraseReg(REG_R12);
    case REG_R12D: eraseReg(REG_R12D);
    case REG_R12W: eraseReg(REG_R12W);
    case REG_R12B: eraseReg(REG_R12B);
        break;
    
    case REG_R13: eraseReg(REG_R13);
    case REG_R13D: eraseReg(REG_R13D);
    case REG_R13W: eraseReg(REG_R13W);
    case REG_R13B: eraseReg(REG_R13B);
        break;
    
    case REG_R14: eraseReg(REG_R14);
    case REG_R14D: eraseReg(REG_R14D);
    case REG_R14W: eraseReg(REG_R14W);
    case REG_R14B: eraseReg(REG_R14B);
        break;

    case REG_R15: eraseReg(REG_R15);
    case REG_R15D: eraseReg(REG_R15D);
    case REG_R15W: eraseReg(REG_R15W);
    case REG_R15B: eraseReg(REG_R15B);
        break;

    case REG_XMM0: eraseReg(REG_XMM0);
        break;

    case REG_XMM1: eraseReg(REG_XMM1);
        break;

    case REG_XMM2: eraseReg(REG_XMM2);
        break;

    case REG_XMM3: eraseReg(REG_XMM3);
        break;

    case REG_XMM4: eraseReg(REG_XMM4);
        break;

    case REG_XMM5: eraseReg(REG_XMM5);
        break;

    case REG_XMM6: eraseReg(REG_XMM6);
        break;

    case REG_XMM7: eraseReg(REG_XMM7);
        break;

    case REG_XMM8: eraseReg(REG_XMM8);
        break;

    case REG_XMM9: eraseReg(REG_XMM9);
        break;

    case REG_XMM10: eraseReg(REG_XMM10);
        break;

    case REG_XMM11: eraseReg(REG_XMM11);
        break;

    case REG_XMM12: eraseReg(REG_XMM12);
        break;

    case REG_XMM13: eraseReg(REG_XMM13);
        break;

    case REG_XMM14: eraseReg(REG_XMM14);
        break;

    case REG_XMM15: eraseReg(REG_XMM15);
        break;


    default:
        // std::cout << "[TAINT]  " << REG_StringShort(reg) << " can't be freed" << std::endl;
        return false;
  }

  // std::cout << "[TAINT]  " << REG_StringShort(reg) << " is now freed" << std::endl;
  return true;
}



VOID ReadMem(UINT64 insAddr, std::string insDis, UINT32 opCount, REG reg_r, UINT64 memOp)
{

  // list<UINT64>::iterator i;
    list<Mappedfile>::iterator i;
    list<Address_>::iterator ii;
    list<REG_>::iterator j;
    UINT64 addr = memOp;
    UINT64 base_offset;
    std::vector<UINT64> tempvector;
    // Address_ * tempmem;
    if (opCount != 2)
        return;
    if (vulnflag){
        //1. 파일 매핑 메모리에서 read하거나
        //2. read하는 address가 taintedAddress 또는 candidateAddress이면
        //reg를 tainted에 넣고
        //해당하는 파일 offset을 taintedfile에 넣음
        for (i = Mappinglist.begin(); i != Mappinglist.end(); i++){
            Mappedfile tempfile = *i;
            for (UINT64 j = tempfile.memory_addr; j < (tempfile.memory_addr+tempfile.size); j++){
                if (addr == j){
                    
                    // real file value check
                    ADDRINT * fvalue = reinterpret_cast<ADDRINT *>(addr);
                    std::cout << std::hex << *fvalue << std::endl;
                    if ((tempfile.file_offset + j - tempfile.memory_addr) < filesize){
                        std::cout << std::hex << " file offset : " << tempfile.file_offset + j - tempfile.memory_addr;

                        base_offset = tempfile.file_offset + j - tempfile.memory_addr;
                        pushOrigin(insDis, base_offset);
                        taintReg(reg_r, insDis, base_offset, 2);
                        if (first_flag == 1){

                            context_list.push_back(base_offset);
                            // first_flag = 0;
                        }
                        return;
                    }
                }
            }   
        }
        for (ii = taintedAddress.begin(); ii != taintedAddress.end(); ii++){
            Address_ tempaddr = *ii;

            if (addr == tempaddr.addr){
                pushOrigin_Mem(insDis, tempaddr.addr, 1);
                // tempvector.clear();
                // tempvector.push_back(tempaddr.origin);
                taintReg(reg_r, insDis, tempaddr.addr, 1);
                if (first_flag == 1){
                    
                    context_list.push_back(tempaddr.origin);
                    // first_flag = 0;
                }
                return;
            }
        }
        for (ii = candidateAddress.begin(); ii != candidateAddress.end(); ii++){
            Address_ tempaddr = *ii;
            if (addr == tempaddr.addr){
                pushOrigin_Mem(insDis, tempaddr.addr, 0);
                // tempvector.clear();
                // tempvector.push_back(tempaddr.origin);
                taintReg(reg_r, insDis, tempaddr.addr, 0);
                if (first_flag == 1){
                    
                    context_list.push_back(tempaddr.origin);
                    // first_flag = 0;
                }
                return;
            }
        }

    }
    else{
        //1. 파일 매핑 메모리에서 read하거나
        //2. read하는 address가 candidateaddress이면 
        //reg를 tainted에 넣음
        for (i = Mappinglist.begin(); i != Mappinglist.end(); i++){
            Mappedfile tempfile = *i;
            for (UINT64 j = tempfile.memory_addr; j < (tempfile.memory_addr+tempfile.size); j++){
                if (addr == j){
                    if(ffff){
                    // sleep(0.3);
                    // std::cout << "[READ]" << hex << insAddr << ":" << insDis << std::endl;
                    // std::cout << "READ from " << hex << memOp << " to " << REG_StringShort(reg_r) << std::endl;
                        }
                    // std::cout << insDis << std::endl;
                    std::cout << "[FILE READ] READ from " << hex << memOp << " to " << REG_StringShort(reg_r) << std::endl;
                    base_offset = j - tempfile.memory_addr + tempfile.file_offset;
                    // std::cout << "base : " << base_offset << std::endl;
                    
                        ADDRINT * fvalue = reinterpret_cast<ADDRINT *>(addr);
                        std::cout << "[from file]ins : " << insDis << " : " << hex << addr << std::endl;
                        std::cout << "value : " << *fvalue << std::endl;
                        // ffff=1;
                        // sleep(1);
                    
                    taintReg(reg_r, insDis, base_offset, 2);

                    // taintReg(reg_r, (j - tempfile.memory_addr + tempfile.file_offset));
                    return;
                }
            }
        }
        for (ii = candidateAddress.begin(); ii != candidateAddress.end(); ii++){
            Address_ tempaddr = *ii;
            if (addr == tempaddr.addr){
                //if(ffff){
                // sleep(0.3);
                // std::cout << "[READ]" << hex << insAddr << ":" << insDis << std::endl;
                // std::cout << insDis << std::endl;
                // std::cout << "[CANDI READ]from " << hex << memOp << " to " << REG_StringShort(reg_r) << std::endl;
                //}
                // std::cout << "[from candi]ins : " << insDis << std::endl;
                tempvector.clear();
                tempvector.push_back(tempaddr.origin);
                // std::cout << "[from candi]ins : " << insDis << " : " << hex << addr << std::endl;
                taintReg(reg_r, insDis, tempaddr.addr, 0);
                return;
            }
        }

    }
    int regtflag = 0;
    for (j = taintedRegs.begin(); j != taintedRegs.end(); j++){
        REG_ tempreg = *j;
        if (reg_r == tempreg.reg){
            regtflag = 1;
            break;
        }
    }
    //메모리는 taint또는 candi가 아니지만 reg는 이미 taint된 상태일 때 taint 풀어줌
    if (regtflag){
        removeRegTainted(reg_r);
    }
        
/*
  for(i = taintedAddress.begin(); i != taintedAddress.end(); i++){
      if (addr == *i){
        std::cout << std::hex << "[READ in " << addr << "]\t" << insAddr << ": " << insDis << std::endl;
        taintReg(reg_r);
        return;
      }
  }
*/
//read가 일어났을 때 주소가 file이 올라가있는 주소인지 확인 
  /* if mem != tained and reg == taint => free the reg */
  // if (checkAlreadyRegTainted(reg_r)){
  //   std::cout << std::hex << "[READ in " << addr << "]\t" << insAddr << ": " << insDis << std::endl;
  //   removeRegTainted(reg_r);
  // }
}

VOID WriteMem(UINT64 insAddr, std::string insDis, UINT32 opCount, REG reg_r, UINT64 memOp)
{
    
    list<Address_>::iterator i;
    list<REG_>::iterator j;
    UINT64 addr = memOp;
    REG_ sreg;
    int regtflag = 0;
    if (opCount != 2)
        return;
    for (j = taintedRegs.begin(); j != taintedRegs.end(); j++){
        REG_ tempreg = *j;
        if (reg_r == tempreg.reg){
            sreg.reg = tempreg.reg;
            sreg.originlist = tempreg.originlist;
            regtflag = 1;
            break;
        }
    }
    //pushorigin 부분만 if로 빼고 나머지 if밖으로 보내기
    if (vulnflag){
        //1. taint된 reg에서 taint되지 않은 address로 읽을 때 taintedaddress에 추가 
        //2. taint되지 않은 reg에서 taint된 address로 읽을 때 taintedAddress에서 제거
        for (i = taintedAddress.begin(); i != taintedAddress.end(); i++){
            Address_ tempaddr = *i;
            if (addr == tempaddr.addr){
                if (!REG_valid(reg_r) || !regtflag){
                    removeMemTainted(addr);
                    return;
                }
            }
        }
        if (regtflag){
            addMemTainted(addr, sreg.originlist);
            pushOrigin(sreg.originlist);
            if (first_flag == 1){
                // context_list.push_back(sreg.originlist[0]);
                // first_flag = 0;
            }
        }
    }
    else{
        //1. taint된 reg에서 candi되지 않은 address로 읽을 때 candiaddress에 추가 
        //2. taint되지 않은 reg에서 candi된 address로 읽을 때 candiAddress에서 제거
        for (i = candidateAddress.begin(); i != candidateAddress.end(); i++){
            Address_ tempaddr = *i;
            if (addr == tempaddr.addr){
                if (!REG_valid(reg_r) || !regtflag){
                    removeMemCandidate(addr);
                    // std::cout << "[WRITE]  " << insDis << std::endl;
                    return;
                }
            }
        }
        if (regtflag){
            if(ffff){
            string name = RTN_FindNameByAddress(insAddr);
            // std::cout << name << std::endl;
            }
            // std::cout << insDis << std::endl;
            addMemCandidate(addr, sreg.originlist);
            
            /*
            if ((sreg.origin == prev) && (prev == p) && (p == pp) && (pp == ppp) && (ppp == pppp)){
                ffff=1;
                std::cout << prev << std::endl;
                // sleep(10);
            }
            pppp = ppp;
            ppp = pp;
            pp = p;
            p = prev;
            prev = sreg.origin;
            //*/
        }

    }
  // for(i = taintedAddress.begin(); i != taintedAddress.end(); i++){
  //     if (addr == *i){
  //       std::cout << std::hex << "[WRITE in " << addr << "]\t" << insAddr << ": " << insDis << std::endl;
  //       if (!REG_valid(reg_r) || !checkAlreadyRegTainted(reg_r))
  //         removeMemTainted(addr);
  //       return ;
  //     }
  // }
  // if (checkAlreadyRegTainted(reg_r)){
  //   std::cout << std::hex << "[WRITE in " << addr << "]\t" << insAddr << ": " << insDis << std::endl;
  //   addMemTainted(addr);
  // }
}

VOID spreadReg(UINT64 insAddr, std::string insDis, UINT32 opCount, REG reg_w, REG reg_r)
{

    
    list<REG_>::iterator j;
    REG_ sregr = {};
    REG_ sregw = {};
    int regrflag = 0;
    int regwflag = 0;
    std::vector<UINT64> tempvector;
    
    if (opCount != 2)
        return;

    for (j = taintedRegs.begin(); j != taintedRegs.end(); j++){
        REG_ tempreg = *j;
        if (reg_r == tempreg.reg){
            sregr.reg = tempreg.reg;
            sregr.originlist = tempreg.originlist;
            regrflag = 1;
            break;
        }
    }
    for (j = taintedRegs.begin(); j != taintedRegs.end(); j++){
        REG_ tempreg = *j;
        if (reg_w == tempreg.reg){
            sregw.reg = tempreg.reg;
            sregw.originlist = tempreg.originlist;
            regwflag = 1;
            break;
        }
    }

    if (insDis.find("mov") != std::string::npos){
        if (REG_valid(reg_w)){
        //taint가 아니거나 유효하지 않은 reg에서 taint인 reg에 쓸 때 regw 테인트에서 remove시킴
            if (regwflag && (!REG_valid(reg_r) || !regrflag)){

              removeRegTainted(reg_w);
            }
            //taint가 아닌 reg에 taint인 reg를 쓸 때 테인트에 reg 추가
            else if (regrflag){

                // std::cout << "[SPREAD] from " << REG_StringShort(reg_r) << " to " << REG_StringShort(reg_w) << " with " << sregr.origin << std::endl;
                // std::cout << "[from reg]ins : " << insDis << std::endl;
                
                taintReg(reg_w, sregr.originlist);
                if (vulnflag){
                    pushOrigin(sregr.originlist);
                    if (first_flag == 1){
                        // context_list.push_back(sregr.originlist[0]);
                        // first_flag = 0;
                    }
                }
            }
        }
        else{
            // std::cout << "REG not valid!" << std::endl;
        }
        
    }
    else{
        if (vulnflag){
            if (regwflag) pushOrigin(sregw.originlist);
            if (regrflag) pushOrigin(sregr.originlist);
            if (first_flag == 1){
                // context_list.push_back(sregr.originlist[0]);
                // first_flag = 0;
            }
        }
    }
}
///*
//ex. cmp, test 
//vulnflag일 때만 사용된 레지스터 또는 어드레스 무조건 taint
VOID spreadMem(UINT64 insAddr, std::string insDis, UINT32 opCount, ADDRINT addr, REG reg){
  list<Mappedfile>::iterator i;
  list<Address_>::iterator ii;
  list<REG_>::iterator j;

    
    if (opCount != 2)
        return;
    if (vulnflag){
        for (j = taintedRegs.begin(); j != taintedRegs.end(); j++){
            REG_ tempreg = *j;
            if (reg == tempreg.reg){

                pushOrigin(tempreg.originlist);
                if (first_flag == 1){

                    // context_list.push_back(tempreg.originlist[0]);
                    // first_flag = 0;
                }
                break;
            }
        }
        for (i = Mappinglist.begin(); i != Mappinglist.end(); i++){
            Mappedfile tempfile = *i;
            for (UINT64 j = tempfile.memory_addr; j < (tempfile.memory_addr+tempfile.size); j++){
                if (addr == j){
                    
                    // real file value check
                    // ADDRINT * fvalue = reinterpret_cast<ADDRINT *>(addr);
                    // std::cout << std::hex << *fvalue << std::endl;
                    if ((tempfile.file_offset + j - tempfile.memory_addr) < filesize){
                        // std::cout << std::hex << " file offset : " << tempfile.file_offset + j - tempfile.memory_addr;

                        pushOrigin(insDis, tempfile.file_offset + j - tempfile.memory_addr);
                        if (first_flag == 1){

                            context_list.push_back(tempfile.file_offset + j - tempfile.memory_addr);
                            // first_flag = 0;
                        }
                        return;
                    }
                }
            }   
        }
        for (ii = taintedAddress.begin(); ii != taintedAddress.end(); ii++){
            Address_ tempaddr = *ii;
            if (addr == tempaddr.addr){
                pushOrigin_Mem(insDis, tempaddr.addr, 1);
                if (first_flag == 1){

                            context_list.push_back(tempaddr.addr);
                            // first_flag = 0;
                        }
                return;
            }
        }
        for (ii = candidateAddress.begin(); ii != candidateAddress.end(); ii++){
            Address_ tempaddr = *ii;
            if (addr == tempaddr.addr){
                pushOrigin_Mem(insDis, tempaddr.addr, 0);
                if (first_flag == 1){

                            context_list.push_back(tempaddr.addr);
                            // first_flag = 0;
                        }
                return;
            }
        }

    }

}
        

//VOID specialLea(std::string insDis, UINT32 opCount, ADDRINT addr, REG reg){
// VOID specialLea(std::string insDis, CONTEXT *ctxt, REG reg, ADDRINT baseea, ADDRDELTA disp, REG basereg, REG indexreg, UINT32 scale){
VOID specialLea(std::string insDis, CONTEXT *ctxt, REG reg, ADDRDELTA disp, REG basereg, REG indexreg, UINT32 scale){
    UINT64 reg_val; 
    UINT64 EA = 0;
    list<Mappedfile>::iterator i;
    list<Address_>::iterator ii;
    list<REG_>::iterator j;
    std::vector<UINT64> tempvector;
    UINT64 base_offset;
       
    /*
    std::cout << insDis << std::endl;
    std::cout << hex << "displacement : " << disp << std::endl;
    PIN_GetContextRegval(ctxt, basereg, reinterpret_cast<UINT8 *>(&reg_val));
    std::cout << REG_StringShort(basereg) << ": 0x" << reg_val << std::endl;
    PIN_GetContextRegval(ctxt, indexreg, reinterpret_cast<UINT8 *>(&reg_val));
    std::cout << REG_StringShort(indexreg) << ": 0x" << reg_val << std::endl;
    std::cout << "scale : " << scale << std::endl;
    //*/

    //Effective address = Displacement + BaseReg + IndexReg * Scale
    //calc effective address
    PIN_GetContextRegval(ctxt, basereg, reinterpret_cast<UINT8 *>(&reg_val));
    EA = disp + reg_val;
    if (REG_valid(indexreg)){
        PIN_GetContextRegval(ctxt, indexreg, reinterpret_cast<UINT8 *>(&reg_val));
        EA += reg_val * scale;
    }
    // std::cout << hex << "EA : " << EA << std::endl;



    if (vulnflag){
        //1. 파일 매핑 메모리에서 read하거나
        //2. read하는 address가 taintedAddress 또는 candidateAddress이면
        //reg를 tainted에 넣고
        //해당하는 파일 offset을 taintedfile에 넣음
        for (i = Mappinglist.begin(); i != Mappinglist.end(); i++){
            Mappedfile tempfile = *i;
            for (UINT64 j = tempfile.memory_addr; j < (tempfile.memory_addr+tempfile.size); j++){
                if (EA == j){
                    
                    // real file value check
                    // ADDRINT * fvalue = reinterpret_cast<ADDRINT *>(addr);
                    // std::cout << std::hex << *fvalue << std::endl;
                    if ((tempfile.file_offset + j - tempfile.memory_addr) < filesize){
                        // std::cout << std::hex << " file offset : " << tempfile.file_offset + j - tempfile.memory_addr;
                        base_offset = tempfile.file_offset + j - tempfile.memory_addr;
                        pushOrigin(insDis, tempfile.file_offset + j - tempfile.memory_addr);
                        // std::cout << "[from file]ins : " << insDis << std::endl;
                        tempvector.clear();
                        tempvector.push_back(base_offset);
                        
                        //taintReg(reg, insDis, base_offset, 3);
                        taintReg(reg, tempvector);

                        if (first_flag == 1){
                            context_list.push_back(tempfile.file_offset + j - tempfile.memory_addr);
                            // first_flag = 0;
                        }


                        return;
                    }
                }
            }   
        }
        for (ii = taintedAddress.begin(); ii != taintedAddress.end(); ii++){
            Address_ tempaddr = *ii;
            if (EA == tempaddr.addr){
                pushOrigin_Mem(insDis, tempaddr.addr, 1);
                tempvector.clear();
                tempvector.push_back(tempaddr.origin);
                // std::cout << "[from taint]ins : " << insDis << std::endl;
                // taintReg(reg, insDis, tempaddr.addr, 1);
                taintReg(reg, tempvector);
                if (first_flag == 1){
                    context_list.push_back(tempaddr.origin);
                    // first_flag = 0;
                }

                return;
            }
        }
        for (ii = candidateAddress.begin(); ii != candidateAddress.end(); ii++){
            Address_ tempaddr = *ii;
            if (EA == tempaddr.addr){
                pushOrigin_Mem(insDis, tempaddr.addr, 0);
                tempvector.clear();
                tempvector.push_back(tempaddr.origin);
                // std::cout << "[from candi]ins : " << insDis << std::endl;
                // taintReg(reg, insDis, tempaddr.addr, 0);
                taintReg(reg, tempvector);
                if (first_flag == 1){
                    context_list.push_back(tempaddr.origin);
                    // first_flag = 0;
                }
                return;
            }
        }

    }
    else{
        //1. 파일 매핑 메모리에서 read하거나
        //2. read하는 address가 candidateaddress이면 
        //reg를 tainted에 넣음
        for (i = Mappinglist.begin(); i != Mappinglist.end(); i++){
            Mappedfile tempfile = *i;
            for (UINT64 j = tempfile.memory_addr; j < (tempfile.memory_addr+tempfile.size); j++){
                if (EA == j){
                    
                    // std::cout << "[READ]" << hex << EA << " to " << REG_StringShort(reg) << std::endl;
                    base_offset = j - tempfile.memory_addr + tempfile.file_offset;
                    // std::cout << "[from file]ins : " << insDis << std::endl;
                    tempvector.clear();
                    tempvector.push_back(base_offset);
                    // taintReg(reg, insDis, base_offset, 2);
                    taintReg(reg, tempvector);
                    // taintReg(reg, (j - tempfile.memory_addr + tempfile.file_offset));
                    return;
                }
            }
        }
        for (ii = candidateAddress.begin(); ii != candidateAddress.end(); ii++){
            Address_ tempaddr = *ii;
            if (EA == tempaddr.addr){
                
                // std::cout << "[READ]" << hex << EA << " to " << REG_StringShort(reg) << std::endl;
                tempvector.clear();
                tempvector.push_back(tempaddr.origin);
                // std::cout << "[from candi]ins : " << insDis << std::endl;
                // taintReg(reg, insDis, tempaddr.addr, 0);
                taintReg(reg, tempvector);
                return;
            }
        }

    }
    int regtflag = 0;
    for (j = taintedRegs.begin(); j != taintedRegs.end(); j++){
        REG_ tempreg = *j;
        if (reg == tempreg.reg){
            regtflag = 1;
            break;
        }
    }
    //메모리는 taint또는 candi가 아니지만 reg는 이미 taint된 상태일 때 taint 풀어줌
    if (regtflag){
        removeRegTainted(reg);
    }







    
}
VOID followData(UINT64 insAddr, std::string insDis, REG reg)
{
  if (!REG_valid(reg))
    return;
    int regtflag = 0;
    list<REG_>::iterator j;
    for (j = taintedRegs.begin(); j != taintedRegs.end(); j++){
        REG_ tempreg = *j;
        if (reg == tempreg.reg){
            regtflag = 1;
            break;
        }
    }
  if (regtflag){
      // std::cout << "[FOLLOW]\t\t" << insAddr << ": " << insDis << std::endl;
  }
}
//*/
VOID setvulnflag(ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8){
    vulnflag = 1;
    // first_flag = 1;
    ffff = 1;
    list<Mappedfile>::iterator i;
    list<Address_>::iterator j;
    string filepath = "candi_v3.txt";
    ofstream writeFile(filepath.data());
    if(writeFile.is_open()){
        for (j = candidateAddress.begin(); j != candidateAddress.end(); j++){
            Address_ tempaddr_t = *j;
            writeFile << tempaddr_t.origin << " ";
        }
        writeFile.close();
    }

    //unset this comment
    std::cout << "!!!!!!!!!!!!!!!!!!!!!!!!set vuln flag" << std::endl;
        std::cout << "====================" << std::endl;
    for (j = taintedAddress.begin(); j != taintedAddress.end(); j++){
        Address_ tempaddr = *j;
        std::cout << tempaddr.origin << " ";
    }

    std::cout << "\n====================" << std::endl;


    for (j = candidateAddress.begin(); j != candidateAddress.end(); j++){
        Address_ tempaddr = *j;
        std::cout << tempaddr.origin << " ";
    }

    std::cout << "\n====================" << std::endl;


    //premise : fp == arg1 
    //by using array, deal other cases

    // std::cout << "ARGS : " << hex << "(" << arg1 << ", " << arg2 << ", " << arg3 << ", " << arg4 << ", " << arg5 << ", " << arg6 << ", " << arg7 << ")" << std::endl;
    // ADDRINT * fp = reinterpret_cast<ADDRINT *>(arg1);


    //for file pointer...
    // ADDRINT * pos = reinterpret_cast<ADDRINT *>(arg1+0x8);
    
    // ADDRINT * filepos = reinterpret_cast<ADDRINT *>(arg1+0x10); //error, not use
    // ADDRINT * filevalue = reinterpret_cast<ADDRINT *>(*filepos);
    // ADDRINT * cvalue = reinterpret_cast<ADDRINT *>(*pos);


    // std::cout << "fp : 0x" << hex << arg1 << std::endl;
    // std::cout << "pos : 0x" << hex << *pos << std::endl;

    /* //argument에 file pointer가 있는 경우
    ADDRINT coffset;
    //알맞은 offset 찾기
    if (Mappinglist.size() == 1){
        coffset = *pos - Mappinglist.front().memory_addr + Mappinglist.front().file_offset;
    }
    else{
        for (i = Mappinglist.begin(); i != Mappinglist.end(); i++){
            list<Mappedfile>::iterator i2 = i;
            std::advance(i2,1);
            Mappedfile tempfile = *i;
            if (i2 == Mappinglist.end()){
                coffset = *pos - tempfile.memory_addr + tempfile.file_offset;
                break;
            }
            Mappedfile nextfile = *i2;
            if ((*pos >= tempfile.memory_addr) && (*pos < nextfile.memory_addr)){
                coffset = *pos - tempfile.memory_addr + tempfile.file_offset;
                break;
            }
        }
    }
    arglist.push_back(coffset);
    arglist.push_back(arg2);
    arglist.push_back(arg3);
    arglist.push_back(arg4);
    arglist.push_back(arg5);
    arglist.push_back(arg6);
    arglist.push_back(arg7);
    vuln_arg.push_back(arglist);


    std::cout << "offset : 0x" << hex << coffset << std::endl;

    */
    
    sleep(3);
}
VOID unsetvulnflag(ADDRINT a){
    vulnflag = 0;
    ffff = 0;
    // std::cout << "unset vuln flag" << std::endl;
    // list<UINT64>::iterator j;
    // std::cout << "\n=============================" << std::endl;
    
    // for (j = context_list.begin(); j != context_list.end(); j++){
    //     std::cout << hex << *j << " ";
    // }
    // std::cout << "\n=============================" << std::endl;
    // std::cout << first_flag << std::endl;
    context_list.clear();
    sleep(3);
}
VOID showmain(ADDRINT a){
    std::cout << "[+] Start of Main" << std::endl;   
}

VOID handleFread(ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, FILE* arg3){
    list<Mappedfile>::iterator it;
    std::cout << arg3 << std::endl;
    ADDRINT * testvalue = reinterpret_cast<ADDRINT *>(arg3);
    std::cout << testvalue << std::endl;
    // ADDRINT * testvalue2 = reinterpret_cast<ADDRINT *>(testvalue);
    // std::cout << testvalue2 << std::endl;
    if (arg3 == inputfilestream){
        std::cout << "[+]fread " << arg3 << std::endl;
        buf = arg0;
        size = arg1 * arg2;
        if(size+cur_read_pos > filesize){
            size = filesize - cur_read_pos;
        }
        else if (filesize < size){
            size = filesize;
        }
        // std::cout << "[+]buf : " << buf << std::endl;
        // std::cout << "[+]size " << size << std::endl;
        
        for (it = Mappinglist.begin(); it != Mappinglist.end();){
            Mappedfile tempfile = *it;
            if (tempfile.memory_addr == buf){
                Mappinglist.erase(it++);
                break;
            }
            else it++;
        }
        Mappedfile file = {buf, cur_read_pos, size};
        Mappinglist.push_back(file);
        // std::cout << "[+]read file " << fd << std::hex << " offset : " << cur_read_pos << " size : " << size << " buf : " << buf << std::endl;;
        
        cur_read_pos = cur_read_pos + size;

        
        if (cur_read_pos >= filesize){
            cur_read_pos = 0;
        }

        ///*
        std::cout << "=======map table(fread)=======" << std::endl;
        std::cout << "MEM_ADDR" << "\t|" << "Offset" << "\t|" << "SIZE" << std::endl;
        std::cout << "-----------------------------" << std::endl;
        for (it = Mappinglist.begin(); it != Mappinglist.end(); it++){
            Mappedfile tempfile = *it;
            std::cout << hex << "0x" << tempfile.memory_addr << "\t|" << "0x" << tempfile.file_offset << "\t|" << "0x" <<tempfile.size << std::endl;
        }
        std::cout << "=============================" << std::endl;
        //*/
        
        // sleep(4);
        // sleep(1);
    }
    
    std::cout << "[+] fread!!!!!!!!!!!!!!!!!!!!!!!!!!" << std::endl;
}
VOID hookfopen(char* arg0, char* arg1, FILE* ret){
    // char * mmapArg = reinterpret_cast<char *>(PIN_GetSyscallArgument(ctx, std, 0));
      std::string fname(arg0);
      // std::cout << arg0 << std::endl;

     ADDRINT * testvalue = reinterpret_cast<ADDRINT *>(ret);
    std::cout << "!" << testvalue << std::endl;
    // ADDRINT * testvalue2 = reinterpret_cast<ADDRINT *>(testvalue);
    // std::cout << testvalue2 << std::endl;

      if(!(fname.compare(filename))){
          std::cout << "[+]fopen " << filename << std::endl;
          inputfilestream = ret;
          std::cout << "stream : " << ret << std::endl;
      }

      
}

VOID Image(IMG img, VOID *v){
    /*
    for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym)) { 
        string undFuncName = PIN_UndecorateSymbolName(SYM_Name(sym), UNDECORATION_COMPLETE); 
    // Find the RtlAllocHeap() function. 
        // std::cout << undFuncName << std::endl;
        if (undFuncName.find("displayPage") != std::string::npos){
            std::cout << undFuncName << std::endl;    
        }
        // RTN testrtn = RTN_FindByAddress(0x00007ffff7aa5720);
        ADDRINT add = 0x00007ffff7aa5720;
        string rtnname = RTN_FindNameByAddress(add);
        if (rtnname != ""){
            std::cout << "??????????????????" << rtnname << std::endl;    
        }
        

    }
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)){
    for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)){
        if (RTN_Name(rtn) == "_ZN6PDFDoc11displayPageEP9OutputDeviddibbbPFbPvES2_PFbP5AnnotS2_ES2_b"){
            std::cout << "??????????????????here" << std::endl;
            RTN_Open(rtn);
            RTN_InsertCall(
                rtn, IPOINT_AFTER, (AFUNPTR)setvulnflag,
                IARG_ADDRINT, "test",
                IARG_END);
            RTN_Close(rtn);
        }
        // if (RTN_Name(rtn).find("Preprocessor") != std::string::npos){
        //     std::cout << "??????????????????" << RTN_Name(rtn) << std::endl;
            
        // }
        if (RTN_Name(rtn) == "_ZN10pdf2htmlEX12Preprocessor7processEP6PDFDoc"){
            std::cout << "??????????????????here" << std::endl;
            RTN_Open(rtn);
            RTN_InsertCall(
                rtn, IPOINT_AFTER, (AFUNPTR)setvulnflag,
                IARG_END);
            RTN_Close(rtn);
        }
        

    }
    }
    //*/

    RTN vulnRtn = RTN_FindByName(img, vulnfunc);
    // RTN vulnRtn = RTN_FindByName(img, "malloc");
    if (RTN_Valid(vulnRtn)){
        RTN_Open(vulnRtn);
        RTN_InsertCall(
            vulnRtn, IPOINT_BEFORE, (AFUNPTR)setvulnflag,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
            IARG_END);
        RTN_Close(vulnRtn);
    }
    if (RTN_Valid(vulnRtn)){
        RTN_Open(vulnRtn);
        RTN_InsertCall(
            vulnRtn, IPOINT_AFTER, (AFUNPTR)unsetvulnflag,
            IARG_END);
        RTN_Close(vulnRtn);
    }
    RTN mainRtn = RTN_FindByName(img, "main");
    if (RTN_Valid(mainRtn)){
        RTN_Open(mainRtn);
        RTN_InsertCall(
            mainRtn, IPOINT_BEFORE, (AFUNPTR)showmain,
            IARG_END);
        RTN_Close(mainRtn);
    }
    RTN freadRtn = RTN_FindByName(img, "fread");
    if (RTN_Valid(freadRtn)){
        RTN_Open(freadRtn);
        RTN_InsertCall(
            freadRtn, IPOINT_BEFORE, (AFUNPTR)handleFread,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
            IARG_END);
        RTN_Close(freadRtn);
    }
    RTN fopenRtn = RTN_FindByName(img, "fopen");
    if (RTN_Valid(fopenRtn)){
        RTN_Open(fopenRtn);
        RTN_InsertCall(
            fopenRtn, IPOINT_BEFORE, (AFUNPTR)hookfopen,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
            IARG_FUNCRET_EXITPOINT_VALUE, 
            IARG_END);
        RTN_Close(fopenRtn);
    }
    
    // else{
        // std::cout << "!!!!!!!!!!!!!!!!!!!!!!!can not find" << std::endl;
    // }
}


VOID temp(std::string insDis){
    if (ffff){
    std::cout << insDis << std::endl;
        
    }
}

VOID Instruction(INS ins, VOID *v)
{

    // if(ffff){
    // std::cout << INS_Disassemble(ins) << std::endl;
    // }
// UINT32 memOperands = INS_MemoryOperandCount(ins);
// UINT32 Operands = INS_OperandCount(ins); // Iterate over each memory operand of the instruction. 

//     std::cout << "mem : " << memOperands << std::endl;
//     std::cout << "no : " << Operands << std::endl;
    




    // if (INS_OperandCount(ins) > 1 && INS_OperandIsReg(ins,0) && !INS_OperandIsReg(ins,1) && (INS_MemoryOperandCount(ins) == 0)){
    //     std::cout << INS_Disassemble(ins) << std::endl;
    //     // std::cout << "[Memory op1 read] & register" << std::endl;    
    // }
    
    // if (INS_MemoryOperandIsWritten(ins, 0)){
    //     std::cout << INS_Disassemble(ins) << std::endl;
    //     std::cout << "[Memory op1 written]" << std::endl;    
    // }
    // if (INS_MemoryOperandIsRead(ins, 1)){
    //     std::cout << INS_Disassemble(ins) << std::endl;
    //     std::cout << "[Memory op2 read]" << std::endl;    
    // }
    // if (INS_MemoryOperandIsWritten(ins, 1)){
    //     std::cout << INS_Disassemble(ins) << std::endl;
    //     std::cout << "[Memory op2 written]" << std::endl;    
    // }
    // else{
    //     std::cout << "neither" << std::endl;    
    // }
    

    /*
    if (INS_OperandCount(ins) > 1 && INS_OperandIsMemory(ins, 0) && INS_OperandIsReg(ins, 1) && !INS_MemoryOperandIsWritten(ins, 0)){
        string insDis = INS_Disassemble(ins);
        std::cout << insDis << std::endl;
        
    }
    //*/

    /*
    if (INS_OperandCount(ins) > 1 ){
        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)temp,
            IARG_PTR, new string(INS_Disassemble(ins)),
            IARG_END);
    }
    //*/
    
    // if (INS_Disassemble(ins).find("mov") != std::string::npos){
    //     std::cout << INS_Disassemble(ins) << std::endl;
    // }
  if (INS_OperandCount(ins) > 1 && INS_MemoryOperandIsRead(ins, 0) && INS_OperandIsReg(ins, 0)){
    INS_InsertCall(
        ins, IPOINT_BEFORE, (AFUNPTR)ReadMem,
        IARG_ADDRINT, INS_Address(ins),
        IARG_PTR, new string(INS_Disassemble(ins)),
        IARG_UINT32, INS_OperandCount(ins),
        IARG_UINT32, INS_OperandReg(ins, 0),
        IARG_MEMORYOP_EA, 0,
        IARG_END);
  }
  
  else if (INS_OperandCount(ins) > 1 && INS_MemoryOperandIsWritten(ins, 0)){
    INS_InsertCall(
        ins, IPOINT_BEFORE, (AFUNPTR)WriteMem,
        IARG_ADDRINT, INS_Address(ins),
        IARG_PTR, new string(INS_Disassemble(ins)),
        IARG_UINT32, INS_OperandCount(ins),
        IARG_UINT32, INS_OperandReg(ins, 1),
        IARG_MEMORYOP_EA, 0,
        IARG_END);
  }
  else if (INS_OperandCount(ins) > 1 && INS_OperandIsReg(ins, 0) && INS_OperandIsReg(ins, 1)){
    INS_InsertCall(
        ins, IPOINT_BEFORE, (AFUNPTR)spreadReg,
        IARG_ADDRINT, INS_Address(ins),
        IARG_PTR, new string(INS_Disassemble(ins)),
        IARG_UINT32, INS_OperandCount(ins),
        // IARG_UINT32, INS_RegR(ins, 0),
        // IARG_UINT32, INS_RegW(ins, 0),
        IARG_UINT32, INS_OperandReg(ins, 0),
        IARG_UINT32, INS_OperandReg(ins, 1),
        IARG_END);
  }
  
  ///*
  

  else if (INS_OperandCount(ins) > 1 && INS_OperandIsMemory(ins, 0) && INS_OperandIsReg(ins, 1) 
            && (INS_Disassemble(ins).find("nop") == std::string::npos)
            && (INS_Disassemble(ins).find("jmp") == std::string::npos)){
    INS_InsertCall(
        ins, IPOINT_BEFORE, (AFUNPTR)spreadMem,
        IARG_ADDRINT, INS_Address(ins),
        IARG_PTR, new string(INS_Disassemble(ins)),
        IARG_UINT32, INS_OperandCount(ins),
        IARG_MEMORYOP_EA, 0,
        IARG_UINT32, INS_RegR(ins, 1),
        IARG_END);
  }
  else if (INS_IsLea(ins)){
    INS_InsertCall(
        ins, IPOINT_BEFORE, (AFUNPTR)specialLea,
        IARG_PTR, new string(INS_Disassemble(ins)),
        IARG_CONST_CONTEXT,
        IARG_UINT32, INS_OperandReg(ins, 0),
        // IARG_MEMORYREAD_EA,
        IARG_ADDRINT, INS_MemoryDisplacement(ins),
        IARG_UINT32, INS_MemoryBaseReg(ins),
        // IARG_REG_CONST_REFERENCE, INS_MemoryBaseReg(ins),
        IARG_UINT32, INS_MemoryIndexReg(ins),
        IARG_UINT32, INS_MemoryScale (ins),
        IARG_END);
  }
  //*/
  //Effective address = Displacement + BaseReg + IndexReg * Scale

}




VOID Fini(INT32 code, VOID *v)
{
    //읽히지 않은 파일 바이트 출력
    list<UINT64>::iterator j;
    list<UINT64>::iterator beforeend;
    list<Address_>::iterator jj;
    ofstream fs;
    
    end_time = clock();
    std::cout << "TIME " << (float)(end_time - start_time)/CLOCKS_PER_SEC << std::endl;
    string primpath = "";
    char* exepath_c = static_cast<char*>(v);
    string exepath(exepath_c);
    
    
    
    std::vector<string> exepath_v = split(exepath, '/');
    for (uint i = 0; i < exepath_v.size()-2; i++){
        primpath = primpath + exepath_v[i] + "/";
    }
    std::cout << primpath << std::endl;
    // primpath = primpath + "prim";
    primpath = "prim";
    // std::cout << "=======CRASH PRIMITIVE=======" << std::endl;
    // for (j = taintedFile.begin(); j != taintedFile.end(); j++){
    //     std::cout << hex << *j << " ";
    // }

    // std::cout << "\n=============================" << std::endl;
    
    // for (j = context_list.begin(); j != context_list.end(); j++){
    //     std::cout << hex << *j << " ";
    // }
    // std::cout << "\n=============================" << std::endl;

    fs.open(primpath.data());
    beforeend = taintedFile.end();
    std::advance(beforeend, -1);

    for (j = taintedFile.begin(); j != beforeend; j++){
        fs << hex << *j << ",";
    }
    fs << hex << *j;
    fs.close();

    // for (jj = taintedAddress.begin(); jj != taintedAddress.end(); jj++){
    //     Address_ tempaddr = *jj;
    //     std::cout << tempaddr.origin << " ";
    // }

    // std::cout << "\n====================" << std::endl;
    //     list<REG_>::iterator ii;
    // for (ii = taintedRegs.begin(); ii != taintedRegs.end(); ii++){
    //     REG_ sreg = *ii;
    //     std::cout << sreg.origin << " ";
    // }
    // std::cout << "\n====================" << std::endl;

    // for (i = 0; i <= filesize; i++){
    //     int flag = 0;
    //     for (j = taintedFile.begin(); j != taintedFile.end(); j++){
    //         if (i == *j){
    //             flag = 1;
    //             break;
    //         }
    //     }
    //     if (flag == 0){
    //         std::cout << i << "  ";
    //     }
    // }
}
// static unsigned int tryksOpen;

// #define TRICKS(){if (tryksOpen++ == 0)return;}



string hex2ascii(string hex) 
{ 
    // initialize the ASCII code string as empty. 
    string ascii = ""; 
    for (size_t i = hex.length()-2; i >0; i -= 2) 
    { 
        // extract two characters from hex string 
      string part;
        if(hex.substr(i, 2) != "00"){
          part = hex.substr(i, 2); 
        
        // change it into base 16 and  
        // typecast as the character 
        char ch = std::strtol(part.c_str(), NULL, 16);
        // std::cout << ch << std::endl;
        // add this char to final ASCII string 
        ascii += ch; 
      }
    }

    return ascii;
} 

VOID Syscall_entry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v)
{
    //input파일이 메모리에 올라갈 때 메모리 매핑 정보 저장
  // unsigned int i;
  list<Mappedfile>::iterator it;


  
  syscall_number = PIN_GetSyscallNumber(ctx, std);
  // std::cout << "syscall : " << syscall_number << std::endl;
  
    if(PIN_GetSyscallNumber(ctx, std) == __NR_open){
      // std::cout <<"open call" << std::endl;
      //get open file name
      // ADDRINT * mmapArgs = reinterpret_cast<ADDRINT *>(PIN_GetSyscallArgument(ctx, std, 0));


      // string arg0 = StringFromAddrint(mmapArgs[0]);
      // string arg1 = StringFromAddrint(mmapArgs[1]);
      // arg0 = hex2ascii(arg0);
      // arg1 = hex2ascii(arg1);
      // std::cout << mmapArgs << std::endl;
      // std::cout << arg1 << std::endl;
      
//new
      char * mmapArg = reinterpret_cast<char *>(PIN_GetSyscallArgument(ctx, std, 0));
      std::string arg0(mmapArg);
      // std::cout << arg0 << std::endl;

    

      if(!(arg0.compare(filename))){
          std::cout << "[+]open " << filename << std::endl;
      }
    }
    if(PIN_GetSyscallNumber(ctx, std) == __NR_read){
        UINT64 fd = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 0)));
        // std::cout << "read fd : " << fd << std::endl;
        // std::cout << "input fd : " << input_fd << std::endl;
        if (fd == input_fd){
            // std::cout << "[+]read " << fd << std::endl;
            buf = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 1)));
            size = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 2)));
            if(size+cur_read_pos > filesize){
                size = filesize - cur_read_pos;
            }
            else if (filesize < size){
                size = filesize;
            }
            // std::cout << "[+]buf : " << buf << std::endl;
            // std::cout << "[+]size " << size << std::endl;
            
            for (it = Mappinglist.begin(); it != Mappinglist.end();){
                Mappedfile tempfile = *it;
                if (tempfile.memory_addr == buf){
                    Mappinglist.erase(it++);
                    break;
                }
                else it++;
            }
            Mappedfile file = {buf, cur_read_pos, size};
            Mappinglist.push_back(file);
            // std::cout << "[+]read file " << fd << std::hex << " offset : " << cur_read_pos << " size : " << size << " buf : " << buf << std::endl;;
            
            cur_read_pos = cur_read_pos + size;

            
            if (cur_read_pos >= filesize){
                cur_read_pos = 0;
            }

            ///*
            std::cout << "=======map table(read)=======" << std::endl;
            std::cout << "MEM_ADDR" << "\t|" << "Offset" << "\t|" << "SIZE" << std::endl;
            std::cout << "-----------------------------" << std::endl;
            for (it = Mappinglist.begin(); it != Mappinglist.end(); it++){
                Mappedfile tempfile = *it;
                std::cout << hex << "0x" << tempfile.memory_addr << "\t|" << "0x" << tempfile.file_offset << "\t|" << "0x" <<tempfile.size << std::endl;
            }
            std::cout << "=============================" << std::endl;
            //*/
            
            // sleep(4);
            // sleep(1);
        }
    }
    if(PIN_GetSyscallNumber(ctx, std) == __NR_pread64){
        UINT64 fd = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 0)));
        if (fd == input_fd){
            // std::cout << "[+]pread " << fd << std::endl;
            buf = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 1)));
            size = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 2)));
            offset = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 3)));

            //old code
            // for (i = 0; i < size; i++)
            //     taintedAddress.push_back(buf+i);
            //new code
            ///*
            for (it = Mappinglist.begin(); it != Mappinglist.end();){
                Mappedfile tempfile = *it;
                // (void)tempfile;
                
                if (tempfile.memory_addr == buf){
                    Mappinglist.erase(it++);
                    break;  
                } 
                else it++;
            }
            //*/
            if (offset <= filesize){
                if (offset + size > filesize){
                    size = filesize - offset;
                }
            }
            //strange but store
            else{
                size = 8;
            }
                
            Mappedfile file = {buf,offset,size};
            
            Mappinglist.push_back(file);
 
            

            ///*
            // std::cout << "======map table=========" << std::endl;
            // for (it = Mappinglist.begin(); it != Mappinglist.end(); it++){
            //     Mappedfile tempfile = *it;
                
            //     std::cout << tempfile.memory_addr << "\t|" << tempfile.file_offset << "\t|" << tempfile.size << std::endl;
                
                   
            // }
            // std::cout << "=======================" << std::endl;
            // //*/
            


            // std::cout << "[+]pread file " << fd << std::hex << " offset : " << offset << " size : " << size << " buf : " << buf << std::endl;;
            
        }
    }

    
    ///*


  //*/
}

VOID Syscall_exit(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v)
{
    list<Mappedfile>::iterator it;

    //모든 syscall에 대해 input file(poc)인지 확인 후 input file의 fd 설정
    if(syscall_number == __NR_open){
      
 

        char * mmapArg = reinterpret_cast<char *>(PIN_GetSyscallArgument(ctx, std, 0));
        std::string arg0(mmapArg);

      // std::cout << arg0 << std::endl;
      if(!(arg0.compare(filename))){
        input_fd = PIN_GetSyscallReturn(ctx, std);

        std::cout << "[+]setting file descriptor " << input_fd << std::endl;
      }
      else{
        input_fd = -10;
      }
    }

    if (syscall_number == __NR_mmap){
        
        UINT64 fd = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 4)));
        if (fd == input_fd){
            size = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 1)));
            offset = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 5)));
            buf = PIN_GetSyscallReturn(ctx, std);
            
            if (filesize < size){ size = filesize; }

            for (it = Mappinglist.begin(); it != Mappinglist.end();){
                Mappedfile tempfile = *it;
                if (tempfile.memory_addr == buf){
                    Mappinglist.erase(it++);
                    break;
                }
                else it++;
            }
            Mappedfile file = {buf, offset, size};
            Mappinglist.push_back(file);
            std::cout << fd << "   "<< input_fd << std::endl;
            // std::cout << "=======map table(mmap)=======" << std::endl;
            // std::cout << "MEM_ADDR" << "\t|" << "Offset" << "\t|" << "SIZE" << std::endl;
            // std::cout << "-----------------------------" << std::endl;
            // for (it = Mappinglist.begin(); it != Mappinglist.end(); it++){
            //     Mappedfile tempfile = *it;
            //     std::cout << hex << "0x" << tempfile.memory_addr << "\t|" << "0x" << tempfile.file_offset << "\t|" << "0x" <<tempfile.size << std::endl;
            // }
            // std::cout << "=============================" << std::endl;

        
        }
    }

    if(syscall_number == __NR_lseek){
    // std::cout << "[+]system call lseek" << std::endl;
      UINT64 fd = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 0)));
      if (fd == input_fd){
        std::cout << "[+]lseek " << fd << std::endl;
        start = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 2)));
        size  = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 1)));
        cur_read_pos = PIN_GetSyscallReturn(ctx, std);
        std::cout << cur_read_pos << std::endl;
        std::cout << start << ' ' << size << std::endl;
      // for (i = 0; i < size; i++)
      //   taintedAddress.push_back(start+i);
      
      // std::cout << "[TAINT]\t\t\tbytes tainted from " << std::hex << "0x" << start << " to 0x" << start+size << " (via read)"<< std::endl;
      }

  }

}


// VOID Routine(RTN rtn, VOID *v) { 
//     std::cout << RTN_Name(rtn) << std::endl;
// }



int main(int argc, char *argv[])
{
    // clock_t start, end;
    PIN_InitSymbols();
    if(PIN_Init(argc, argv)){
        return Usage();
    }
    // std::cout << "==================" << std::endl;
    // std::cout << argc << std::endl;
    // std::cout << argv[0] << std::endl;
    // std::cout << argv[1] << std::endl;
    // std::cout << argv[2] << std::endl;
    // std::cout << argv[3] << std::endl;
    // std::cout << argv[4] << std::endl;
    // std::cout << argv[5] << std::endl;
    // std::cout << argv[6] << std::endl;
    // std::cout << argv[7] << std::endl;
    // std::cout << argv[8] << std::endl;
    std::cout << "==================" << std::endl;


    filename = KnobPoCName.Value().c_str();
    std::cout << filename << std::endl;
    std::cout << "==================" << std::endl;

    std::ifstream in_file(filename.c_str(), std::ios::binary);
    in_file.seekg(0, ios::end);
    filesize = in_file.tellg();
    std::cout << filesize << std::endl;
    std::cout << "==================" << std::endl;

    vulnfunc = KnobVulnFunc.Value().c_str();
    std::cout << vulnfunc << std::endl;
    std::cout << "==================" << std::endl;




    PIN_SetSyntaxIntel();
    PIN_AddSyscallEntryFunction(Syscall_entry, 0);
    PIN_AddSyscallExitFunction(Syscall_exit, 0);


    INS_AddInstrumentFunction(Instruction, 0);
    IMG_AddInstrumentFunction(Image, 0);
    
    // RTN_AddInstrumentFunction(Routine,0);

    PIN_AddFiniFunction(Fini, argv[4]);   

    start_time = clock();
    PIN_StartProgram();
    // end = clock();
    // std::cout << "TIME" << (float)(end - start)/CLOCKS_PER_SEC << std::endl;
    return 0;
}