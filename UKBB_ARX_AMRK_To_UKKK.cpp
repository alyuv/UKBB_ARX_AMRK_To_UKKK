// UKBB_ARX_AMRK_To_UKKK.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "SshConnection.h"

std::string getCurrentDirWindows()
{
        const unsigned long maxDir = 260;
        char currentDir[maxDir];
        GetCurrentDirectory(maxDir, currentDir);
        return std::string(currentDir);
}

int _tmain(int argc, _TCHAR* argv[])
{
        const char * host = "localhost";
        const char * user = "autobrif";
        const char * password = "MliIlb+v:55x*";
        const char * logfile = "UKBB_ARX_AMRK_To_UKKK.log";

        std::string pathprivatekey = getCurrentDirWindows().append("\\key\\autobrif@localhost.ppk");
        std::string pathpublickey = getCurrentDirWindows().append("\\key\\autobrif@localhost.key");

        SshConnection sshconnection(host, user, password, pathpublickey.c_str(), pathprivatekey.c_str(), 0, 22, logfile);
        sshconnection.sendMissingFiles("I:/ARX_AMRK/S33348", "/mnt/zhul_telex_d/IRAM/ARX_AMRK/S33348");
        sshconnection.sendMissingFiles("I:/ARX_AMRK/R33348", "/mnt/zhul_telex_d/IRAM/ARX_AMRK/R33348");
        sshconnection.sendMissingFiles("I:/ARX_AMRK/V33348", "/mnt/zhul_telex_d/IRAM/ARX_AMRK/V33348");
        sshconnection.sendMissingFiles("I:/ARX_AMRK/W33348", "/mnt/zhul_telex_d/IRAM/ARX_AMRK/W33348");
        return 0;
}

