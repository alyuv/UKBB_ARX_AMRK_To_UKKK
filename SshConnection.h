#pragma once

#include <libssh2.h>
#include <libssh2_sftp.h>
#include <string>
#include <vector>

class SshConnection
{
public:
        SshConnection(const char *hostname, const char *username, const char *password, const char *publickey = "", const char *privatekey = "", const unsigned int auth_pw = 0, const unsigned int port = 22, const char *logfile = "test.log");
        ~SshConnection();

        const char * hostToIp(const char * host);
        std::string findLastFile(const std::string &srcpath);
        std::string createIramDatePath();

        bool runCommand(const std::string &command, std::string &output, int &exitcode); 
        bool sendMissingFiles(const std::string &srcpath, const std::string &scppath); 
        bool sendFile(const std::string &srcpathfile, const std::string &scppathfile); 
        bool sendLastFile(const std::string &srcpath, const std::string &scppath);
        bool getFile(const std::string &scppath, const std::string &dstpath); 

private:
        bool sshConnect();
        void sshDisconnect();
        bool getFilesSourceDir(std::string dir); 
        bool getFilesDestDir(std::string dir); 
        bool createDestDir(std::string dir); 

        
        LIBSSH2_CHANNEL *channel_;
        LIBSSH2_SFTP *session_sftp_;
        LIBSSH2_SFTP_HANDLE *sftp_handle_;

        LIBSSH2_SESSION *session_ssh_;  
        int socket_;                    

        std::vector<std::string> srcFiles_;
        std::vector<std::string> scpFiles_;
        std::vector<std::string> diffFiles_;

        const char *hostname_; 
        const char *username_;
        const char *password_;
        const char *publickey_;
        const char *privatekey_;
        const unsigned int auth_pw_;
        const unsigned int port_;
        const char *logfile_;

};


