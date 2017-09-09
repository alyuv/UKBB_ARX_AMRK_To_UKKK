#include "stdafx.h"
#include "SshConnection.h"

#pragma comment(lib, "Ws2_32.lib")

#include "libssh2_config.h"

#include <iostream>
#include <fstream>

#include <libssh2.h>

#ifdef HAVE_WINSOCK2_H
# include <winsock2.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
# ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif

/* last resort for systems not defining PRIu64 in inttypes.h */
#ifndef __PRI64_PREFIX
#ifdef WIN32
#define __PRI64_PREFIX "I64"
#else
#if __WORDSIZE == 64
#define __PRI64_PREFIX "l"
#else
#define __PRI64_PREFIX "ll"
#endif /* __WORDSIZE */
#endif /* WIN32 */
#endif /* !__PRI64_PREFIX */
#ifndef PRIu64
#define PRIu64 __PRI64_PREFIX "u"
#endif  /* PRIu64 */


#include <plog/Log.h>
#include <plog/Appenders/RollingFileAppender.h>
#include <plog/Appenders/ColorConsoleAppender.h>
#include <plog/Appenders/DateFileAppender.h>

#include <filesystem>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/array.hpp>
#include <boost/filesystem.hpp>
#include <boost/range.hpp>
#include <iostream>
#include <map>

#pragma warning (disable : 4996)

static int waitsocket(int socket_fd, LIBSSH2_SESSION *session_ssh_) {
        struct timeval timeout;
        int rc;
        fd_set fd;
        fd_set *writefd = NULL;
        fd_set *readfd = NULL;
        int dir;
        
        timeout.tv_sec = 0;
        timeout.tv_usec = 100;

        FD_ZERO(&fd);
        FD_SET(socket_fd, &fd);

        dir = libssh2_session_block_directions(session_ssh_);

        if (dir & LIBSSH2_SESSION_BLOCK_INBOUND)
                readfd = &fd;

        if (dir & LIBSSH2_SESSION_BLOCK_OUTBOUND)
                writefd = &fd;

        rc = select(socket_fd + 1, readfd, writefd, NULL, &timeout);

        return rc;
}

const char * SshConnection::hostToIp(const char * host) {
        hostent* hostname = gethostbyname(host);
        if (hostname)
                return inet_ntoa(**(in_addr**)hostname->h_addr_list);
        return{};
}

SshConnection::SshConnection(const char *hostname, const char *username, const char *password, const char *publickey, const char *privatekey, const unsigned int auth_pw, const unsigned int port, const char * logfile) :
hostname_(hostname), username_(username), password_(password), publickey_(publickey), privatekey_(privatekey), auth_pw_(auth_pw), port_(port), logfile_(logfile)
{
        static plog::DateFileAppender<plog::TxtFormatterN> dfileAppender(logfile_);
        plog::init(plog::debug, &dfileAppender);

        session_ssh_ = NULL;
        LOGI << "Start SSH connection to host " << hostname_;
        bool success = sshConnect();
        if (!success)
        {
                LOGE << "Erro to start SSH connection to host " << hostname_;
                exit(1);
        }


}

SshConnection::~SshConnection()
{
        sshDisconnect();
        LOGI << "End SSH Connection to host " << hostname_;
}

bool SshConnection::getFilesSourceDir(std::string dir) 
{
        srcFiles_.clear();
        using namespace boost::filesystem;
        path p(dir);
        if (!exists(p))
        {
                LOGE << "Not found source directory: " << p;
                return false;
        }
        if (is_directory(p))
        {
                directory_iterator end_iter;
                for (directory_iterator dir_itr(p); dir_itr != end_iter; ++dir_itr)
                {
                        try
                        {
                                if (is_regular_file(dir_itr->status()))
                                {
                                        std::stringstream tmpss;
                                        tmpss << dir_itr->path().filename().string();
                                        srcFiles_.push_back(tmpss.str());
                                }
                        }
                        catch (const std::exception & ex)
                        {
                                LOGE << dir_itr->path().filename() << " " << ex.what();
                        }
                }
                return true;
        }

        else 
        {
                LOGE << "Found: " << p;
                return true;
        }
}

bool SshConnection::createDestDir(std::string dir)
{       
        int rc = 0;     
        sftp_handle_ = libssh2_sftp_opendir(session_sftp_, dir.c_str());
        if (!sftp_handle_)
        {
                LOGW << "Destenation directory " << dir << " not exist. Trying to create.";
                rc = libssh2_sftp_mkdir(session_sftp_, dir.c_str(), LIBSSH2_SFTP_S_IRWXU | LIBSSH2_SFTP_S_IRWXU |
                        LIBSSH2_SFTP_S_IRGRP | LIBSSH2_SFTP_S_IXGRP | LIBSSH2_SFTP_S_IROTH | LIBSSH2_SFTP_S_IXOTH);
                sftp_handle_ = libssh2_sftp_opendir(session_sftp_, dir.c_str());

                if (rc)
                {
                        LOGE << "Create destenation directory " << dir << " failed.";
                        return false;
                }
                else
                {
                        LOGI << "Destenation dir " << dir << " created successfully.";                  
                }
                        
        }
        return true;
}

bool SshConnection::getFilesDestDir(std::string dir) 
{       
        scpFiles_.clear();
        session_sftp_ = libssh2_sftp_init(session_ssh_);        

        std::vector<std::string> splitVec;
        boost::array<char, 2>separator = { '/', '\\' };
        boost::algorithm::split(splitVec, dir, boost::algorithm::is_any_of(separator));

        std::string destdir;
        if (splitVec.size() > 1)
        {
                destdir = "/" + splitVec[1] + "/" + splitVec[2] + "/";          
        }

        if (splitVec.size() > 2)
        {
                for (size_t i = 3; i < splitVec.size()-1; i++)
                {                       
                        destdir = destdir + splitVec[i] + "/";  
                        createDestDir(destdir); 
                }
        }
        
        int rc = 0;

        if (sftp_handle_)
        {
                do 
                {
                        char filename[512];
                        LIBSSH2_SFTP_ATTRIBUTES attrs;

                        rc = libssh2_sftp_readdir(sftp_handle_, filename, sizeof(filename), &attrs);
                        if (rc > 0)
                        {
                                if (filename[0] != '\0' && filename[0] != '.')
                                {
                                        std::stringstream tmpss;
                                        tmpss << filename;
                                        scpFiles_.push_back(tmpss.str());
                                }
                        }
                        else
                                break;

                } while (1);
                return true;
        }

        else
        {
                LOGE << "Get files in destenation directory " << dir << " failed.";
                return false;
        }

        libssh2_sftp_closedir(sftp_handle_);            
        libssh2_sftp_shutdown(session_sftp_);
        return true;
}

std::string SshConnection::findLastFile(const std::string &srcpath)
{
        using namespace boost::filesystem;
        std::time_t latest_tm{};
        path latest;

        path p(srcpath);
        if (!exists(p))
        {
                LOGE << " Not found directory - " << p;
                return false;
        }

        if (is_directory(p))
        {
                directory_iterator end_iter;
                for (directory_iterator dir_itr(p); dir_itr != end_iter; ++dir_itr)
                {
                        try
                        {
                                if (is_regular_file(dir_itr->status()))
                                {
                                        std::stringstream tmpss;
                                        tmpss << dir_itr->path().filename().string();
                                        srcFiles_.push_back(tmpss.str());

                                        std::time_t timestamp;
                                        timestamp = last_write_time(dir_itr->path());
                                        if (latest_tm < timestamp)
                                        {
                                                latest = dir_itr->path();
                                                latest_tm = timestamp;
                                        }                                                                            
                                }
                        }
                        catch (const std::exception & ex)
                        {
                                LOGE << dir_itr->path().filename() << " " << ex.what();
                        }
                }
                return latest.filename().string();
        }
        else
        {
                LOGE << "Found: " << p;
                return p.string() + " must be a file";
        }

}

std::string SshConnection::createIramDatePath()
{
        time_t loctime;
        struct tm * ptm;

        time(&loctime);
        ptm = gmtime(&loctime);

        std::string year = std::to_string(ptm->tm_year + 1900);
        std::string month = std::to_string(ptm->tm_mon + 1);
        std::string day = std::to_string(ptm->tm_mday);

        std::stringstream datePath;        
        datePath << "/G" << year << "/M" << std::setfill('0') << std::setw(2) << month << "/D" << std::setfill('0') << std::setw(2) << day << "/";
        return datePath.str();
}

bool SshConnection::sshConnect()
{
        unsigned long hostaddr;
        struct sockaddr_in sin;
        int rc;       

#ifdef WIN32
        WSADATA wsadata;
        int err;

        err = WSAStartup(MAKEWORD(2, 0), &wsadata);
        if (err != 0) {                
                LOGE << "WSAStartup failed with error: " << err;
                return false;
        }
#endif

        rc = libssh2_init(0);
        if (rc != 0)
        {
                LOGE << "libssh2 initialization failed (" << rc << ")";
                return false;
        }

        hostaddr = inet_addr(hostToIp(hostname_));


        sin.sin_family = AF_INET;
        sin.sin_port = htons(port_);
        sin.sin_addr.s_addr = hostaddr;

        socket_ = socket(AF_INET, SOCK_STREAM, 0);

        if (connect(socket_, (struct sockaddr*) (&sin), sizeof(struct sockaddr_in)) != 0)
        {
                LOGE << "Could not connect to host " << hostname_;
                return false;
        }

        session_ssh_ = libssh2_session_init();
        if (!session_ssh_)
                return false;

        rc = libssh2_session_handshake(session_ssh_, socket_);
        if (rc)
        {
                LOGE << "Failure establishing SSH session_ssh_: " << rc;
                return false;
        }

        if (auth_pw_)
        {
                if (libssh2_userauth_password(session_ssh_, username_, password_))
                {
                        LOGE << "Authentication by password failed.";
                        return false;
                }
        }
        else
        {
                if (libssh2_userauth_publickey_fromfile(session_ssh_, username_, publickey_, privatekey_, password_))
                {
                        LOGE << "Authentication by public key " << publickey_ << " failed.";
                        return false;
                }
        }
        LOGI << "SCP public/private key authentication for username '" << username_ << "'";

        return true;
}

void SshConnection::sshDisconnect()
{
        libssh2_session_disconnect(session_ssh_, "Normal Shutdown. Thank you for interaction");
        libssh2_session_free(session_ssh_);
#ifdef WIN32
        closesocket(socket_);
#else
        close(socket_);
#endif
        libssh2_exit();

}

bool SshConnection::runCommand(const std::string &command, std::string &output, int &exitcode) //const
{
        return true;
}

bool SshConnection::sendFile(const std::string &srcpathfile, const std::string &scppathfile)
{
        FILE *local;
        struct stat fileinfo;
        int rc;
        char mem[1024 * 100];
        size_t nread;
        char *ptr;
        long total = 0;
        size_t prev;

        LOGI << "Start copy file: " << srcpathfile;
        local = fopen(srcpathfile.c_str(), "rb");
        if (!local)
        {               
                LOGE << "Can't find local file " << srcpathfile.c_str();
                return false;
        }

        stat(srcpathfile.c_str(), &fileinfo);
        channel_ = libssh2_scp_send(session_ssh_, scppathfile.c_str(), fileinfo.st_mode & 0777, (unsigned long)fileinfo.st_size);

        if ((!channel_) && (libssh2_session_last_errno(session_ssh_) != LIBSSH2_ERROR_EAGAIN))
        {
                char *err_msg;

                libssh2_session_last_error(session_ssh_, &err_msg, NULL, 0);
                LOGE << "Send file error: " << err_msg;
                return false;
        }

        do {
                nread = fread(mem, 1, sizeof(mem), local);
                if (nread <= 0) {
                        break;
                }
                ptr = mem;

                total += nread;

                prev = 0;
                do {
                        while ((rc = libssh2_channel_write(channel_, ptr, nread)) == LIBSSH2_ERROR_EAGAIN)
                        {
                                waitsocket(socket_, session_ssh_);
                                prev = 0;
                        }
                        if (rc < 0) {
                                LOGE << "Send file error " << rc << "total " << total << " / " << (int)nread << " prev " << (int)prev;
                                return false;
                        }
                        else {
                                prev = nread;
                                nread -= rc;
                                ptr += rc;
                        }
                } while (nread);
        } while (!nread);

        LOGI << "File: " << srcpathfile << " is copied to " << scppathfile;
        libssh2_channel_free(channel_);
        channel_ = NULL;
        return true;
}

bool SshConnection::sendMissingFiles(const std::string &srcpath, const std::string &scppath) //const
{
        std::string srcFile;
        std::string scpFile;
        long total = 0;

        time_t loctime;
        struct tm * ptm;

        time(&loctime);
        ptm = gmtime(&loctime);

        std::string year = std::to_string(ptm->tm_year + 1900);
        std::string month = std::to_string(ptm->tm_mon + 1);
        std::string day = std::to_string(ptm->tm_mday);

        std::stringstream sourcePath;
        sourcePath << srcpath << createIramDatePath();
        
        std::stringstream scpPath;
        scpPath << scppath << createIramDatePath();
        
        getFilesSourceDir(sourcePath.str());
        getFilesDestDir(scpPath.str());

        std::sort(srcFiles_.begin(), srcFiles_.end());
        std::sort(scpFiles_.begin(), scpFiles_.end());

        diffFiles_.clear();
        std::set_difference(srcFiles_.begin(), srcFiles_.end(), scpFiles_.begin(), scpFiles_.end(), std::back_inserter(diffFiles_));
        if (diffFiles_.size() == 0)
        {
                LOGI << "No new files to copy from " << sourcePath.str() << " to " << scpPath.str();
        }
        else
        {
                for (size_t i = 0; i < diffFiles_.size(); i++)
                {
                        srcFile = sourcePath.str() + diffFiles_[i];
                        scpFile = scpPath.str() + diffFiles_[i];
                        sendFile(srcFile, scpFile);
                }
        }
        return true;
}

bool SshConnection::sendLastFile(const std::string &srcpath, const std::string &scppath)
{
        std::string dateSrcPath = srcpath + createIramDatePath();

        std::string lastFile = findLastFile(dateSrcPath);       
        std::string srcFile = srcpath + createIramDatePath() + lastFile;
        std::string dstFile = scppath + createIramDatePath() + lastFile;
        std::string dstPath = scppath + createIramDatePath();
        getFilesDestDir(dstPath);  ///  
        sendFile(srcFile, dstFile);
        return true;
}

bool SshConnection::getFile(const std::string &scppath, const std::string &dstpath) //const
{
        struct stat fileinfo;
        int total = 0;
        int spin = 0;
        off_t got = 0;

        std::ofstream dstFile;
        try
        {
                dstFile.open(dstpath.c_str());
        }
        catch (std::ofstream::failure e)
        {
                LOGE << "SSH download to file error - could not open local file: " << dstpath;
                return false;
        }

        channel_ = libssh2_scp_recv(session_ssh_, scppath.c_str(), &fileinfo);
        if (!channel_)
        {
                char *err_msg;
                libssh2_session_last_error(session_ssh_, &err_msg, NULL, 0);
                LOGE << "getFile() error: " << err_msg;
                return false;
        }

        while (got < fileinfo.st_size)
        {
                char mem[1024];
                int amount = sizeof(mem);
                int rc;
                if ((fileinfo.st_size - got) < amount) {
                        amount = fileinfo.st_size - got;
                }

                rc = libssh2_channel_read(channel_, mem, amount);
                if (rc > 0) 
                {
                        for (int i = 0; i<rc; i++)
                                dstFile << mem[i];
                }
                else if (rc < 0) 
                {
                        LOGE << "libssh2_channel_read() failed: " << rc;                        
                        break;
                }
                got += rc;
        }
        
        libssh2_channel_free(channel_);
        channel_ = NULL;

        dstFile.close();

        return true;
}
