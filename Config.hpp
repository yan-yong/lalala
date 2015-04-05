#ifndef __CONFIG_HPP
#define __CONFIG_HPP
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp> 
#include <string>
#include "utility/string_utility.h"
#include "utility/net_utility.h"

struct Config
{
    char* bind_ip_;
    char* config_file_;
    char* listen_port_;
    unsigned worker_process_count_;
    unsigned max_connect_count_;
    unsigned connect_timeout_sec_;
    char* save_offset_file_prefix_;
    unsigned scan_low_range_[4];
    unsigned scan_high_range_[4];
    unsigned scan_interval_sec_;
    char* try_http_url_;
    unsigned try_http_size_; 
    char* try_https_url_;
    unsigned try_https_size_;
    int shm_key_;
    unsigned shm_size_;
    unsigned max_proxy_num_;
    unsigned validate_interval_sec_;
    unsigned proxy_error_retry_num_;
    char*    dump_file_name_;
    unsigned dump_interval_seconds_;
    char*    proxy_judy_url_;

    std::vector<uint16_t> port_vec_;

public:
    Config(const char* config_file)
    {
        memset(this, 0, (char*)&port_vec_ - (char*)this);
        config_file_ = strdup(config_file);
    }
    ~Config()
    {
        if(config_file_)
        {
            free(config_file_);
            config_file_ = NULL;
        }
        if(save_offset_file_prefix_)
        {
            free(save_offset_file_prefix_);
            save_offset_file_prefix_ = NULL;
        }
        if(try_http_url_)
        {
            free(try_http_url_);
            try_http_url_ = NULL;
        }
        if(try_https_url_)
        {
            free(try_https_url_);
            try_https_url_ = NULL;
        }
        if(proxy_judy_url_)
        {
            free(proxy_judy_url_);
            proxy_judy_url_ = NULL;
        }
        if(bind_ip_)
        {
            free(bind_ip_);
            bind_ip_ = NULL;
        }
        if(listen_port_)
        {
            free(listen_port_);
            listen_port_ = NULL;
        }
        if(dump_file_name_)
        {
            free(dump_file_name_);
            dump_file_name_ = NULL;
        }
    }

    int ReadConfig()
    {
        boost::property_tree::ptree pt; 
        read_xml(config_file_, pt);

        std::string bind_eth = pt.get<std::string>("Root.EthName");
        std::string ip_str;
        get_local_address(bind_eth, ip_str);
        if(ip_str.empty())
            bind_ip_ = strdup("0.0.0.0");
        else
            bind_ip_ = strdup(ip_str.c_str());
        std::string port_str = pt.get<std::string>("Root.ListenPort");
        listen_port_ = strdup(port_str.c_str());
        assert(atoi(listen_port_) > 0);
        worker_process_count_ = pt.get<unsigned>("Root.WorkProcessCount");
        max_connect_count_ = pt.get<unsigned>("Root.MaxConnectCount");
        connect_timeout_sec_ = pt.get<unsigned>("Root.ConnectTimeoutSec");
        std::string file_prefix = pt.get<std::string>("Root.ScanOffsetFilePrefix");
        if(!file_prefix.empty())
            save_offset_file_prefix_ = strdup(file_prefix.c_str());

        std::string low_range_str = pt.get<std::string>("Root.ScanLowRange");
        std::vector<std::string> low_range_vec;
        split_string(low_range_str.c_str(), ".", low_range_vec);
        assert(low_range_vec.size() == 4);
        std::string high_range_str = pt.get<std::string>("Root.ScanHighRange");
        std::vector<std::string> high_range_vec;
        split_string(high_range_str.c_str(), ".", high_range_vec);
        assert(high_range_vec.size() == 4);
        unsigned low_range_sum = 0, high_range_sum = 0;
        for(unsigned i = 0; i < 4; i++)
        {
            scan_low_range_[i] = (unsigned)atoi(low_range_vec[i].c_str());
            scan_high_range_[i]= (unsigned)atoi(high_range_vec[i].c_str());
            assert(scan_low_range_[i] < scan_high_range_[i]);
            low_range_sum  += scan_low_range_[i];
            high_range_sum += scan_high_range_[i];
        }
        assert(low_range_sum < high_range_sum);

        scan_interval_sec_ = pt.get<unsigned>("Root.ScanIntervalSec");

        std::string try_http_url = pt.get<std::string>("Root.TryHttpUrl");
        try_http_url_ = strdup(try_http_url.c_str());
        try_http_size_= pt.get<unsigned>("Root.TryHttpUrl.<xmlattr>.size");

        std::string try_https_url = pt.get<std::string>("Root.TryHttpsUrl");
        try_https_url_ = strdup(try_https_url.c_str());
        try_https_size_= pt.get<unsigned>("Root.TryHttpsUrl.<xmlattr>.size");

        std::string proxy_judy_url = pt.get<std::string>("Root.ProxyJudyUrl");
        proxy_judy_url_ = strdup(proxy_judy_url.c_str()); 

        std::string scan_port_str = pt.get<std::string>("Root.ScanPort");
        std::vector<std::string> port_vec;
        split_string(scan_port_str.c_str(), ":", port_vec);
        for(unsigned i = 0; i < port_vec.size(); i++)
            port_vec_.push_back((uint16_t)atoi(port_vec[i].c_str()));

        shm_key_ = pt.get<int>("Root.ShmKey"); 
        shm_size_= pt.get<unsigned>("Root.ShmSize");        
        max_proxy_num_ = pt.get<unsigned>("Root.MaxProxyNum");
        std::string dump_file = pt.get<std::string>("Root.ShmDumpFile");
        dump_file_name_ = strdup(dump_file.c_str());
        dump_interval_seconds_ = pt.get<unsigned>("Root.ShmDumpIntervalSec");

        validate_interval_sec_ = pt.get<unsigned>("Root.ValidateIntervalSec");
        proxy_error_retry_num_ = pt.get<unsigned>("Root.ProxyErrorRetryNum");
        return 0;
    }
};

#endif
