#ifndef __CONFIG_HPP
#define __CONFIG_HPP
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp> 
#include <string>
#include <boost/regex.hpp>
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
    unsigned proxy_judy_size_;
    size_t   tx_max_speed_bytes_;
    unsigned syn_retries_;
    size_t   rx_max_speed_bytes_;
    size_t   max_http_body_size_;

    std::vector<uint16_t>    port_vec_;
    std::vector<std::string> nodes_ip_;
    ScannerCounter     scanner_counter_;
    std::string  worker_log_name_;
    std::string  master_log_name_;

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
        worker_process_count_ = pt.get<unsigned>("Root.WorkerProcessCount");
        max_connect_count_ = pt.get<unsigned>("Root.MaxConnectCount");
        connect_timeout_sec_ = pt.get<unsigned>("Root.ConnectTimeoutSec");

        scan_interval_sec_ = pt.get<unsigned>("Root.ScanIntervalSec");
        std::string ip_file = pt.get<std::string>("Root.ScanIpFile");
        ScannerCounter all_scanner_counter;
        all_scanner_counter.LoadFromFile(ip_file.c_str());

        std::string nodes_str = pt.get<std::string>("Root.Nodes");
        boost::regex expression("\\d+\\.\\d+\\.\\d+\\.\\d+");
        boost::smatch what;
        std::string::const_iterator start = nodes_str.begin();
        std::string::const_iterator end   = nodes_str.end();
        while( boost::regex_search(start, end, what, expression) )
        {
            for (size_t i = 0; i < what.size(); ++i)
            {
                if (what[i].matched)
                    nodes_ip_.push_back(what[i]);
            }
            start = what[0].second;
        }
        int nodes_num = nodes_ip_.size();
        assert(nodes_num > 0);
        int cur_node_idx = -1;
        std::string bind_ip = bind_ip_;
        for(unsigned i = 0; i < nodes_ip_.size(); ++i)
        {
            if(bind_ip == nodes_ip_[i])
            {
                cur_node_idx = i;
                break;
            }
        }
        assert(cur_node_idx >= 0);
        scanner_counter_ = all_scanner_counter.Split(nodes_num)[cur_node_idx];

        std::string try_http_url = pt.get<std::string>("Root.TryHttpUrl");
        try_http_url_ = strdup(try_http_url.c_str());
        try_http_size_= pt.get<unsigned>("Root.TryHttpUrl.<xmlattr>.size");

        std::string try_https_url = pt.get<std::string>("Root.TryHttpsUrl");
        try_https_url_ = strdup(try_https_url.c_str());
        try_https_size_= pt.get<unsigned>("Root.TryHttpsUrl.<xmlattr>.size");

        std::string proxy_judy_url = pt.get<std::string>("Root.ProxyJudyUrl");
        proxy_judy_url_  = strdup(proxy_judy_url.c_str());
        proxy_judy_size_ = pt.get<unsigned>("Root.ProxyJudyUrl.<xmlattr>.maxsize");

        tx_max_speed_bytes_ = pt.get<size_t>("Root.MaxTxSpeedByte");

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

        syn_retries_ = pt.get<unsigned>("Root.SynRetries");
        assert(syn_retries_ < 10 && syn_retries_ > 0);

        rx_max_speed_bytes_ = pt.get<size_t>("Root.MaxRxSpeedByte");
        //max_http_body_size_ = pt.get<size_t>("Root.MaxHttpBodySize");

        worker_log_name_ = pt.get<std::string>("Root.WorkerLog");
        master_log_name_  = pt.get<std::string>("Root.MasterLog");

        return 0;
    }
};

#endif
