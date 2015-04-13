#ifndef __PROXY_SCANNER_HPP
#define __PROXY_SCANNER_HPP
#include <string>
#include <vector>
#include <queue>
#include <map>
#include <list>
#include <boost/shared_ptr.hpp>
#include <boost/function.hpp>
#include <boost/bind.hpp>
#include <httpparser/TUtility.hpp>
#include <boost/unordered_set.hpp>
#include "lock/lock.hpp"
#include "utility/net_utility.h"
#include "fetcher/Fetcher.hpp"
#include "shm/ShareHashSet.hpp" 
#include "Proxy.hpp" 

typedef ShareHashSet<Proxy, HashFunctor> ProxySet; 

class ProxyScanner: protected IMessageEvents
{
    static const unsigned DEFAULT_SCAN_INTERVAL_SEC    = 0;
    static const unsigned DEFAULT_VALIDATE_INTERVAL_SEC= 600;
    static const unsigned DEFAULT_REQ_CHECK_INTERVAL   = 100;

    void __load_offset_file();
    void __save_offset_file();     

protected:
    virtual struct RequestData* CreateRequestData(void *);
    virtual void FreeRequestData(struct RequestData *);
    virtual IFetchMessage* CreateFetchResponse(const FetchAddress&, void *);
    virtual void FreeFetchMessage(IFetchMessage *);

    virtual void GetScanProxyRequest(int, std::vector<RawFetcherRequest>&);
    virtual void FinishProxy(Proxy* proxy);
    virtual void ProcessResult(const RawFetcherResult&);
    RawFetcherRequest CreateFetcherRequest(Proxy* proxy, Connection* conn = NULL);
 
public:
    ProxyScanner(ProxySet * proxy_set,
        Fetcher::Params fetch_params,
        const char* eth_name = NULL);
    ~ProxyScanner();
    void SetHttpTryUrl(std::string try_url, size_t page_size);
    void SetHttpsTryUrl(std::string try_url, size_t page_size);
    void SetScanPort(const std::vector<uint16_t>& scan_port);
    void SetScanRange(unsigned low_range[4], unsigned high_range[4]); 
    void SetScanOffset(unsigned offset[4]);
    void GetScanOffset(unsigned offset[4]) const;
    void SetValidateIntervalSeconds(time_t validate_interval_sec);
    void SetScanIntervalSeconds(time_t scan_interval_sec);
    void SetErrorRetryNum(unsigned proxy_error_num);
    void SetProxyJudyUrl(std::string url, size_t max_size);
    void SetMaxTxSpeed(size_t max_tx_speed);
    void SetMaxRxSpeed(size_t max_rx_speed);
    void SetSynRetryTimes(unsigned retry_times);
    void Stop();
    void RequestGenerator(int fetcher_quota, std::vector<RawFetcherRequest>& req_vec);
    void Start();

protected:
    Fetcher::Params params_;
    time_t offset_save_interval_;
    time_t offset_save_time_;
    Fetcher::Params fetcher_params_;
    URI*    try_http_uri_;
    size_t  try_http_size_;
    URI*    try_https_uri_;
    size_t  try_https_size_;
    URI*    proxy_judy_uri_;
    size_t  max_http_body_size_;
    boost::shared_ptr<ThreadingFetcher> fetcher_;
    std::vector<uint16_t> scan_port_;
    unsigned offset_[4];
    unsigned port_idx_;
    unsigned low_range_[4];
    unsigned high_range_[4];
    sockaddr* local_addr_;
    time_t validate_time_;
    time_t validate_interval_;
    time_t scan_time_;
    time_t scan_interval_; 
    ProxySet *proxy_set_;
    bool stopped_;
    std::queue<RawFetcherRequest> req_queue_;
    unsigned error_retry_num_;
    ProxySet::HashKey validate_idx_;
    time_t   conn_timeout_;
    //最大入带宽，单位是Byte
    size_t   max_tx_traffic_;
    time_t   last_tx_stat_time_;
    unsigned syn_retry_times_;
    //当前由正常连接造成的出带宽
    size_t   cur_tx_traffic_;
    //当前入带宽
    size_t   cur_rx_traffic_;
    //最大出带宽，单位是Byte
    size_t   max_rx_traffic_;
    time_t   last_rx_stat_time_;
    time_t   fit_rx_begin_time_;
    size_t   each_validate_max_;
};

inline time_t current_time_ms()
{
    timeval tv; 
    gettimeofday(&tv, NULL);
    return (tv.tv_sec*1000000 + tv.tv_usec) / 1000;
}

#endif 
