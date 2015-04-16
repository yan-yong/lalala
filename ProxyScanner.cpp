#include "ProxyScanner.hpp"
#include "fetcher/Fetcher.hpp"
#include "utility/net_utility.h"
#include "boost/bind.hpp"
#include "httpparser/TUtility.hpp"
#include "httpparser/URI.hpp"
#include "httpparser/HttpFetchProtocal.hpp"
#include "log/log.h"

//tcp第一个握手包大小
const unsigned TCP_FIRST_PACKET_SIZE = 66;
const unsigned TCP_SECOND_PACKET_SIZE= 66;
const unsigned TCP_THIRD_PACKET_SIZE = 54;
const unsigned TCP_CLOSE_PACKET_SIZE = 54*2;
const unsigned TCP_DATA_HEADER_SIZE  = 54;

ProxyScanner::ProxyScanner(ProxySet * proxy_set,
    Fetcher::Params fetch_params,
    ScannerCounter * scanner_counter, 
    const char* ip_addr_str):
    scanner_counter_(scanner_counter),
    try_http_uri_(NULL), try_http_size_(0),
    try_https_uri_(NULL),try_https_size_(0),
    proxy_judy_uri_(NULL), 
    max_http_body_size_(0), port_idx_(0), 
    local_addr_(NULL), validate_time_(0),
    validate_interval_(DEFAULT_VALIDATE_INTERVAL_SEC*1000),
    scan_time_(0), 
    scan_interval_(DEFAULT_SCAN_INTERVAL_SEC*1000),
    proxy_set_(proxy_set), stopped_(false),
    error_retry_num_(0), validate_idx_(0),
    conn_timeout_(0), max_tx_traffic_(0), 
    last_tx_stat_time_(0), syn_retry_times_(6), 
    cur_tx_traffic_(0), cur_rx_traffic_(0),
    max_rx_traffic_(0), last_rx_stat_time_(0),
    fit_rx_begin_time_(0), each_validate_max_(1)
{
    uint16_t scan_ports[] = {80, 8080, 3128, 8118, 808};
    scan_port_.assign(scan_ports, scan_ports + sizeof(scan_ports)/sizeof(*scan_ports));
    memcpy(&params_, &fetch_params, sizeof(fetch_params));
    SetHttpTryUrl("http://www.baidu.com/img/baidu_jgylogo3.gif", 705);
    SetHttpsTryUrl("https://www.baidu.com/img/baidu_jgylogo3.gif", 705);
    proxy_judy_uri_ = NULL;        

    fetcher_.reset(new ThreadingFetcher(this));
    fetcher_->SetResultCallback(boost::bind(&ProxyScanner::ProcessResult, this, _1));
    ThreadingFetcher::RequestGenerator req_generator =
        boost::bind(&ProxyScanner::RequestGenerator, this, _1, _2);
    fetcher_->SetRequestGenerator(req_generator);
    if(ip_addr_str)
    {
        local_addr_ = (struct sockaddr*)malloc(sizeof(struct sockaddr));
        memset(local_addr_, 0, sizeof(struct sockaddr));
        local_addr_ = get_sockaddr_in(ip_addr_str, 0);
    }

    conn_timeout_ = params_.conn_timeout.tv_sec * 1000 + params_.conn_timeout.tv_usec / 1000;
}

ProxyScanner::~ProxyScanner()
{
    if(try_http_uri_)
        delete try_http_uri_;
    if(try_https_uri_)
        delete try_https_uri_;
}

void ProxyScanner::SetHttpTryUrl(std::string try_url, size_t page_size)
{
    if(try_http_uri_)
    {
        delete try_http_uri_;
        try_http_uri_ = NULL;
    }
    try_http_uri_ = new URI();
    if(!UriParse(try_url.c_str(), try_url.size(), *try_http_uri_)
        || !HttpUriNormalize(*try_http_uri_))
    {
        assert(false);
    }
    try_http_size_ = page_size;
    max_http_body_size_ = std::max(max_http_body_size_, try_http_size_ + 10);
}

void ProxyScanner::SetHttpsTryUrl(std::string try_url, size_t page_size)
{
    if(try_https_uri_)
    {
        delete try_https_uri_;
        try_https_uri_ = NULL;
    }
    try_https_uri_ = new URI();
    if(!UriParse(try_url.c_str(), try_url.size(), *try_https_uri_)
        || !HttpUriNormalize(*try_https_uri_))
    {
        assert(false);
    }
    try_https_size_ = page_size;
    max_http_body_size_ = std::max(max_http_body_size_, try_https_size_ + 10);
}

void ProxyScanner::SetProxyJudyUrl(std::string judy_url, size_t max_size)
{
    proxy_judy_uri_ = new URI();
    if(!UriParse(judy_url.c_str(), judy_url.size(), *proxy_judy_uri_)
        || !HttpUriNormalize(*proxy_judy_uri_))
    {
        assert(false);
    }
    if(max_http_body_size_ < max_size)
        max_http_body_size_ = max_size;
}

void ProxyScanner::SetMaxTxSpeed(size_t max_tx_speed)
{
    max_tx_traffic_ = max_tx_speed;
}

void ProxyScanner::SetMaxRxSpeed(size_t max_rx_speed)
{
    max_rx_traffic_ = max_rx_speed;
}

void ProxyScanner::SetSynRetryTimes(unsigned retry_times)
{
    syn_retry_times_ = retry_times;
}

void ProxyScanner::SetScanPort(const std::vector<uint16_t>& scan_port)
{
    scan_port_ = scan_port;
}

RawFetcherRequest ProxyScanner::CreateFetcherRequest(Proxy* proxy, Connection* conn)
{
    assert(proxy->state_ != Proxy::SCAN_IDLE);
    proxy->request_time_ = current_time_ms();
    int scheme = PROTOCOL_HTTP;
    switch(proxy->state_)
    {
        case(Proxy::SCAN_HTTP):
        {
            scheme = PROTOCOL_HTTP;
            ++(proxy->request_cnt_);
            break;
        }
        case(Proxy::SCAN_CONNECT):
        {
            scheme = PROTOCOL_HTTP;
            break;
        }
        case(Proxy::SCAN_HTTPS):
        {
            assert(conn);
            RawFetcherRequest request;
            request.context = (void*)proxy;
            request.conn    = conn;
            fetcher_->SetConnectionScheme(request.conn, PROTOCOL_HTTPS);
            return request;
        }
        case(Proxy::SCAN_JUDGE):
        {
            scheme = PROTOCOL_HTTP;
            break;
        }
        default:
        {
            LOG_ERROR("invalid proxy state: %d.\n", proxy->state_);
            assert(false);
        }
    }

    FetchAddress fetch_address;
    fetch_address.remote_addr = proxy->AcquireSockAddr();
    fetch_address.remote_addrlen = sizeof(sockaddr);
    fetch_address.local_addr  = local_addr_;
    fetch_address.local_addrlen = local_addr_ ?sizeof(sockaddr):0;
    RawFetcherRequest request;
    request.conn = fetcher_->CreateConnection(
		scheme, AF_INET, SOCK_STREAM, 0, fetch_address);
    free(fetch_address.remote_addr);
    request.context = (void*)proxy;
    return request;
}

void ProxyScanner::GetScanProxyRequest(
    int n, std::vector<RawFetcherRequest>& req_vec)
{
    time_t cur_time = current_time_ms();
    if(scanner_counter_->IsBegin() && port_idx_ == 0)
    {
        if(scan_time_ + scan_interval_ > cur_time)
            return;
        LOG_INFO("####### Start scan from %s ########\n",
            scanner_counter_->offset_.ToString().c_str());
        scan_time_ = cur_time;
    }

    for(int i = 0 ; i < n; i++)
    {
        //进位
        if(++port_idx_ >= scan_port_.size())
        {
            port_idx_ = 0;
            ++(*scanner_counter_);
        }

        //检查是否结束
        if(scanner_counter_->IsEnd())
        {

            LOG_INFO("####### End scan from %s ########\n", 
                scanner_counter_->offset_.ToString().c_str());
            port_idx_ = 0;
            scanner_counter_->Reset();
            return;
        }

        uint16_t port = scan_port_[port_idx_];
        char ip_str[200];
        snprintf(ip_str, 200, "%s", scanner_counter_->offset_.ToString().c_str());
        Proxy * proxy = new Proxy(ip_str, port);
        proxy->state_ = Proxy::SCAN_HTTP;
        req_vec.push_back(CreateFetcherRequest(proxy));
    }
}

void ProxyScanner::FinishProxy(Proxy* proxy)
{
    if(proxy->err_num_ > error_retry_num_)
    {
        LOG_INFO("erase failed proxy: %s\n", proxy->ToString().c_str());
        proxy_set_->erase(*proxy);
        delete proxy;
        return;
    }
    proxy->state_ = Proxy::SCAN_IDLE;
    if(proxy->request_cnt_ == 1)
    {
        if(proxy_set_->find(*proxy))
        {
            delete proxy;
            return;
        }
        LOG_INFO("===== %s %u %u %u =====\n", proxy->ip_, 
            proxy->port_, proxy->http_enable_, proxy->https_enable_);
    }
    proxy_set_->update(*proxy);
    delete proxy;
}

void ProxyScanner::ProcessResult(const RawFetcherResult& fetch_result)
{
    HttpFetcherResponse *resp = (HttpFetcherResponse *)fetch_result.message;
    Proxy* proxy = (Proxy*)fetch_result.context;
    assert(proxy->state_ != Proxy::SCAN_IDLE);

#ifdef PROXY_DEBUG
    LOG_INFO("errno: %s %s %hu\n", strerror(fetch_result.err_num), 
        proxy->ip_, proxy->port_);
    if(resp)
    {
        resp->Body.push_back('\0');
        LOG_INFO("resp content_length: %zd\n%s\n", resp->Body.size() - 1, (const char*)&resp->Body[0]);
        resp->Body.pop_back();
    }
#endif

    if(fetch_result.err_num != 110)
    {
        //关闭连接时，产生的两次握手出包
        cur_tx_traffic_ += TCP_CLOSE_PACKET_SIZE;
        //不是errno110, 是因为对方发了个包过来了
        cur_rx_traffic_ += TCP_DATA_HEADER_SIZE;
    }
    if(fetch_result.err_num == 0 && resp)
    {
        //http数据入包
        cur_rx_traffic_ += resp->Body.size();
        char error_msg[100];
        if(resp->ContentEncoding(error_msg) != 0)
            LOG_INFO("%s ContentEncoding error: %s\n", proxy->ToString().c_str(), error_msg);
    }

    //用户打提示日志的
    if(rand() % 2000 == 0)
    {
        LOG_INFO("errno: %s %s %hu\n", strerror(fetch_result.err_num), 
            proxy->ip_, proxy->port_);
    }

    //** process http result **//
    switch(proxy->state_)
    {
        case(Proxy::SCAN_HTTP):
        {
            if(fetch_result.err_num == 0 && resp && resp->Body.size() == try_http_size_)
            {
                proxy->err_num_ = 0;
                proxy->http_enable_ = 1;
                proxy->state_ = Proxy::SCAN_CONNECT;
                req_queue_.push(CreateFetcherRequest(proxy));
                if(proxy->request_cnt_ > 1)
                    LOG_INFO("request HTTP success: %s.\n", proxy->ToString().c_str());
                break;
            }
            //first error.
            if(proxy->request_cnt_ == 1)
            {
                delete proxy;
                break;
            }
            ++(proxy->err_num_);
            LOG_INFO("request HTTP error: %s %u\n", proxy->ToString().c_str(), proxy->err_num_);
            FinishProxy(proxy);
            break;
        }
        case(Proxy::SCAN_CONNECT):
        {
            if(fetch_result.err_num == 0 && resp && resp->StatusCode == 200)
            {
                proxy->state_ = Proxy::SCAN_HTTPS;
                req_queue_.push(CreateFetcherRequest(proxy, fetch_result.conn));
                delete resp;
                LOG_INFO("request CONNECT success: %s\n", proxy->ToString().c_str());
                //not close connection, just return.
                return;
            }
            LOG_INFO("request CONNECT error: %s %u\n", proxy->ToString().c_str(), proxy->err_num_);
            // no need judy proxy --> end
            if(proxy->type_ != Proxy::TYPE_UNKNOWN || !proxy_judy_uri_)
            {
                FinishProxy(proxy);
                break; 
            }
            proxy->state_ = Proxy::SCAN_JUDGE;
            req_queue_.push(CreateFetcherRequest(proxy));
            break;
        }
        case(Proxy::SCAN_HTTPS):
        {
            if(fetch_result.err_num == 0 && resp && resp->Body.size() == try_https_size_)
            {
                proxy->https_enable_ = 1;
                LOG_INFO("request HTTPS success: %s:%hu\n", proxy->ip_, proxy->port_);
            }
            else
            {
                LOG_INFO("request HTTPS error: %d %s:%hu\n", fetch_result.err_num, 
                    proxy->ip_, proxy->port_);
            }
            // no need judy proxy --> end
            if(proxy->type_ != Proxy::TYPE_UNKNOWN || !proxy_judy_uri_)
            {
                FinishProxy(proxy);
                break; 
            }
            proxy->state_ = Proxy::SCAN_JUDGE;
            req_queue_.push(CreateFetcherRequest(proxy));
            break;
        }
        case(Proxy::SCAN_JUDGE):
        {
            // last --> end
            const char *pat_str = "HTTP_X_FORWARDED_FOR";
            if(fetch_result.err_num == 0 && resp && resp->StatusCode == 200)
            {
                resp->Body.push_back('\0');
                if(strstr(&(resp->Body[0]), pat_str))
                    proxy->type_ = Proxy::TRANSPORT;
                else
                    proxy->type_ = Proxy::HIGH_ANONYMOUS;
                LOG_INFO("request JUDGE success: %s %d\n", proxy->ToString().c_str(), proxy->type_);
            }
            else
                LOG_INFO("request JUDGE error: %s\n", proxy->ToString().c_str());
            FinishProxy(proxy);
            break;
        }
        default:
        {
            LOG_ERROR("invalid proxy state: %d\n", proxy->state_);
            assert(false);
        }
    }

    fetcher_->CloseConnection(fetch_result.conn);
    fetcher_->FreeConnection(fetch_result.conn);
    if(resp)
        delete resp;
}

void ProxyScanner::SetScanIntervalSeconds(time_t scan_interval_sec)
{
    scan_interval_ = scan_interval_sec * 1000; 
}

void ProxyScanner::SetErrorRetryNum(unsigned error_retry_num)
{
    error_retry_num_ = error_retry_num;
}

void ProxyScanner::SetValidateIntervalSeconds(time_t validate_interval_sec)
{
    validate_interval_ = validate_interval_sec * 1000; 
}

void ProxyScanner::RequestGenerator(
    int fetcher_quota, std::vector<RawFetcherRequest>& req_vec)
{
#ifdef PROXY_DEBUG
    static int seq_idx = 0;
    if(seq_idx  == 0)
    {
        Proxy * proxy = new Proxy();
        strcpy(proxy->ip_, "1.13.234.192");
        proxy->port_ = 80;
    
        //std::string req_url = "http://www.proxyjudge.net/";
        //assert(UriParse(req_url.c_str(), req_url.size(), *try_http_uri_) && HttpUriNormalize(*try_http_uri_));
        proxy->state_ = Proxy::SCAN_JUDGE;
        req_vec.push_back(CreateFetcherRequest(proxy));
    }
    ++seq_idx;
    while(!req_queue_.empty())
    {
        RawFetcherRequest req = req_queue_.front();
        req_queue_.pop();
        req_vec.push_back(req);
    }
    return; 
#endif

    static const int REQUEST_INTERVAL = 50;
    static const int tx_traffic_quota = max_tx_traffic_ == 0 ? INT_MAX : max_tx_traffic_ * REQUEST_INTERVAL / ((syn_retry_times_ + 1) * TCP_FIRST_PACKET_SIZE * 1000);
    static const int http_data_size   = (max_http_body_size_ + 200)*0.8 + TCP_DATA_HEADER_SIZE;
    static const int rx_traffic_quota = max_rx_traffic_ == 0 ? INT_MAX : std::max(max_rx_traffic_*REQUEST_INTERVAL / (1000*http_data_size), (size_t)1);

    time_t cur_time = current_time_ms();
    if(cur_time < last_tx_stat_time_ + REQUEST_INTERVAL)
        return;
    last_tx_stat_time_ = cur_time;

    //计算出配额
    int n = tx_traffic_quota;
    n -= cur_tx_traffic_ / TCP_FIRST_PACKET_SIZE;
    cur_tx_traffic_ = 0;
    if(n > fetcher_quota)
        n = fetcher_quota;

    //计算可以验证的代理数目，主要有此时的入带宽决定
    if(cur_rx_traffic_ < max_rx_traffic_)
    {
        if(fit_rx_begin_time_ == 0)
            fit_rx_begin_time_ = cur_time;
        else if(fit_rx_begin_time_ + conn_timeout_ <= cur_time)
        {
            if(each_validate_max_ < (unsigned)rx_traffic_quota)
                ++each_validate_max_;
            fit_rx_begin_time_ = cur_time;
        }
    }
    else if(cur_rx_traffic_ >= max_rx_traffic_ && each_validate_max_ > 0)
    {
        each_validate_max_ = 0;
        fit_rx_begin_time_ = 0;
    }
    if(cur_time >= last_rx_stat_time_ + 1000)
    {
        last_rx_stat_time_ = cur_time;
        cur_rx_traffic_ = 0;
    }
    int max_validate_num = each_validate_max_;
    //LOG_INFO("###### cur_rx_traffic_: %zd --> %d\n", 
    //    cur_rx_traffic_, max_validate_num);

    /// 1) 处理https的请求
    while(!req_queue_.empty() && n > 0 && max_validate_num > 0)
    {
        RawFetcherRequest req = req_queue_.front();
        req_queue_.pop();
        req_vec.push_back(req);
        --n;
        --max_validate_num;
    }

    /// 2) 处理验证的请求
    if(validate_time_ + validate_interval_ <= cur_time && n > 0)
    {
        if(validate_idx_ == 0)
            LOG_INFO("validate begin.\n");
        for(int i = 0; i < max_validate_num && n > 0; i++)
        {
            Proxy * proxy = new Proxy();
            // 验证结束
            if(!proxy_set_->get_next(validate_idx_, *proxy))
            {
                delete proxy;
                validate_time_ = cur_time;
                validate_idx_  = 0;
                LOG_INFO("validate end.\n");
                break;
            }
            --n;
            proxy->state_ = Proxy::SCAN_HTTP;
            req_vec.push_back(CreateFetcherRequest(proxy));
            LOG_INFO("put validate request: %s\n", proxy->ToString().c_str());
        }
    }
    /// 3) 处理扫描的请求
    if(n > 0)
        GetScanProxyRequest(n, req_vec);

    //LOG_INFO("put request: %zd\n", req_vec.size());
}

void ProxyScanner::Start()
{
    fetcher_->Begin(params_);
}

struct RequestData* ProxyScanner::CreateRequestData(void * contex)
{
    Proxy* proxy = (Proxy*)contex;
    HttpFetcherRequest* req = new HttpFetcherRequest();
    req->Clear();
    URI * uri = NULL;
    switch(proxy->state_)
    {
        case Proxy::SCAN_HTTP:
        {
            uri = try_http_uri_;
            break;
        }
        case Proxy::SCAN_CONNECT:
        {
            uri = try_https_uri_;
            break;
        }
        case Proxy::SCAN_HTTPS:
        {
            uri = try_https_uri_; 
            break;
        }
        case Proxy::SCAN_JUDGE:
        {
            uri = proxy_judy_uri_;
            break;
        }
        default:
        {
            assert(false);
        }
    }

    if(proxy->state_ == Proxy::SCAN_CONNECT)
    {
        req->Method = "CONNECT";
        std::string host_with_port = uri->Host();
        if(uri->HasPort())
            host_with_port += ":" + uri->Port();
        else
            host_with_port += ":443";
        req->Uri    = host_with_port;
        req->Headers.Add("Host", host_with_port);
    }
    else
    {
        req->Uri    = uri->ToString();
        req->Method = "GET";
        req->Version= "HTTP/1.1";
        req->Headers.Add("Host", uri->Host());
        req->Headers.Add("Accept", "*/*");
        req->Headers.Add("Accept-Language", "zh-cn");
        req->Headers.Add("Accept-Encoding", "gzip, deflate");
        req->Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 6.1)");
    }
    req->Close();
    //tcp第三次握手出包 + 发送请求的数据出包
    cur_tx_traffic_ += TCP_THIRD_PACKET_SIZE + req->Size() + TCP_DATA_HEADER_SIZE;
    //tcp第二次握手入包
    cur_rx_traffic_ += TCP_SECOND_PACKET_SIZE;
    
#ifdef PROXY_DEBUG
    req->Dump();
#endif

    return req;
}

void ProxyScanner::FreeRequestData(struct RequestData * request_data)
{
    delete (HttpFetcherRequest*)request_data;
}

IFetchMessage* ProxyScanner::CreateFetchResponse(const FetchAddress& address, void * contex)
{
    HttpFetcherResponse* resp = new HttpFetcherResponse(
        address.remote_addr, 
        address.remote_addrlen,
        address.local_addr,
        address.local_addrlen,
        max_http_body_size_, max_http_body_size_);
    return resp;
}

void ProxyScanner::FreeFetchMessage(IFetchMessage *message)
{
    delete message;
}

void ProxyScanner::Stop()
{
    stopped_ = true;
    fetcher_->End();
}
