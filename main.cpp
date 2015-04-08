#include <stdio.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include "log/log.h"
#include "ProxyScanner.hpp"
#include <sys/types.h>
#include <sys/wait.h>
#include "Config.hpp"
#include "httpserver/httpserver.h"
#include "lock/lock.hpp"

/* 保存进程运行信息 */
struct ProcessInfo
{
    int pid_;
    unsigned low_range_[4];
    unsigned high_range_[4];
    unsigned offset_[4];
};

/* 全局变量 */
static const int MAX_PROCESS_CNT = 256;
static bool g_stop = false;
static unsigned g_proc_num = 0;
static Config*  g_cfg = NULL;
static ProcessInfo* g_proc_info = NULL;
static ProxySet *   g_proxy_set = NULL;
static ShareMem *   g_shm       = NULL;   

/* 提供http接口服务 */
class ProxyService: public HttpServer
{
    virtual void handle_recv_request(boost::shared_ptr<http::server4::request> http_req, 
            boost::shared_ptr<HttpSession> session)
    {  
        Json::Value json_lst;
        ProxySet::HashKey idx = 0;
        Proxy* proxy = new Proxy(); 
        while(g_proxy_set->get_next(idx, *proxy))
        {
            Json::Value cur_json = proxy->ToJson();
            json_lst.append(cur_json);
        }
        delete proxy;
        std::string response_content = json_lst.toStyledString();
        session->m_reply->status = http::server4::reply::ok;
        session->m_reply->content= response_content;
        session->send_response();
    }
};

static void SetupSignalHandler(bool is_worker);

static void WorkerRuntine(ProcessInfo* proc_info)
{
    for(int i = 3; i < sysconf(_SC_OPEN_MAX); i++)
        close(i);
    SetupSignalHandler(true);
    Fetcher::Params fetch_params;
    memset(&fetch_params, 0, sizeof(fetch_params));
    fetch_params.conn_timeout.tv_sec = g_cfg->connect_timeout_sec_;
    fetch_params.max_connecting_cnt  = g_cfg->max_connect_count_;
    fetch_params.socket_rcvbuf_size  = 8096;
    fetch_params.socket_sndbuf_size  = 8096;
    ProxyScanner proxy_scanner(g_proxy_set, fetch_params);
    proxy_scanner.SetScanOffset(proc_info->offset_);
    proxy_scanner.SetScanRange(proc_info->low_range_, proc_info->high_range_);
    proxy_scanner.SetScanIntervalSeconds(g_cfg->scan_interval_sec_);
    proxy_scanner.SetValidateIntervalSeconds(g_cfg->validate_interval_sec_);
    proxy_scanner.SetErrorRetryNum(g_cfg->proxy_error_retry_num_);
    proxy_scanner.SetScanPort(g_cfg->port_vec_);
    proxy_scanner.SetHttpTryUrl(g_cfg->try_http_url_, g_cfg->try_http_size_);
    proxy_scanner.SetHttpsTryUrl(g_cfg->try_https_url_, g_cfg->try_https_size_);
    proxy_scanner.SetProxyJudyUrl(g_cfg->proxy_judy_url_);
    proxy_scanner.SetMaxTxSpeed(g_cfg->tx_max_speed_bytes_);
    proxy_scanner.SetSynRetryTimes(g_cfg->syn_retries_);
    proxy_scanner.Start();

    char proc_id_str[100];
    snprintf(proc_id_str, 100, "%d (%d.%d.%d.%d - %d.%d.%d.%d)", getpid(),
        proc_info->low_range_[0], proc_info->low_range_[1], proc_info->low_range_[2], proc_info->low_range_[3],
        proc_info->high_range_[0],proc_info->high_range_[1],proc_info->high_range_[2],proc_info->high_range_[3]);
    LOG_INFO("Worker process %s start.\n", proc_id_str);

    time_t last_dump_time = current_time_ms();
    while(!g_stop)
    {
        sleep(1);
        time_t cur_time = current_time_ms();
        //第一个进程进行同步
        if(proc_info == g_proc_info && 
            cur_time - last_dump_time > g_cfg->dump_interval_seconds_ * 1000)
        {
            
            last_dump_time = cur_time;
            //记录offset
            proxy_scanner.GetScanOffset(proc_info->offset_);
            if(g_shm->sync() < 0)
                LOG_ERROR("Share memory sync failed.\n");
            else
                LOG_INFO("Share memory sync success.\n");
        }
    }

    proxy_scanner.GetScanOffset(proc_info->offset_);
    LOG_INFO("Worker process %s stopping ...\n", proc_id_str);
    proxy_scanner.Stop();
    LOG_INFO("Worker process %s end.\n", proc_id_str);
    delete g_cfg;
    g_cfg = NULL;
    exit(0);
}

static void SpawnWorkerProcess()
{
    unsigned worker_process_count = g_cfg->worker_process_count_;
    unsigned* low_range = g_cfg->scan_low_range_;
    unsigned* high_range= g_cfg->scan_high_range_;
    assert(worker_process_count < (unsigned)MAX_PROCESS_CNT);
    int range_interval = (high_range[0] - low_range[0]) / worker_process_count;
    if(range_interval == 0)
        range_interval = 1;
    //check process num 
    for(unsigned i = 0; g_proc_num < worker_process_count && i < worker_process_count; i++)
    {
        if(g_proc_info[i].pid_)
            continue;
        if(g_proc_info[i].low_range_[0] == 0)
        {
            g_proc_info[i].low_range_[0]  = low_range[0] + i * range_interval;
            if(i != 0)
                g_proc_info[i].low_range_[0] += 1;
            g_proc_info[i].high_range_[0] = low_range[0] + (i+1)*range_interval;
            if(g_proc_info[i].low_range_[0] > 255)
                g_proc_info[i].low_range_[0] = 255;
            if(g_proc_info[i].high_range_[0] > 255)
                g_proc_info[i].high_range_[0] = 255;
            if(g_proc_info[i].low_range_[0] > g_proc_info[i].high_range_[0] ||
                    low_range[1] + low_range[2] + low_range[3] >=
                    high_range[1]+ high_range[2]+ high_range[3] )
            {
                g_proc_info[i].low_range_[0] = 0;
                g_proc_info[i].high_range_[0]= 0;
                break;
            }
            memcpy(g_proc_info[i].low_range_ + 1, low_range + 1, 3*sizeof(*low_range));
            memcpy(g_proc_info[i].high_range_+ 1, high_range+ 1, 3*sizeof(*high_range));
        }
        pid_t child_pid = fork();
        if(child_pid == 0)
            WorkerRuntine(g_proc_info + i);
        g_proc_info[i].pid_ = child_pid;
        ++g_proc_num;
    }
}

static void SigChildHandler(int sig)
{
    while(1) 
    {
        pid_t pid = 0;
        /* seems to be the bug of glibc */
        errno = 0;
        if((pid = waitpid(-1, NULL, WNOHANG)) <= 0) 
        {
            if(errno == EINTR)
                continue;
            return;
        }
        for(unsigned i = 0; i < g_proc_num && g_proc_info[i].pid_; i++) 
        {
            if(pid == g_proc_info[i].pid_) 
            {
                LOG_INFO("Found process %d (%d.%d.%d.%d - %d.%d.%d.%d) quited.\n", pid, 
                    g_proc_info[i].low_range_[0], g_proc_info[i].low_range_[1], 
                    g_proc_info[i].low_range_[2], g_proc_info[i].low_range_[3], 
                    g_proc_info[i].high_range_[0], g_proc_info[i].high_range_[1], 
                    g_proc_info[i].high_range_[2], g_proc_info[i].high_range_[3]);

                g_proc_info[i].pid_ = 0;
                std::swap(g_proc_info[i], g_proc_info[g_proc_num - 1]);
                --g_proc_num;
            }
        }
        if(!g_stop)
            SpawnWorkerProcess();
        return;
    }
}

static void SigQuitHandler(int sig)
{
    g_stop = true;
}

static void SetupSignalHandler(bool is_worker)
{
    signal(SIGPIPE, SIG_IGN);
    // worker
    if(is_worker)
    {
        struct sigaction quit_act, oact;
        sigemptyset(&quit_act.sa_mask);
        quit_act.sa_flags = 0;
        quit_act.sa_handler = SigQuitHandler;
        //sigaddset(&quit_act.sa_mask, SIGINT);
        //sigaddset(&quit_act.sa_mask, SIGTERM);
        sigaddset(&quit_act.sa_mask, SIGUSR1);
        signal(SIGTERM, SIG_IGN);
        signal(SIGINT, SIG_IGN);
        if(sigaction(SIGUSR1, &quit_act, &oact) < 0)
        {
            LOG_ERROR("child sigaction SIGUSR1 error.\n");
            return;
        }
    }

    struct sigaction worker_quit_act, oact;
    worker_quit_act.sa_handler = SigChildHandler;
    sigemptyset(&worker_quit_act.sa_mask);
    worker_quit_act.sa_flags = 0;
    //sigaddset(&worker_quit_act.sa_mask, SIGCHLD);
    if(sigaction(SIGCHLD, &worker_quit_act, &oact) < 0)
    {
        LOG_ERROR("parent sigaction SIGCHLD error.\n");
        return;
    }
}

int main(int argc, char* argv[])
{
    /* handle config */
    std::string config_file = "config.xml";
    if(argc == 1)
        LOG_INFO("Use default config file %s\n", config_file.c_str());
    else
        config_file = argv[1];
    g_cfg = new Config(config_file.c_str());
    g_cfg->ReadConfig();

    /* initialize */
    // set tcp syn retry times. notice: will CHANGE system config!!!
    FILE* syn_fid = fopen("/proc/sys/net/ipv4/tcp_syn_retries", "w");
    assert(syn_fid);
    fprintf(syn_fid, "%u", g_cfg->syn_retries_);
    fclose(syn_fid);
    //initialize share memeory
    g_shm = new ShareMem(g_cfg->shm_key_, g_cfg->shm_size_, g_cfg->dump_file_name_);
    g_proxy_set = new ProxySet(*g_shm, g_cfg->max_proxy_num_);
    g_proc_info = g_shm->New<ProcessInfo>(MAX_PROCESS_CNT);
    for(int i = 0; i < MAX_PROCESS_CNT; i++)
        g_proc_info[i].pid_ = 0; 

    /* spwan worker processes */
    LOG_INFO("Master process starting ...\n");
    SpawnWorkerProcess();
    SetupSignalHandler(false);

    /* set up httpserver */
    boost::shared_ptr<ProxyService> httpserver(new ProxyService());
    httpserver->initialize(g_cfg->bind_ip_, g_cfg->listen_port_);
    httpserver->run();

    /* handle stop */
    LOG_INFO("Master process stopping ...\n");
    g_stop = true;
    //kill child process
    for(int i = 0; i < MAX_PROCESS_CNT; ++i)
    {
        if(g_proc_info[i].pid_ == 0)
            continue;
        if(kill(g_proc_info[i].pid_, SIGUSR1) < 0)
            LOG_ERROR("kill %d error: %s\n", g_proc_info[i].pid_, strerror(errno));
        LOG_INFO("Master process killing worker process %d ...\n", g_proc_info[i].pid_);
    } 
    for(unsigned i = 0; i < g_proc_num; i++)
    {
        if(g_proc_info[i].pid_)
        {
            int status = 0;
            waitpid(g_proc_info[i].pid_, &status, 0);
        }
    }
    g_shm->sync();
    delete g_proxy_set;
    delete g_shm;

    return 0;
}
