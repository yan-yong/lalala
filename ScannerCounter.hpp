#ifndef __SCANNER_COUNTER_HPP
#define __SCANNER_COUNTER_HPP
#include <string.h>
#include <assert.h>
#include <string>
#include <algorithm>
#include <vector>

class IpTriple
{
public:
    static const int SEC_LEN = 4;
    int sec_[SEC_LEN];

private:
    int __comp_ip_triple(const int *triple1, const int *triple2) const
    {
        int ret = 0;
        for(int i = SEC_LEN - 1; i >= 0; i--)
        {
            if(triple1[i] > triple2[i])
            {
                ret = 1;
                break;
            }
            else if(triple1[i] < triple2[i])
            {
                ret = -1;
                break;
            }
        }
        return ret;
    }

    void __uniform()
    {
        for(int i = 0; i < SEC_LEN; i++)
        {
            if(sec_[i] < 0)
                sec_[i] = 0;
            else if(sec_[i] > 255)
                sec_[i] = 255; 
        }       
    }

public:
    IpTriple()
    {
        memset(sec_, 0, sizeof(sec_));
    }

    IpTriple(const int *ip_sec)
    {
        memcpy(sec_, ip_sec, sizeof(sec_));
        __uniform();
    }

    void SetValue(const int *ip_sec)
    {
        memcpy(sec_, ip_sec, sizeof(sec_));
        __uniform();
    }
 
    bool operator < (const IpTriple& other) const
    {
        return __comp_ip_triple(sec_, other.sec_) < 0;
    }

    bool operator <= (const IpTriple& other) const
    {
        return __comp_ip_triple(sec_, other.sec_) <= 0;
    }

    bool operator > (const IpTriple& other) const
    {
        return __comp_ip_triple(sec_, other.sec_) > 0;
    }

    bool operator >= (const IpTriple& other) const
    {
        return __comp_ip_triple(sec_, other.sec_) >= 0;
    }

    bool operator == (const IpTriple& other) const
    {
        return __comp_ip_triple(sec_, other.sec_) == 0;
    }

    void Add(size_t interval)
    {
        for(int i = SEC_LEN - 1; i >= 0; --i)
        {
            size_t interger_val = interval / (1 << i*8);
            sec_[i]            += interger_val;
            interval            = interval % (1 << i*8);
        }
        for(int i = 0; i < SEC_LEN - 1; i++)
        {
            sec_[i + 1] += sec_[i] / 256;
            sec_[i]      = sec_[i] % 256;
        }
    }

    size_t ToNum() const
    {
        size_t num = 0;
        for(int i = 0; i < SEC_LEN; i++)
        {
            num += ((size_t)sec_[i]) * (1 << 8*i);
        }
        return num;
    }

    void operator++()
    {
        ++sec_[0];
        for(int i = 0; i < SEC_LEN - 1; i++)
        {
            if(sec_[i] > 255)
            {
                sec_[i + 1] += sec_[i] / 256;
                sec_[i] = sec_[i] % 256;
            }
        }
        //跳过0.xxx.xxx.xxx
        if(sec_[3] == 0)
            sec_[3] = 1;
        //跳过内网地址
        if(sec_[3] == 10)
        {
            sec_[3] = 11;
            sec_[2] = 0;
            sec_[1] = 0;
            sec_[0] = 0;
        }
        if(sec_[3] == 172 && sec_[2] >= 16 && sec_[2] <= 31)
        {
            sec_[2] = 32;
            sec_[1] = 0;
            sec_[0] = 0;
        }
        if(sec_[3] == 192 && sec_[2] == 168)
        {
            sec_[2] = 169;
            sec_[1] = 0;
            sec_[0] = 0;
        }
    }

    std::string ToString() const
    {
        char buf[100];
        snprintf(buf, 100, "%d.%d.%d.%d", 
            sec_[3], sec_[2], sec_[1], sec_[0]);
        return buf;
    }
};

class Range
{
public:
    IpTriple low_;
    IpTriple high_;

public:
    Range()
    {

    }
    
    Range(int low[], int high[]):
        low_(low), high_(high)
    {
        assert(low_ <= high);
    }

    bool operator < (const Range& other) const
    {
        return low_ < other.low_;
    }

    size_t IpNum() const
    {
        if(low_ > high_)
            return 0;
        return high_.ToNum() - low_.ToNum() + 1;
    }

    bool Slice(size_t ip_num, Range& range)
    {
        if(IpNum() < ip_num || ip_num == 0)
            return false;
        range.low_  = low_;

        low_.Add(ip_num - 1);

        range.high_ = low_;
        ++low_;
        return true;
    }

    std::string ToString() const
    {
        std::string content = "[" + low_.ToString() + " - " + high_.ToString() + "]";
        return content;
    }
};

class ScannerCounter 
{
public:
    std::vector<Range> range_vec_;
    IpTriple offset_;
    unsigned offset_range_idx_;

private:
    void __format_offset(IpTriple& offset)
    {
        unsigned i = 0;
        for( ; i < range_vec_.size() && offset > range_vec_[i].high_; ++i);
        if(i >= range_vec_.size())
        {
            offset = range_vec_[0].low_;
            offset_range_idx_ = 0;
            return;
        }

        offset_range_idx_ = i;
        if(offset < range_vec_[i].low_)
            offset = range_vec_[i].low_;
    }

public:
    void AddRange(const Range& range)
    {
        range_vec_.push_back(range);
    }

    void LoadFromFile(const char* ip_file)
    {
        FILE * fid = fopen(ip_file, "r");
        assert(fid);
        char buf[1024];
        while(fgets(buf, 1024, fid))
        {
            int low[4] = {0};
            int high[4]= {0};
            if(sscanf(buf, "%d.%d.%d.%d %d.%d.%d.%d", 
                        low + 3, low + 2, low + 1, low,
                        high+ 3, high + 2, high + 1, high) != 8)
            {
                fprintf(stderr, "skip %s", buf);
                continue;
            }
            Range range(low, high);
            AddRange(range);
        }
        fclose(fid);
        Initialize();
    }

    void Initialize()
    {
        assert(range_vec_.size());
        std::sort(range_vec_.begin(), range_vec_.end());
        __format_offset(offset_);
    }

    void SetOffset(IpTriple offset)
    {
        __format_offset(offset);
        offset_ = offset;
    }

    void GetOffset(IpTriple& offset) const
    {
        offset = offset_;
    }
    std::vector<ScannerCounter> Split(unsigned n)
    {
        assert(n > 0);
        std::vector<ScannerCounter> sc_vec;
        if(n == 1)
        {
            std::vector<ScannerCounter> sc_vec;
            sc_vec.push_back(*this);
            return sc_vec;
        }

        size_t ip_sum = 0;
        for(unsigned i = 0; i < range_vec_.size(); i++)
            ip_sum += range_vec_[i].IpNum();
        assert(ip_sum > n);
        size_t each_ip_num = ip_sum / n;

        ScannerCounter cur_sc;
        size_t cur_ip_sum = 0;
        for(unsigned i = 0; i < range_vec_.size(); )
        {
            size_t ip_num = range_vec_[i].IpNum();
            if(ip_num == 0)
            {
                ++i;
                continue;
            }
            if(sc_vec.size() == n-1 || cur_ip_sum + ip_num < each_ip_num)
            {
                cur_sc.AddRange(range_vec_[i]); 
                cur_ip_sum += ip_num;
                ++i;
                continue;
            }
            Range range;
            assert(range_vec_[i].Slice(each_ip_num - cur_ip_sum, range));
            cur_sc.AddRange(range);
            cur_sc.Initialize();
            sc_vec.push_back(cur_sc);
            cur_ip_sum = 0;
            cur_sc = ScannerCounter();
        }
        cur_sc.Initialize();
        sc_vec.push_back(cur_sc);
        return sc_vec;
    }
    void operator++()
    {
        ++offset_;
        if(offset_ > range_vec_[offset_range_idx_].high_ && 
            offset_range_idx_ < range_vec_.size() - 1)
        {
            ++offset_range_idx_;
            offset_ = range_vec_[offset_range_idx_].low_;
        }
    }
    bool IsEnd() const
    {
        return offset_range_idx_ == range_vec_.size() - 1 && 
            offset_ > range_vec_[offset_range_idx_].high_;
    }
    bool IsBegin() const
    {
        return offset_range_idx_ == 0 && offset_ == range_vec_[0].low_;
    }
    void Reset() 
    {
        offset_range_idx_ = 0;
        offset_ = range_vec_[0].low_;
    }

    std::string ToString() const
    {
        std::string content;
        size_t num = 0;
        for(unsigned i = 0; i < range_vec_.size(); ++i)
        {
            content += range_vec_[i].ToString() + "\n";
            num     += range_vec_[i].IpNum();
        }
        //char buf[20];
        //snprintf(buf, 20, "sum: %d\n", num);
        return content;
    }
};
#endif
