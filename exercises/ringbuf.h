#ifndef FULL_H
#define FULL_H

struct event_to_match {
    unsigned int fd;
    unsigned long long ts;
};

struct rb_event {
    unsigned int fd;
    char io_type;
    unsigned long long duration;
};

struct rw_stats {
    unsigned int fd;

    // read stats
    unsigned int r_count;
    unsigned long long r_time;

    //write stats
    unsigned int w_count;
    unsigned long long w_time;
};

#endif
