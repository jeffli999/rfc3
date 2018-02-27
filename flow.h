#define	    MAXFLOWS	3000000
#define	    INITFLOWS	 100000

typedef struct flow_entry {
    unsigned int    sip, dip;
    unsigned char   proto;
    unsigned short  sp, dp;
    int		    match_rule;
} flow_entry_t;

void create_flows();
void write_flow_trace(char *trace_name);
void dump_flow_trace();
