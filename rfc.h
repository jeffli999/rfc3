#define MAXRULES	65536
#define MAXDIMENSIONS	5
#define MAXCHUNKS	7

struct range{
    unsigned low;
    unsigned high;
};

typedef struct pc_rule{
    struct range field[MAXDIMENSIONS];
} pc_rule_t;

typedef struct cbm_entry {
    int	id;
    int numrules;
    int *rulelist;
    int rulesum;
} cbm_t;

typedef struct eq_entry {
    int	eq_id;
} eq_t;

typedef struct cbm_stat {
    int	id;
    int	count;
} cbm_stat_t;
