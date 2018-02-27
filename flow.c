#include <stdio.h>
#include <stdlib.h>
#include "rfc.h"
#include "flow.h"


const int	field_max[FIELDS] = {0xFFFFFFFF, 0xFFFFFFFF, 0xFF, 0xFFFF, 0xFFFF};
const int	hash_tab_sizes[FIELDS] = {1999, 1999, 37, 359, 359};

extern pc_rule_t *ruleset;
extern int	numrules;

FILE		*ftrace;
unsigned int	epoints[FIELDS][MAXRULES*2];
int		num_epoints[FIELDS];
int		field_rules[FIELDS+1][MAXRULES];
int		num_field_rules[FIELDS+1];
unsigned int	**epoint_hash[FIELDS];
int		*hash_entry_size[FIELDS];
int		*hash_entry_num[FIELDS];
int		epoint_stack[FIELDS];
int		num_flows;  // current number of flows
int		size_flows; // current memory size for flows
flow_entry_t	*flows;

int		stack1[FIELDS], stack2[FIELDS];



void init_epoint_hash()
{
    int	    f, i;

    for (f = 0; f < FIELDS; f++) {
	epoint_hash[f] = (unsigned int **) malloc(hash_tab_sizes[f]*sizeof(unsigned int*));
	hash_entry_size[f] = (int *) malloc(hash_tab_sizes[f]*sizeof(int));
	hash_entry_num[f] = (int *) malloc(hash_tab_sizes[f]*sizeof(int));
	for (i = 0; i < hash_tab_sizes[f]; i++) {
	    hash_entry_size[f][i] = 4;
	    epoint_hash[f][i] = (unsigned int *) malloc(hash_entry_size[f][i]*sizeof(unsigned int));
	    hash_entry_num[f][i] = 0;
	}
    }
}


void reset_epoint_hash(int f)
{
    int	    i;

    for (i = 0; i < hash_tab_sizes[f]; i++)
	hash_entry_num[f][i] = 0;
}


// 1: hit a point in hash; 0: it's a new point, add it into hash
int lookup_epoint_hash(unsigned int point, int f)
{
    unsigned int    h, n, i;

    h = point % hash_tab_sizes[f];
    n = hash_entry_num[f][h];
    for (i = 0; i < n; i++) {
	if (epoint_hash[f][h][i] == point)
	    return 1;
    }
    // point not in hash table, add it in
    if (n == hash_entry_size[f][h]) {
	hash_entry_size[f][h] <<= 1;
	epoint_hash[f][h] = (int *) realloc(epoint_hash[f][h], hash_entry_size[f][h]*sizeof(unsigned int));
    }
    epoint_hash[f][h][n] = point;
    hash_entry_num[f][h]++;
    return 0;
}


int point_cmp(const void *p, const void *q)
{
    return *(int *)p - *(int *)q;
}


void dump_epoints(int field)
{
    int   *p = epoints[field], i;

    printf("Field[%d] end points: %d\n", field, num_epoints[field]);
    for (i = 0; i < num_epoints[field]; i++) {
	printf("%x:\n", p[i]);
    }
    printf("\n");
}


void sort_epoints(int field)
{
    unsigned int    *p;
    int		    i, j = 0, hit;

    qsort(p, num_epoints[field], sizeof(unsigned int), point_cmp);
    for (i = 0; i < num_epoints[field]; i++) {
	if (p[i] != p[j])
	    p[j++] = p[i];
    }
    num_epoints[field] = j;
}


void collect_all_rules(int field)
{
    int	    i;
    for (i = 0; i < numrules; i++)
	field_rules[field][i] = i;
    num_field_rules[field] = numrules;

}


// generate end points on field f for rules
void gen_field_epoints(int f, int *rules, int nrules)
{
    unsigned int    *p = epoints[f], point;
    int		    i, r, hit, n = 0;

    reset_epoint_hash(f);
    num_epoints[f] = 0;
    for (i = 0; i < nrules; i++) {
	r = rules[i];
	point = ruleset[r].field[f].low;
	hit = lookup_epoint_hash(point, f);
	if (!hit)
	    p[num_epoints[f]++] = point;
	if (ruleset[r].field[f].high != point) {
	    point = ruleset[r].field[f].high;
	    hit = lookup_epoint_hash(point, f);
	    if (!hit)
		p[num_epoints[f]++] = point;
	}
    }
}


void dump_field_epoints(int f)
{
    int	    i;
    for (i = 0; i < num_epoints[f]; i++)
	printf("epoint[%d]: %x\n", i, epoints[f][i]);
}


// collect a subset of field_rules[field] crossing an end point on field f
void collect_epoint_rules(int f, unsigned int point)
{
    int	    i, r, low, high;

    num_field_rules[f+1] = 0;
    for (i = 0; i < num_field_rules[f]; i++) {
	r = field_rules[f][i];
	low = ruleset[r].field[f].low;
	high = ruleset[r].field[f].high;
	if (low <= point && high >= point)
	    field_rules[f+1][num_field_rules[f+1]++] = r;
    }
}


// create a flow from: 
// 1) the subset of rules in the virtual field[FIELDS]
// 2) the stack of end points from field[0] ~ field[FIELDS-1]
int create_one_flow()
{
    int	    i;

    if (num_flows == size_flows) {
	size_flows += INITFLOWS;
	flows = (flow_entry_t *) realloc(flows, size_flows*sizeof(flow_entry_t));
    }
    flows[num_flows].sip = epoint_stack[0];
    flows[num_flows].dip = epoint_stack[1];
    flows[num_flows].proto = epoint_stack[2];
    flows[num_flows].sp = epoint_stack[3];
    flows[num_flows].dp = epoint_stack[4];
    if (num_field_rules[FIELDS] == 0)
	flows[num_flows].match_rule = -1;
    else
	flows[num_flows].match_rule = field_rules[FIELDS][0];
    if (num_field_rules[FIELDS] > 1) {
	fprintf(stderr, "Overlap: ");
	for (i = 0; i < num_field_rules[FIELDS]; i++)
	    fprintf(stderr, "%d ", field_rules[FIELDS][i]);
	fprintf(stderr, "\n");
    }

    if (++num_flows == MAXFLOWS)
	return 1;
    else
	return 0;
}


int process_field(int f)
{
    int		    finished, i;
    static int	    old_num_flows = 0;
    unsigned int    point;

    if (f == FIELDS) {
	finished = create_one_flow();
    } else {
	gen_field_epoints(f, field_rules[f], num_field_rules[f]);
	for (i = 0; i < num_epoints[f]; i++) {
	    point = epoints[f][i];
	    collect_epoint_rules(f, point);
	    epoint_stack[f] = point;
	    stack1[f] = num_epoints[f];
	    stack2[f] = i;
	    finished = process_field(f+1);
	    if (f == 0) {
		printf("f:%x : %d\n", epoint_stack[0], num_flows - old_num_flows);
		old_num_flows = num_flows;
	    }
	    if (finished)
		break;
	}
    }
    return finished;
}


void theory_flows()
{
    long	nflows = 1;
    int		f;

    //init_epoint_hash();

    for (f = 0; f < FIELDS; f++) {
	collect_all_rules(f);
	gen_field_epoints(f, field_rules[f], num_field_rules[f]);
	printf("%d * ", num_epoints[f]);
	nflows *= num_epoints[f];
    }
    printf("\ntheory: %ld\n", nflows);
}


// The process works as follows:
// 0. Pick the first field F[0], associate with F[0] the global ruleset (called R[0] in this context)
// 1. Projecting end points P[0] on F[0] for the associated ruleset R[0]
// 2. For each end point p in P[0], collect a subset of R[0] crossing p (called R[0]@p)
// 3. Pick the next field F[i] (i >= 1), associate with it the subset of rules R[i-1]@p collected in
//    the previous step
// 4. Projecting end points P[i] on field F[i] for the rule subset R[i-1]@p
// 5. For each end point p' in P[i], collect a subset of R[i-1]@p crossing p' (called R[i]@p')
// 6. If the last field F[n] has not been reached, go to Step 3; otherwise go to Step 7
// 7. With all fields been reached (under specific end points), we get the final subset of rules,
//    and the one with the highest priority will be the matched rule, which will be associated with
//    a test packet header generated with the n-tuple of end points picked in prevous steps
// 8: Iterate over the rest end points at each level (field) (Steps 0~7)
void create_flows()
{
    int		    f, i;
    unsigned int    point;

    size_flows = INITFLOWS;
    flows = (flow_entry_t *) malloc(size_flows*sizeof(flow_entry_t));

    init_epoint_hash();
    theory_flows();

    collect_all_rules(0);
    process_field(0);

    printf("#flows: %d\n", num_flows);

    dump_flow_trace();
}


void write_flow_trace(char *trace_name)
{
    FILE    *ftrace;
    int	    i;

    ftrace = fopen(trace_name, "w");
    if (ftrace == NULL) {
	fprintf(stderr, "Fail to create trace file: %s\n", trace_name);
	exit(1);
    }
    fwrite(&num_flows, sizeof(int), 1, ftrace);
    fwrite(flows, sizeof(flow_entry_t), num_flows, ftrace);
    fclose(ftrace);
}


char *ip_int2str(const unsigned int ip, char *str)
{
    unsigned char *val = (unsigned char *)&ip;

    sprintf(str, "%u.%u.%u.%u", val[3], val[2], val[1], val[0]);
    return str;
}


void dump_flow_trace()
{
    int	    i;
    char    ip_str[16];

    for (i = 0; i < num_flows; i++) {
	printf("%s ", ip_int2str(flows[i].sip, ip_str));
	printf("%s ", ip_int2str(flows[i].dip, ip_str));
	printf("%d ", flows[i].proto);
	printf("%d ", flows[i].sp);
	printf("%d ", flows[i].dp);
	printf(": rule[%d]\n", flows[i].match_rule);
    }
}
