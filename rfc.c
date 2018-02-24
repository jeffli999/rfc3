/***************************************
   chunk_id  chunk_size  header-field
       0         16       s.ip[15:0]
       1         16       s.ip[31:16]
       2         16       d.ip[15:0]
       3         16       d.ip[31:16]
       4         8        proto
       5         16       s.port
       6         16       d.port   
****************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include "rfc.h"

int  phase = 4;  // number of pahses
FILE *fpr;       // ruleset file
FILE *fpt;       // test trace file

int	numrules=0;  // actual number of rules in rule set
struct pc_rule *rules; 

int	epoints[MAXCHUNKS][MAXRULES*2+2];
int	num_epoints[MAXCHUNKS];

int	p0_table[7][65536];	//phase 0 chunk tables
int	*p1_table[4];		//phase 1 chunk tables
int	*p2_table[2];  		//phase 2 chunk tables
int	*p3_table;     		//phase 3 chunk tables
int	p1_table_size[4];	//size of the phase 1 tables
int	p2_table_size[2];	//size of the phase 2 tables
int	p3_table_size;		//size of the phase 3 tables


cbm_t	*p0_cbm[7];		//phase 0 chunk equivalence class
cbm_t	*p1_cbm[4];		//phase 1 chunk equivalence class
cbm_t	*p2_cbm[2];		//phase 2 chunk equivalence class
cbm_t	*p3_cbm;		//phase 3 chunk equivalence class
int	p0_cbm_num[7];		//phase 0 number of chunk equivalence classes
int	p1_cbm_num[4];          //phase 1 number of chunk equivalence classes
int	p2_cbm_num[2];          //phase 2 number of chunk equivalence classes
int	p3_cbm_num;		//phase 3 number of chunk equivalence classes

int	rulelist_len_count[64];

// cbm_lookup() works slow when there is a large number of CBMs,
// To speed up, we can limit its search to CBMs with the same rulesum
// A hash table hashing on CBM's rulesum is introduced for this purpose
//#define HASH_TAB_SIZE   9209
#define HASH_TAB_SIZE   29123
int     *cbm_hash[HASH_TAB_SIZE];
int     cbm_hash_size[HASH_TAB_SIZE];   
int     cbm_hash_num[HASH_TAB_SIZE];    

long	hash_stats[10000];
long	intersect_stats[MAXRULES*2];


void dump_intersect_stats()
{
    int	    i;
    long    total = 0;

    for (i = 0; i < MAXRULES*2; i++) {
	if (intersect_stats[i] > 0) {
	    printf("intersect[%5d]: %7ld / %9ld\n", i, intersect_stats[i], intersect_stats[i]*i);
	    total += intersect_stats[i]*i;
	}
    }
    printf("Total intersect comparisons: %ld\n", total);
}


void dump_hash_stats()
{
    int	    i;
    long    total = 0;

    printf("Statistics on cbm hash lookups\n================================\n");
    for (i = 0; i < 10000; i++) {
	if (hash_stats[i] > 0) {
	    total += hash_stats[i] * i;
	    printf("cbm_lookup[%4d]: %7ld / %8ld\n", i, hash_stats[i], hash_stats[i]*i);
	}
    }
    printf("Total cbm hash lookups: %ld\n", total);
}


void init_cbm_hash()
{
    int	i;

    for (i = 0; i < HASH_TAB_SIZE; i++) {
        cbm_hash[i] = (int *) malloc(2*sizeof(int));
        cbm_hash_size[i] = 2;
        cbm_hash_num[i] = 0;
    }
}


void free_cbm_hash()
{
    int i;

    for (i = 0; i < HASH_TAB_SIZE; i++)
        free(cbm_hash[i]);
}


int do_cbm_stats(int *table, int n, cbm_t *cbm_set, int cbm_num, int flag);


int dump_rulelist_len_count()
{
    int	    i;

    printf("======================\n");
    for (i = 0; i < 64; i++)
	printf("rulelist[%d]: %d\n", i,  rulelist_len_count[i]);
}


void parseargs(int argc, char *argv[]) 
{
    int	c;
    int ok = 1;

    while ((c = getopt(argc, argv, "p:r:t:h")) != -1) {
	switch (c) {
	    case 'p':
		phase = atoi(optarg);
		break;
	    case 'r':
		fpr = fopen(optarg, "r");
		break;
	    case 't':
		fpt = fopen(optarg, "r");
		break;
	    case 'h':
		printf("rfc [-p phase][-r ruleset][-t trace][-h]\n");
		exit(1);
		break;
	    default:
		ok = 0;
	}
    }

    if(phase < 3 || phase > 4) {
	printf("number of phases should be either 3 or 4\n");
	ok = 0;
    }	
    if(fpr == NULL) {
	printf("can't open ruleset file\n");
	ok = 0;
    }
    if (!ok || optind < argc) {
	fprintf (stderr, "rfc [-p phase][-r ruleset][-t trace][-h]\n");
	exit(1);
    }
}


int loadrule(FILE *fp, pc_rule_t *rule){

    int tmp;
    unsigned sip1, sip2, sip3, sip4, siplen;
    unsigned dip1, dip2, dip3, dip4, diplen;
    unsigned proto, protomask;
    int i = 0;

    while(1) {
	if(fscanf(fp,"@%d.%d.%d.%d/%d %d.%d.%d.%d/%d %d : %d %d : %d %x/%x\n", 
		    &sip1, &sip2, &sip3, &sip4, &siplen, &dip1, &dip2, &dip3, &dip4, &diplen, 
		    &rules[i].field[3].low, &rules[i].field[3].high, &rules[i].field[4].low, &rules[i].field[4].high,
		    &proto, &protomask) != 16) break;
	if(siplen == 0) {
	    rules[i].field[0].low = 0;
	    rules[i].field[0].high = 0xFFFFFFFF;
	} else if(siplen > 0 && siplen <= 8) {
	    tmp = sip1<<24;
	    rules[i].field[0].low = tmp;
	    rules[i].field[0].high = rules[i].field[0].low + (1<<(32-siplen)) - 1;
	}else if(siplen > 8 && siplen <= 16) {
	    tmp = sip1<<24; tmp += sip2<<16;
	    rules[i].field[0].low = tmp; 	
	    rules[i].field[0].high = rules[i].field[0].low + (1<<(32-siplen)) - 1;	
	}else if(siplen > 16 && siplen <= 24) {
	    tmp = sip1<<24; tmp += sip2<<16; tmp +=sip3<<8; 
	    rules[i].field[0].low = tmp; 	
	    rules[i].field[0].high = rules[i].field[0].low + (1<<(32-siplen)) - 1;			
	}else if(siplen > 24 && siplen <= 32) {
	    tmp = sip1<<24; tmp += sip2<<16; tmp += sip3<<8; tmp += sip4;
	    rules[i].field[0].low = tmp; 
	    rules[i].field[0].high = rules[i].field[0].low + (1<<(32-siplen)) - 1;	
	}else {
	    printf("Src IP length exceeds 32\n");
	    return 0;
	}

	if(diplen == 0) {
	    rules[i].field[1].low = 0;
	    rules[i].field[1].high = 0xFFFFFFFF;
	}else if(diplen > 0 && diplen <= 8) {
	    tmp = dip1<<24;
	    rules[i].field[1].low = tmp;
	    rules[i].field[1].high = rules[i].field[1].low + (1<<(32-diplen)) - 1;
	}else if(diplen > 8 && diplen <= 16) {
	    tmp = dip1<<24; tmp +=dip2<<16;
	    rules[i].field[1].low = tmp; 	
	    rules[i].field[1].high = rules[i].field[1].low + (1<<(32-diplen)) - 1;	
	}else if(diplen > 16 && diplen <= 24) {
	    tmp = dip1<<24; tmp +=dip2<<16; tmp+=dip3<<8;
	    rules[i].field[1].low = tmp; 	
	    rules[i].field[1].high = rules[i].field[1].low + (1<<(32-diplen)) - 1;			
	}else if(diplen > 24 && diplen <= 32) {
	    tmp = dip1<<24; tmp +=dip2<<16; tmp+=dip3<<8; tmp +=dip4;
	    rules[i].field[1].low = tmp; 	
	    rules[i].field[1].high = rules[i].field[1].low + (1<<(32-diplen)) - 1;	
	}else {
	    printf("Dest IP length exceeds 32\n");
	    return 0;
	}

	if(protomask == 0xFF) {
	    rules[i].field[2].low = proto;
	    rules[i].field[2].high = proto;
	} else if(protomask == 0) {
	    rules[i].field[2].low = 0;
	    rules[i].field[2].high = 0xFF;
	} else {
	    printf("Protocol mask error\n");
	    return 0;
	}
	i++;
    }

  return i;
}


static int point_cmp(const void *p, const void *q)
{
    return *(int *)p - *(int *)q;
}


int dump_endpoints()
{
    int	    chunk, i;

    for (chunk = 0; chunk < MAXCHUNKS; chunk++) {
	printf("\nend_points[%d]: %d\n", chunk, num_epoints[chunk]);
	for (i = 0; i < num_epoints[chunk]; i++)
	    printf("%x  ", epoints[chunk][i]);
    }
    printf("\n\n");

}


int sort_endpoints()
{
    int	    chunk, i;

    for (chunk = 0; chunk < MAXCHUNKS; chunk++) {
	qsort(epoints[chunk], numrules*2+2, sizeof(int), point_cmp);
	// remove redundant end points for multiple rules having the same end points
	for (i = 0, num_epoints[chunk] = 1; i < numrules*2+2; i++) {
	    if (epoints[chunk][i] != epoints[chunk][num_epoints[chunk]-1])
		epoints[chunk][num_epoints[chunk]++] = epoints[chunk][i];
	}
    }
}


const int chunk_to_field[MAXCHUNKS] = {0, 0, 1, 1, 2, 3, 4};
const int shamt[MAXCHUNKS] = {0, 16, 0, 16, 0, 0, 0};

int gen_endpoints()
{
    int	    i, f, k, chunk;
    
    for (chunk = 0; chunk < MAXCHUNKS; chunk++)
	epoints[0][0] = 0;

    for (chunk = 0; chunk < MAXCHUNKS; chunk++) {
	f = chunk_to_field[chunk];
	k = shamt[chunk];
	for (i = 0; i < numrules; i++) {
	    epoints[chunk][2*i+1] = (rules[i].field[f].low >> k) & 0xFFFF;
	    epoints[chunk][2*i+2] = (rules[i].field[f].high >> k) & 0xFFFF;
	}
	epoints[chunk][2*i+1] = 65535;
    }

    sort_endpoints();
}


int compare_rules(int *rules1, int *rules2, int n)
{
    int	    i;

    for (i = 0; i < n; i++) {
	if (rules1[i] != rules2[i])
	    return 0;
    }
    return  1;
}


int cbm_lookup(int *cbm_rules, int num_cbm_rules, int rulesum, cbm_t *cbm_set)
{
    int	    h, i, n, id, match = 0;

    h = rulesum % HASH_TAB_SIZE;
    for (i = 0; i < cbm_hash_num[h]; i++) {
	id = cbm_hash[h][i];
	if (cbm_set[id].numrules != num_cbm_rules)
	    continue;
	if (memcmp(cbm_rules, cbm_set[id].rulelist, num_cbm_rules*sizeof(int)) == 0) {
	    hash_stats[i+1]++;
	    return id;
	}
    }
    hash_stats[i]++;
    return -1;
}


// print the phase table with run length of eqid in the table >= thresh_rl
void dump_phase_table(int *table, int len, int thresh_rlen)
{
    int	    i, eqid, eqid1, run_len;

    eqid = table[0];
    run_len = 0;
    for (i = 0; i < len; i++) {
	eqid1 = table[i];
	if (eqid1 == eqid) {
	    run_len++;
	} else {
	    if (run_len >= thresh_rlen)
		printf("table[%d]: %d#%d\n", i, eqid, run_len);
	    eqid = eqid1;
	    run_len = 1;
	}
    }
    if (run_len >= thresh_rlen)
	printf("table[%d]: %d#%d\n", len, eqid, run_len);
}


void add_to_hash(cbm_t *cbm)
{
    int	    h;

    h = cbm->rulesum % HASH_TAB_SIZE;
    cbm_hash[h][cbm_hash_num[h]] = cbm->id;
    if (++cbm_hash_num[h] == cbm_hash_size[h]) {
	cbm_hash_size[h] <<= 1;
	cbm_hash[h] = (int *) realloc(cbm_hash[h], cbm_hash_size[h]*sizeof(int));
    }
}


int gen_p0_cbm(int chunk)
{
    int		cbm_rules[MAXRULES], num_cbm_rules, rulesum;
    int		i, j, f, k, r, len, low, high, point, next_point, cbm_id, num_cbm = 0, cbm_set_size = 64;

    f = chunk_to_field[chunk];
    k = shamt[chunk];
    p0_cbm[chunk] = (cbm_t *) malloc(cbm_set_size * sizeof(cbm_t));
    init_cbm_hash();

    for (i = 0; i < num_epoints[chunk]; i++) {
	// 1. generate a cbm
	point = epoints[chunk][i];
	num_cbm_rules = 0;
	rulesum = 0;
	for (r = 0; r < numrules; r++) {
	    low = rules[r].field[f].low >> k & 0xFFFF;
	    high = rules[r].field[f].high >> k & 0xFFFF;
	    if (low <= point && high >= point) {
		cbm_rules[num_cbm_rules++] = r;
		rulesum += r;
	    }
	}

	// 2. check whether the generated cbm exists
	cbm_id = cbm_lookup(cbm_rules, num_cbm_rules, rulesum, p0_cbm[chunk]);
	if (cbm_id <  0) {
	    // 3. this is a new cbm, add it to the cbm_set
	    cbm_id = num_cbm;
	    p0_cbm[chunk][cbm_id].id = cbm_id;
	    p0_cbm[chunk][cbm_id].numrules = num_cbm_rules;
	    p0_cbm[chunk][cbm_id].rulelist = (int *) malloc(num_cbm_rules * sizeof(int));
	    p0_cbm[chunk][cbm_id].rulesum = rulesum;
	    memcpy(p0_cbm[chunk][cbm_id].rulelist, cbm_rules, num_cbm_rules * sizeof(int));
	    if (++num_cbm == cbm_set_size) {
		cbm_set_size += 64;
		p0_cbm[chunk] = realloc(p0_cbm[chunk], cbm_set_size*sizeof(cbm_t));
	    }

	    // record rulelists in different lengths, s.t. to speed up cbm_lookup()
	    add_to_hash(&p0_cbm[chunk][cbm_id]);
	    len = num_cbm_rules > 63 ? 63 : num_cbm_rules;
	    rulelist_len_count[len]++;
	}

	// 4. fill the corresponding p0 chunk table with the eqid (cbm_id)
	next_point = (i == num_epoints[chunk] - 1) ? 65536 : epoints[chunk][i+1];
	for (j = point; j < next_point; j++)
	    p0_table[chunk][j] = cbm_id;
    }
    free_cbm_hash();
    printf("chunk[%d] has %d cbm\n", chunk, num_cbm);
    //dump_phase_table(p0_table[chunk], 65536);
    return num_cbm;
}


int gen_p0_tables()
{
    int		chunk;

    for (chunk = 0; chunk < MAXCHUNKS; chunk++) {
	p0_cbm_num[chunk] = gen_p0_cbm(chunk);
	do_cbm_stats(p0_table[chunk], 65536, p0_cbm[chunk], p0_cbm_num[chunk], 0);
    }
    dump_intersect_stats();
    bzero(intersect_stats, MAXRULES*2*sizeof(int));
}


int cbm_2intersect(cbm_t *c1, cbm_t *c2, int *cbm_rules, int *rulesum)
{
    int	    i = 0, j = 0, n = 0, ncmp = 0;

    *rulesum = 0;
    while (i < c1->numrules && j < c2->numrules) {
	if (c1->rulelist[i] == c2->rulelist[j]) {
	    cbm_rules[n++] = c1->rulelist[i];
	    *rulesum += c1->rulelist[i];
	    i++; j++;
	} else if (c1->rulelist[i] > c2->rulelist[j]) {
	    j++;
	} else {
	    i++;
	}
	ncmp++;
    }
    intersect_stats[ncmp]++;
    return n;
}


cbm_t* crossprod_2chunk(cbm_t *cbm_set1, int n1, cbm_t *cbm_set2, int n2, int *num_cpd, int *cpd_tab)
{
    int	    i, j, len, cbm_id, n = 0, cpd_set_size = MAXRULES;
    int	    cbm_rules[MAXRULES], num_cbm_rules, rulesum;
    cbm_t   *cpd_set;
    
    cpd_set = (cbm_t *) malloc(cpd_set_size*sizeof(cbm_t));
    init_cbm_hash();

    for (i = 0; i < n1; i++) {

	if ((i & 0xFFF) == 0) {
	    // to show the progress for a long crossproducting process
	    fprintf(stderr, "crossprod_2chunk: %6d/%6d\n", i, n1);
	}

	for (j =  0; j < n2; j++) {
	    // 1. generate the intersect of two cbms from two chunks
	    num_cbm_rules = cbm_2intersect(&cbm_set1[i], &cbm_set2[j], cbm_rules, &rulesum);
	    // 2. check whether the intersect cbm exists in crossproducted cbm list so far
	    cbm_id = cbm_lookup(cbm_rules, num_cbm_rules, rulesum, cpd_set);
	    if (cbm_id < 0) {
		// 3. the intersect cbm is new, so add it to the crossproducted cbm list
		cbm_id = n;
		cpd_set[cbm_id].id = cbm_id;
		cpd_set[cbm_id].numrules = num_cbm_rules;
		cpd_set[cbm_id].rulelist = (int *) malloc(num_cbm_rules * sizeof(int));
		cpd_set[cbm_id].rulesum = rulesum;
		memcpy(cpd_set[cbm_id].rulelist, cbm_rules, num_cbm_rules * sizeof(int));
		if (++n == cpd_set_size) {
		    cpd_set_size += MAXRULES;
		    cpd_set = realloc(cpd_set, cpd_set_size*sizeof(cbm_t));
		}

		add_to_hash(&cpd_set[cbm_id]);
		len = num_cbm_rules > 63 ? 63 : num_cbm_rules;
		rulelist_len_count[len]++;
	    }
	    //4. fill the corresponding crossproduct table with the eqid (cmb_id)
	    cpd_tab[i*n2 + j] = cbm_id;
	}
    }

    free_cbm_hash();
    *num_cpd = n;
    return cpd_set;
}



static int cbm_stat_cmp(const void *p, const void *q)
{
    return ((cbm_stat_t *)q)->count - ((cbm_stat_t *)p)->count;
}



// get the 10 most frequent eqid in a phase table, and output them with their numbers of times in the phase table
// flag = 1: output the detail of each cbm; flag = 0: no detail on each cbm
int do_cbm_stats(int *table, int n, cbm_t *cbm_set, int cbm_num, int flag)
{
    cbm_stat_t	*stats = (cbm_stat_t *) malloc(cbm_num*sizeof(cbm_stat_t));
    int		i, k, m, total = 0;

    for (i = 0; i < cbm_num; i++) {
	stats[i].id = i;
	stats[i].count = 0;
    }
    for (i = 0; i < n; i++) {
	stats[table[i]].count++;
    }
    qsort(stats, cbm_num, sizeof(cbm_stat_t), cbm_stat_cmp);

    m = cbm_num > 16 ? 16 : cbm_num;
    for (i = 0; i < m; i++) {
	if (stats[i].count == 1)
	    break;
	printf("    eqid[%d]: %d\n", stats[i].id, stats[i].count);
	total += stats[i].count;
	if (flag) {
	    printf("    ");
	    for (k = 0; k < cbm_set[stats[i].id].numrules; k++) {
		printf("%d  ", cbm_set[stats[i].id].rulelist[k]);
	    }
	    printf("\n");
	}
    }
    printf("%d/%d\n", total, n);
    free(stats);
}



#define RUNLEN   8
int p1_crossprod()
{
    int		cbm_rules[MAXRULES], num_cbm_rules, i, table_size, cbm_set_size = MAXRULES;

    // SIP[31:16] x SIP[15:0]
    table_size = p0_cbm_num[1] * p0_cbm_num[0];
    p1_table_size[0] = table_size;
    p1_table[0] = (int *) malloc(table_size*sizeof(int));
    p1_cbm[0] = crossprod_2chunk(p0_cbm[1], p0_cbm_num[1], p0_cbm[0], p0_cbm_num[0], &p1_cbm_num[0], p1_table[0]);
    printf("chunk[%d] has %d/%d cbm\n", 0, p1_cbm_num[0], table_size);
    //dump_phase_table(p1_table[0], table_size, RUNLEN);
    do_cbm_stats(p1_table[0], table_size, p1_cbm[0], p1_cbm_num[0], 0);

    // DIP[31:16] x DIP[15:0]
    table_size = p0_cbm_num[3] * p0_cbm_num[2];
    p1_table_size[1] = table_size;
    p1_table[1] = (int *) malloc(table_size*sizeof(int));
    p1_cbm[1] = crossprod_2chunk(p0_cbm[3], p0_cbm_num[3], p0_cbm[2], p0_cbm_num[2], &p1_cbm_num[1], p1_table[1]);
    printf("chunk[%d] has %d/%d cbm\n", 1, p1_cbm_num[1], table_size);
    //dump_phase_table(p1_table[1], table_size, RUNLEN);
    do_cbm_stats(p1_table[1], table_size, p1_cbm[1], p1_cbm_num[1], 0);

    // DP x SP
    table_size = p0_cbm_num[6] * p0_cbm_num[5];
    p1_table_size[2] = table_size;
    p1_table[2] = (int *) malloc(table_size*sizeof(int));
    p1_cbm[2] = crossprod_2chunk(p0_cbm[6], p0_cbm_num[6], p0_cbm[5], p0_cbm_num[5], &p1_cbm_num[2], p1_table[2]);
    printf("chunk[%d] has %d/%d cbm\n", 2, p1_cbm_num[2], table_size);
    //dump_phase_table(p1_table[2], table_size, RUNLEN);
    do_cbm_stats(p1_table[2], table_size, p1_cbm[2], p1_cbm_num[2], 0);

    dump_intersect_stats();
    bzero(intersect_stats, MAXRULES*2*sizeof(int));
}



int p2_crossprod()
{
    int		cbm_rules[MAXRULES], num_cbm_rules, i, table_size;

    // SIP x DIP
    table_size = p1_cbm_num[0] * p1_cbm_num[1];
    p2_table_size[0] = table_size;
    p2_table[0] = (int *) malloc(table_size*sizeof(int));
    p2_cbm[0] = crossprod_2chunk(p1_cbm[0], p1_cbm_num[0], p1_cbm[1], p1_cbm_num[1], &p2_cbm_num[0], p2_table[0]);
    printf("chunk[%d] has %d/%d cbm\n", 0, p2_cbm_num[0], table_size);
    //dump_phase_table(p2_table[0], table_size, RUNLEN);
    do_cbm_stats(p2_table[0], table_size, p2_cbm[0], p2_cbm_num[0], 0);

    // PROTO x (DP x SP)
    table_size = p0_cbm_num[4] * p1_cbm_num[2];
    p2_table_size[1] = table_size;
    p2_table[1] = (int *) malloc(table_size*sizeof(int));
    p2_cbm[1] = crossprod_2chunk(p0_cbm[4], p0_cbm_num[4], p1_cbm[2], p1_cbm_num[2], &p2_cbm_num[1], p2_table[1]);
    printf("chunk[%d] has %d/%d cbm\n", 1, p2_cbm_num[1], table_size);
    //dump_phase_table(p2_table[1], table_size, RUNLEN);
    do_cbm_stats(p2_table[1], table_size, p2_cbm[1], p2_cbm_num[1], 0);

    dump_intersect_stats();
    bzero(intersect_stats, MAXRULES*2*sizeof(int));
}



int p3_crossprod()
{
    int		cbm_rules[MAXRULES], num_cbm_rules, i, table_size;

    // (SIP x DIP) x (PROTO x (DP x SP))
    table_size = p2_cbm_num[0] * p2_cbm_num[1];
    p3_table_size = table_size;
    p3_table = (int *) malloc(table_size*sizeof(int));
    p3_cbm = crossprod_2chunk(p2_cbm[0], p2_cbm_num[0], p2_cbm[1], p2_cbm_num[1], &p3_cbm_num, p3_table);
    printf("chunk[%d] has %d/%d cbm\n", 0, p3_cbm_num, table_size);
    //dump_phase_table(p3_table, table_size, RUNLEN);
    do_cbm_stats(p3_table, table_size, p3_cbm, p3_cbm_num, 0);

    dump_intersect_stats();
}



int do_rfc_stats()
{
    int	    i, phase_total[4] = {0, 0, 0, 0}, total = 0;

    printf("\nPhase 0:\n");
    printf("====================\n");
    for (i = 0; i < 7; i++) {
	printf("#cbm/#phase-table %d: %d/%d\n", i, p0_cbm_num[i], 65536);
	phase_total[0] += 65536;
    }
    printf("Total phase-table size: %d\n", phase_total[0]);

    printf("\nPhase 1:\n");
    printf("====================\n");
    for (i = 0; i < 3; i++) {
	printf("#cbm/#phase-table %d: %d/%d\n", i, p1_cbm_num[i], p1_table_size[i]);
	phase_total[1] += p1_table_size[i];
    }
    printf("Total phase-table size: %d\n", phase_total[1]);

    printf("\nPhase 2:\n");
    printf("====================\n");
    for (i = 0; i < 2; i++) {
	printf("#cbm/#phase-table %d: %d/%d\n", i, p2_cbm_num[i], p2_table_size[i]);
	phase_total[2] += p2_table_size[i];
    }
    printf("Total phase-table size: %d\n", phase_total[2]);

    printf("\nPhase 3:\n");
    printf("====================\n");
    printf("#cbm/#phase-table: %d/%d\n", p3_cbm_num, p3_table_size);
    phase_total[3] = p3_table_size;

    for (i = 0; i < 4; i++)
	total += phase_total[i];
    printf("\n Total table size: %d\n", total);
}



int main(int argc, char* argv[]){

    int i,j,k;
    unsigned a, b, c, d, e, f, g;
    int header[MAXDIMENSIONS];
    char *s = (char *)calloc(200, sizeof(char));
    int done;
    int fid;
    int size = 0;
    int access = 0;
    int tmp;
    clock_t t;

    parseargs(argc, argv);

    while(fgets(s, 200, fpr) != NULL)numrules++;
    rewind(fpr);

    free(s);

    rules = (pc_rule_t *) calloc(numrules, sizeof(pc_rule_t));
    numrules = loadrule(fpr, rules);

    printf("the number of rules = %d\n", numrules);

    gen_endpoints();
    //dump_endpoints();

    t = clock();
    printf("\nPhase 0: \n");
    printf("===========================================\n");
    gen_p0_tables();
    printf("***Phase 0 spent %lds\n", (clock()-t)/1000000);
    fprintf(stderr, "***Phase 0 spent %lds\n", (clock()-t)/1000000);

    t = clock();
    printf("\nPhase 1: \n");
    printf("===========================================\n");
    p1_crossprod();
    printf("***Phase 1 spent %lds\n", (clock()-t)/1000000);
    fprintf(stderr, "***Phase 1 spent %lds\n", (clock()-t)/1000000);

    t = clock();
    printf("\nPhase 2: \n");
    printf("===========================================\n");
    p2_crossprod();
    printf("***Phase 2 spent %lds\n", (clock()-t)/1000000);
    fprintf(stderr, "***Phase 2 spent %lds\n", (clock()-t)/1000000);

    t = clock();
    printf("\nPhase 3: \n");
    printf("===========================================\n");
    p3_crossprod();
    printf("***Phase 3 spent %lds\n", (clock()-t)/1000000);
    fprintf(stderr, "***Phase 3 spent %lds\n", (clock()-t)/1000000);

    dump_rulelist_len_count();

    do_rfc_stats();

    dump_hash_stats();

    printf("\n");

}  
