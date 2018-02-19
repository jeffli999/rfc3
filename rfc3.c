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
#include "rfc.h"

int  phase = 4;  // number of pahses
FILE *fpr;       // ruleset file
FILE *fpt;       // test trace file

int numrules=0;  // actual number of rules in rule set
struct pc_rule *rules; 

int epoints[MAXCHUNKS][MAXRULES*2+2];
int num_epoints[MAXCHUNKS];

int p0_table[7][65536];		//phase 0 chunk tables
int p1_table[4][MAXTABLE];	//phase 1 chunk tables
int p2_table[2][MAXTABLE];      //phase 2 chunk tables
int p3_table[MAXTABLE];         //phase 3 chunk tables
cbm_t *p0_cbm[7];		//phase 0 chunk equivalence class
cbm_t *p1_cbm[4];		//phase 1 chunk equivalence class
cbm_t *p2_cbm[2];		//phase 2 chunk equivalence class
cbm_t *p3_cbm;		//phase 3 chunk equivalence class
int p0_cbm_num[7];		//phase 0 number of chunk equivalence classes
int p1_cbm_num[4];              //phase 1 number of chunk equivalence classes
int p2_cbm_num[2];              //phase 2 number of chunk equivalence classes
int p3_cbm_num;                 //phase 3 number of chunk equivalence classes

int do_cbm_stats(int *table, int n, int cbm_num);


void parseargs(int argc, char *argv[]) 
{
    int	c;
    bool ok = 1;

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



int loadrule(FILE *fp, pc_rule *rule){

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



int cbm_lookup(int *cbm_rules, int num_cbm_rules, cbm_t *cbm_set, int num_cbm)
{
    int		i, k, match = 0;
    cbm_t	*p;

    for (i = 0; i < num_cbm; i++) {
	p = &cbm_set[i];
	if (p->numrules != num_cbm_rules)
	    continue;
	for (k = 0; k < p->numrules; k++) {
	    if (p->rulelist[k] != cbm_rules[k])
		break;
	}
	if (k == p->numrules)
	    break;
    }
    return i;
}



void dump_phase_table(int *table, int len)
{
    int	    i, eqid, eqid1, run_len;

    eqid = table[0];
    run_len = 1;
    for (i = 1; i < len; i++) {
	eqid1 = table[i];
	if (eqid1 == eqid) {
	    run_len++;
	} else {
	    printf("eqid[%d]: %d\n", eqid, run_len);
	    eqid = eqid1;
	    run_len = 1;
	}
    }
    if (run_len > 1)
	printf("eqid[%d]: %d\n", eqid, run_len);
}



int gen_p0_cbm(int chunk)
{
    cbm_t	cbm_set[MAXRULES*2+2];
    int		cbm_rules[MAXRULES], num_cbm_rules;
    int		i, j, f, k, r, low, high, point, next_point, cbm_id, num_cbm = 0;

    f = chunk_to_field[chunk];
    k = shamt[chunk];
    for (i = 0; i < num_epoints[chunk]; i++) {
	// 1. generate a cbm
	point = epoints[chunk][i];
	num_cbm_rules = 0;
	for (r = 0; r < numrules; r++) {
	    low = rules[r].field[f].low >> k & 0xFFFF;
	    high = rules[r].field[f].high >> k & 0xFFFF;
	    if (low <= point && high >= point)
		cbm_rules[num_cbm_rules++] = r;
	}

	// 2. check whether the generated cbm exists
	cbm_id = cbm_lookup(cbm_rules, num_cbm_rules, cbm_set, num_cbm);
	if (cbm_id == num_cbm) {
	    // 3. this is a new cbm, add it to the cbm_set
	    cbm_set[num_cbm].numrules = num_cbm_rules;
	    cbm_set[num_cbm].rulelist = (int *) malloc(num_cbm_rules * sizeof(int));
	    memcpy(cbm_set[num_cbm].rulelist, cbm_rules, num_cbm_rules * sizeof(int));
	    num_cbm++;
	}

	// 4. fill the corresponding p0 chunk table with the eqid (cbm_id)
	next_point = (i == num_epoints[chunk] - 1) ? 65536 : epoints[chunk][i+1];
	for (j = point; j < next_point; j++)
	    p0_table[chunk][j] = cbm_id;
    }
    // 5. allocate memory and copy the generated phase 0 chunk equivalent classes
    p0_cbm[chunk] = (cbm_t *) calloc(num_cbm, sizeof(cbm_t));
    memcpy(p0_cbm[chunk], cbm_set, num_cbm * sizeof(cbm_t));

    printf("chunk[%d] has %d cbm\n", chunk, num_cbm);
    //dump_phase_table(p0_table[chunk], 65536);

    return num_cbm;
}



int gen_p0_tables()
{
    int			chunk;

    for (chunk = 0; chunk < MAXCHUNKS; chunk++) {
	p0_cbm_num[chunk] = gen_p0_cbm(chunk);
	do_cbm_stats(p0_table[chunk], 65536, p0_cbm_num[chunk]);
    }
    
}



int cbm_2intersect(cbm_t *c1, cbm_t *c2, int *cbm_rules)
{
    int	    i = 0, j = 0, n = 0;

    while (i < c1->numrules && j < c2->numrules) {
	if (c1->rulelist[i] == c2->rulelist[j]) {
	    cbm_rules[n++] = c1->rulelist[i];
	    i++; j++;
	} else if (c1->rulelist[i] > c2->rulelist[j]) {
	    j++;
	} else {
	    i++;
	}
    }
    return n;
}



int crossprod_2chunk(cbm_t *cbm_set1, int n1, cbm_t *cbm_set2, int n2, cbm_t *cpd_set, int *cpd_tab)
{
    int	    i, j, cbm_id, num_cpd = 0;
    int	    cbm_rules[MAXRULES], num_cbm_rules;

    for (i = 0; i < n1; i++) {
	for (j =  0; j < n2; j++) {
	    // 1. generate the intersect of two cbms from two chunks
	    num_cbm_rules = cbm_2intersect(&cbm_set1[i], &cbm_set2[j], cbm_rules);
	    // 2. check whether the intersect cbm exists in crossproducted cbm list so far
	    cbm_id = cbm_lookup(cbm_rules, num_cbm_rules, cpd_set, num_cpd);
	    if (cbm_id == num_cpd) {
		// 3. the intersect cbm is new, so add it to the crossproducted cbm list
		cpd_set[num_cpd].numrules = num_cbm_rules;
		cpd_set[num_cpd].rulelist = (int *) malloc(num_cbm_rules * sizeof(int));
		memcpy(cpd_set[num_cpd].rulelist, cbm_rules, num_cbm_rules * sizeof(int));
		num_cpd++;
	    }
	    //4. fill the corresponding crossproduct table with the eqid (cmb_id)
	    cpd_tab[i*n2 + j] = cbm_id;
	}
    }
    return num_cpd;
}



int cbm_3intersect(cbm_t *c1, cbm_t *c2, cbm_t *c3, int *cbm_rules)
{
    int	    i = 0, j = 0, k = 0, n = 0;

    while (i < c1->numrules && j < c2->numrules &&  k < c3->numrules) {
	if (c1->rulelist[i] == c2->rulelist[j] && c1->rulelist[i] == c3->rulelist[k]) {
	    cbm_rules[n++] = c1->rulelist[i];
	    i++; j++; k++;
	} else if (c1->rulelist[i] <= c2->rulelist[j]  &&  c1->rulelist[i] <= c3->rulelist[k]) {
	    i++;
	} else if (c2->rulelist[j] <= c1->rulelist[i]  &&  c2->rulelist[j] <= c3->rulelist[k]) {
	    j++;
	} else {
	    k++;
	}
    }
    return n;
}



int crossprod_3chunk(cbm_t *cbm_set1, int n1, cbm_t *cbm_set2, int n2, cbm_t *cbm_set3, int n3, cbm_t *cpd_set, int *cpd_tab)
{
    int	    i, j, k, cbm_id, num_cpd = 0;
    int	    cbm_rules[MAXRULES], num_cbm_rules;

    for (i = 0; i < n1; i++) {
	for (j =  0; j < n2; j++) {
	    for (k =  0; k < n3; k++) {
		// 1. generate the intersect of two cbms from two chunks
		num_cbm_rules = cbm_3intersect(&cbm_set1[i], &cbm_set2[j], &cbm_set3[k], cbm_rules);
		// 2. check whether the intersect cbm exists in crossproducted cbm list so far
		cbm_id = cbm_lookup(cbm_rules, num_cbm_rules, cpd_set, num_cpd);
		if (cbm_id == num_cpd) {
		    // 3. the intersect cbm is new, so add it to the crossproducted cbm list
		    cpd_set[num_cpd].numrules = num_cbm_rules;
		    cpd_set[num_cpd].rulelist = (int *) malloc(num_cbm_rules * sizeof(int));
		    memcpy(cpd_set[num_cpd].rulelist, cbm_rules, num_cbm_rules * sizeof(int));
		    num_cpd++;
		}
		//4. fill the corresponding crossproduct table with the eqid (cmb_id)
		cpd_tab[i*n2*n3 + j*n3 + k] = cbm_id;
	    }
	}
    }
    return num_cpd;
}



static int cbm_stat_cmp(const void *p, const void *q)
{
    return ((cbm_stat_t *)q)->count - ((cbm_stat_t *)p)->count;
}



int do_cbm_stats(int *table, int n, int cbm_num)
{
    cbm_stat_t	stats[MAXRULES*2+2];
    int		i, k, total = 0;

    for (i = 0; i < cbm_num; i++) {
	stats[i].id = i;
	stats[i].count = 0;
    }
    for (i = 0; i < n; i++) {
	stats[table[i]].count++;
    }
    qsort(stats, cbm_num, sizeof(cbm_stat_t), cbm_stat_cmp);

    k = cbm_num > 10 ? 10 : cbm_num;
    for (i = 0; i < k; i++) {
	if (stats[i].count == 1)
	    break;
	printf("    eqid[%d]: %d\n", stats[i].id, stats[i].count);
	total += stats[i].count;
    }
    printf("%d/%d\n", total, n);
}



int p1_crossprod()
{
    cbm_t	cbm_set[MAXRULES*2+2];
    int		cbm_rules[MAXRULES], num_cbm_rules, i, table_size;


    table_size = p0_cbm_num[0] * p0_cbm_num[1];
    p1_cbm_num[0] = crossprod_2chunk(p0_cbm[0], p0_cbm_num[0], p0_cbm[1], p0_cbm_num[1], cbm_set, p1_table[0]);
    p1_cbm[0] = (cbm_t*) calloc(p1_cbm_num[0], sizeof(cbm_t));
    memcpy(p1_cbm[0], cbm_set, p1_cbm_num[0]*sizeof(cbm_t));
    printf("chunk[%d] has %d/%d cbm\n", 0, p1_cbm_num[0], table_size);
    //dump_phase_table(p1_table[0], table_size);
    do_cbm_stats(p1_table[0], table_size, p1_cbm_num[0]);

    table_size = p0_cbm_num[2] * p0_cbm_num[3];
    p1_cbm_num[1] = crossprod_2chunk(p0_cbm[2], p0_cbm_num[2], p0_cbm[3], p0_cbm_num[3], cbm_set, p1_table[1]);
    p1_cbm[1] = (cbm_t*) calloc(p1_cbm_num[1], sizeof(cbm_t));
    memcpy(p1_cbm[1], cbm_set, p1_cbm_num[1]*sizeof(cbm_t));
    printf("chunk[%d] has %d/%d cbm\n", 1, p1_cbm_num[1], table_size);
    //dump_phase_table(p1_table[1], table_size);
    do_cbm_stats(p1_table[1], table_size, p1_cbm_num[1]);

    table_size = p0_cbm_num[4] * p0_cbm_num[5] * p0_cbm_num[6];
    p1_cbm_num[2] = crossprod_3chunk(p0_cbm[4], p0_cbm_num[4], p0_cbm[5], p0_cbm_num[5], p0_cbm[6], p0_cbm_num[6], cbm_set, p1_table[2]);
    p1_cbm[2] = (cbm_t*) calloc(p1_cbm_num[2], sizeof(cbm_t));
    memcpy(p1_cbm[2], cbm_set, p1_cbm_num[2]*sizeof(cbm_t));
    printf("chunk[%d] has %d/%d cbm\n", 2, p1_cbm_num[2], table_size);
    //dump_phase_table(p1_table[2], table_size);
    do_cbm_stats(p1_table[2], table_size, p1_cbm_num[2]);
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

    parseargs(argc, argv);

    while(fgets(s, 200, fpr) != NULL)numrules++;
    rewind(fpr);

    free(s);

    rules = (pc_rule *)calloc(numrules, sizeof(pc_rule));
    numrules = loadrule(fpr, rules);

    printf("the number of rules = %d\n", numrules);

    gen_endpoints();
    //dump_endpoints();

    printf("\nPhase 0: \n");
    printf("===========================================\n");
    gen_p0_tables();

    printf("\nPhase 1: \n");
    printf("===========================================\n");
    p1_crossprod();

    printf("\n");

}  

