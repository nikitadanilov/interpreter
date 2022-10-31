/* cc -O4 interpreter.c */
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

enum opc {
	O_TRAP          = 0x00,
	O_HALT          = 0x01,
	O_NOP           = 0x02,
	O_ALLOC         = 0x03,
	O_RESUME        = 0x04,
	O_SET           = 0x05,
	O_ADD           = 0x06,
	O_NR            = 0xff + 1
};

struct opcode {
	const char *o_name;
	void       *o_branch;
};

static struct opcode opcode[O_NR] = {};

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

#define OINIT(opc, branch, name) ({			\
        void *label = &&branch;			\
	int   idx   = (opc);				\
							\
	assert(0 <= idx && idx < ARRAY_SIZE(opcode));	\
	assert(0 <= idx && idx < ARRAY_SIZE(branches)); \
	branches[opc]        = label;			\
	opcode[opc].o_name   = name;			\
	opcode[opc].o_branch = label;			\
})

#define OI(x) OINIT(O_ ## x, L_ ## x, #x)
#define CONT ({ goto *branches[*(uint8_t *)pc++]; })

enum { REGS = 16 };

struct regs {
	uint64_t r[REGS];
};

enum { R_PC = 0, R_SF = 1, R_SP = 2, R_REST = 3 };

#define pc (regs.r[R_PC])
#define sf (regs.r[R_SF])
#define sp (regs.r[R_SP])

struct proc {
	struct regs regs;
};

#define REIFY ((struct proc) { .regs = regs })
#define DEIFY(p) ({ regs = (p)->regs; })

#define RF "%016"PRIx64

#define likely(x)       __builtin_expect((x), 1)
#define unlikely(x)     __builtin_expect((x), 0)

#define U64(x) ((uint64_t)(x))
#define P64(x) ((uint64_t *)(x))
#define DEREF(x) (*P64(x))
#define N8 (*(uint8_t *)pc++)
#define N64 (*(uint64_t *)pc++)

enum trapcode {
	T_TRAP = 0x00, /* Trap instruction. */
	T_ILL  = 0x01, /* Ill-formed instruction. */
	T_OOM  = 0x02  /* Out of memory. */
};

static void trap(struct proc *p, uint8_t code) {
	printf("trap: %02x\n", code);
	printf("pc: "RF" ", U64(p->regs.r[R_PC]));
	printf("sf: "RF" ", U64(p->regs.r[R_SF]));
	printf("sp: "RF" ", U64(p->regs.r[R_SP]));
	for (int i = R_REST; i < ARRAY_SIZE(p->regs.r); ++i) {
		printf("r%01x: "RF"%s", i, p->regs.r[i], i%4 == 3 ? "\n" : " ");
	}
	puts("");
}

static uint64_t alloc(uint64_t slots) {
	void *data = calloc(slots, sizeof(uint64_t));
	return U64(data);
}

enum {
	AM_MASK = 0b00110000,
	AM_REF  = 0b10000000,
	AM_IDX  = 0b00001111,
	AM_IMM  = 0b00000000,
	AM_SLOT = 0b00010000,
	AM_REG  = 0b00100000,
	AM_SLOR = 0b01000000
};

#define ADDR ({					\
	uint8_t  next = N8;				\
	uint64_t addr;					\
	uint8_t  idx  = next & AM_IDX;			\
	switch (next & AM_MASK) {			\
	case AM_IMM:					\
		addr = U64(pc); 			\
		pc += 8;				\
		break;					\
	case AM_SLOT:					\
		addr = U64(P64(sf) + idx);		\
		break;					\
	case AM_REG:					\
		addr = U64(&regs.r[idx]);		\
		break;					\
	default:					\
		printf("Wrong mode: %02x\n", next);	\
		assert(0);				\
	}						\
	if (next & AM_SLOR)				\
		addr = U64(P64(DEREF(addr)) + N8);	\
	if (next & AM_REF)				\
		addr = DEREF(addr);			\
	U64(addr);					\
})

/* Little-endian. */

#define IVAL8(x) (uint8_t)AM_IMM, (uint8_t)((x) & 0xff)
#define IVAL16(x) (uint8_t)AM_IMM,	\
	((x) & 0x00ff) >>  0,		\
	((x) & 0xff00) >>  8

#define IVAL32(x) (uint8_t)AM_IMM,	\
	((x) & 0x000000ff) >>  0,	\
	((x) & 0x0000ff00) >>  8,	\
	((x) & 0x00ff0000) >> 16,	\
	((x) & 0xff000000) >> 24

#define IVAL64(flags, x) (uint8_t)(AM_IMM | flags),	\
	((x) & 0x00000000000000ff) >>  0,	\
	((x) & 0x000000000000ff00) >>  8,	\
	((x) & 0x0000000000ff0000) >> 16,	\
	((x) & 0x00000000ff000000) >> 24,	\
	((x) & 0x000000ff00000000) >> 32,	\
	((x) & 0x0000ff0000000000) >> 40,	\
	((x) & 0x00ff000000000000) >> 48,	\
	((x) & 0xff00000000000000) >> 56

#define SLOT(x) ((uint8_t)(AM_SLOT | (x)))
#define REG(x)  ((uint8_t)(AM_REG  | (x)))
#define TRAP(code) ({ *p = REIFY; trap(p, (code)); DEIFY(p); })

static void interpret(struct proc *p) {
	static void *branches[O_NR] = {};
	uint64_t     s0   = 0;
	uint64_t     s1   = 0;
	uint64_t     s2   = 0;
	struct regs  regs = {};

	if (0) {
	L_TRAP:
		TRAP(T_TRAP);
		CONT;
	L_HALT:
		printf("Halt!\n");
		return;
	L_NOP:  CONT;
	L_ALLOC:
		s0 = ADDR;
		s1 = ADDR;
		s2 = alloc(DEREF(s0));
		DEREF(s1) = s2;
		if (unlikely(s2 == 0)) {
			TRAP(T_OOM);
		}
		CONT;
	L_RESUME:
		s0 = ADDR;
		s1 = ADDR;
		DEREF(sf) = (uint64_t)pc;
		sf = DEREF(s0);
		pc = DEREF(s1);
		CONT;
	L_SET:
		s0 = ADDR;
		s1 = ADDR;
		DEREF(s1) = DEREF(s0);
		CONT;
	L_ADD:
		s0 = ADDR;
		s1 = ADDR;
		s2 = ADDR;
		DEREF(s2) = DEREF(s0) + DEREF(s1);
		CONT;
	} else if (p != NULL) {
		DEIFY(p);
		CONT;
	} else {
		OI(TRAP);
		OI(HALT);
		OI(NOP);
		OI(ALLOC);
		OI(RESUME);
		OI(SET);
		OI(ADD);
	}
}

enum {
	MAX_LABEL      = 256,
	MAX_LABEL_NAME = 256,
	MAX_PATCH      = 256
};

struct label {
	const char *name;
	int         off;
	int         patch[MAX_PATCH];
};

struct prog {
	uint8_t     *start;
	int          off;
	struct label label[MAX_LABEL];
};

static void *at(struct prog *prog) {
	return prog->start + prog->off;
}

static void out(struct prog *prog, uint8_t *part, int nob) {
	if (prog->start != NULL) {
		memcpy(at(prog), part, nob);
	}
	prog->off += nob;
}

static int in(const char *str, int *off, const char *op) {
	if (strncmp(str + *off, op, strlen(op)) == 0) {
		*off += strlen(op);
		return 1;
	} else
		return 0;
}

static void skip(const char *s, int *idx) {
	while (s[*idx] != 0 && strchr(" \t\n\r\v", s[*idx]) != NULL) {
		++*idx;
	}
	if (s[*idx] == ';')
		*idx += strlen(s + *idx);
}

static int getnum(const char *s, int *idx, int limit) {
	int n;
	int val;
	int nob;
	n = sscanf(s + *idx, "%i%n", &val, &nob);
	assert(n == 1);
	assert(0 <= val && val < limit);
	*idx += nob;
	return val;
}

static int find(struct prog *prog, const char *name) {
	for (int i = 0; i < ARRAY_SIZE(prog->label); ++i) {
		if (prog->label[i].name != NULL &&
		    strcmp(prog->label[i].name, name) == 0) {
			return i;
		}
		if (prog->label[i].name == NULL) {
			prog->label[i].name = strdup(name);
			return i;
		}
	}
	assert(0); /* Too many labels. */
}

static struct label *add(struct prog *prog, const char *inst, int *idx, int loc) {
	int end = *idx;
	int lidx;
	char name[MAX_LABEL_NAME + 1] = {};
	while (isalnum(inst[end])) {
		++end;
	}
	assert(end > *idx);
	assert(end - *idx <= MAX_LABEL_NAME);
	memcpy(name, inst + *idx, end - *idx);
	*idx = end;
	lidx = find(prog, name);
	if (prog->label[lidx].off == 0)
		prog->label[lidx].off = loc;
	skip(inst, idx);
	return &prog->label[lidx];
}

static void outimm(struct prog *prog, uint64_t val, uint8_t flags) {
	uint8_t data[] = { IVAL64(flags, val) };
	out(prog, data, sizeof data);
}

static void out8(struct prog *prog, uint8_t val) {
	out(prog, &val, sizeof val);
}

static void arg(const char *s, int *idx, struct prog *prog) {
	uint8_t ref;
	uint8_t *cur = at(prog);
	skip(s, idx);
	ref = in(s, idx, "*") ? AM_REF : 0;
	if (in(s, idx, "#")) { /* Immediate argument. */
		uint64_t val;
		int nob;
		int n = sscanf(s + *idx, "%"SCNi64"%n", &val, &nob);
		assert(n == 1);
		*idx += nob;
		outimm(prog, val, ref);
	} else if (in(s, idx, ":")) { /* Slot. */
		out8(prog, AM_SLOT | ref | getnum(s, idx, 16));
	} else if (in(s, idx, "r")) { /* Register */
		out8(prog, AM_REG | ref | getnum(s, idx, 16));
	} else if (in(s, idx, "pc")) {
		out8(prog, AM_REG | ref | R_PC);
	} else if (in(s, idx, "sp")) {
		out8(prog, AM_REG | ref | R_SP);
	} else if (in(s, idx, "sf")) {
		out8(prog, AM_REG | ref | R_SF);
	} else if (in(s, idx, ".")) { /* Label */
		struct label *l = add(prog, s, idx, 0);
		int           i;
		for (i = 0; i < ARRAY_SIZE(l->patch) && l->patch[i] != 0; ++i) {
			;
		}
		assert(i < ARRAY_SIZE(l->patch));
		l->patch[i] = prog->off + 1;
		outimm(prog, ~0ULL, ref);
	} else {
		assert(0);
	}
	if (in(s, idx, "/")) { /* Slor. */
		out8(prog, getnum(s, idx, 256));
		*cur |= AM_SLOR;
	}

}

static struct cmd {
	const char *name;
	uint8_t     opc;
	int         arity;
} cmd[] = {
	{ "trap",   O_TRAP,   0 },
	{ "nop",    O_NOP,    0 },
	{ "halt",   O_HALT,   0 },
	{ "alloc",  O_ALLOC,  2 },
	{ "resume", O_RESUME, 2 },
	{ "set",    O_SET,    2 },
	{ "add",    O_ADD,    3 }
};

static void parse1(const char *inst, struct prog *prog) {
	int idx = 0;
	skip(inst, &idx);
	if (in(inst, &idx, ".")) { /* A label. */
		add(prog, inst, &idx, prog->off);
	}
	for (int i = 0; i < ARRAY_SIZE(cmd); ++i) {
		if (in(inst, &idx, cmd[i].name)) {
			out(prog, (uint8_t[]){ cmd[i].opc }, 1);
			for (int j = 0; j < cmd[i].arity; ++j) {
				arg(inst, &idx, prog);
			}
		}
	}
	skip(inst, &idx);
	assert(inst[idx] == 0);
}

static void patch(struct prog *prog) {
	int off = prog->off;
	for (int i = 0; i < ARRAY_SIZE(prog->label); ++i) {
		struct label *l = &prog->label[i];
		if (l->name != 0) {
			for (int j = 0; j < ARRAY_SIZE(l->patch) &&
				     l->patch[j] != 0; ++j) {
				prog->off = l->patch[j] - 1;
				uint8_t flags = prog->start[l->patch[j] - 1];
				outimm(prog, U64(prog->start) + l->off, flags);
			}
		}
	}
	prog->off = off;
}

static void compile(struct prog *prog, const char **code) {
	for (int i = 0; code[i] != NULL; ++i) {
		parse1(code[i], prog);
	}
	patch(prog);
}

static void dump(const struct prog *prog) {
	for (int i = 0; i < prog->off; ++i) {
		if (i%16 == 0) {
			printf(RF": ", U64(prog->start) + i);
		}
		printf("%02x ", prog->start[i]);
		if (i%16 == 15) {
			puts("");
		}
	}
	puts("");
}

static int disarg(const struct prog *prog, int off) {
	uint8_t *start = prog->start;
	uint8_t  arg   = start[off];
	uint8_t  idx   = arg & AM_IDX;
	uint8_t  mod   = arg & AM_MASK;
	++off;
	if (arg & AM_REF) {
		printf("*");
	}
	if (mod == AM_IMM) {
		uint64_t val = DEREF(&start[off]);
		if (U64(start) <= val && val < U64(start) + prog->off) {
			printf("<+%"PRIx64">", val - U64(start));
		} else {
			printf("#%"PRIx64, val);
		}
		off += 8;
	} else if (mod == AM_SLOT) {
		printf(":%1x", idx);
	} else if (mod == AM_REG) {
		if (idx < R_REST) {
			printf("%s", (char *[]){ [R_PC] = "pc", [R_SF] = "sf",
						 [R_SP] = "sp" }[idx]);
		} else {
			printf("r%1x", idx);
		}
	} else {
		assert(0);
	}
	if (arg & AM_SLOR) {
		printf("/%02x", *(uint8_t *)&start[off]);
		++off;
	}
	return off;
}

static int dis1(const struct prog *prog, int off) {
	int i;
	for (i = 0; i < ARRAY_SIZE(cmd); ++i) {
		if (prog->start[off] == cmd[i].opc) {
			printf(RF"+%4x        %-6s ", U64(prog->start), off,
			       cmd[i].name);
			++off;
			for (int j = 0; j < cmd[i].arity; ++j) {
				off = disarg(prog, off);
				printf(" ");
			}
			puts("");
			break;
		}
	}
	assert(i < ARRAY_SIZE(cmd));
	return off;
}

static void dis(const struct prog *prog)
{
	int off = 0;
	while (off < prog->off) {
		off = dis1(prog, off);
	}
}

int main(int argc, char **argv)
{
	uint64_t frame[8] = {};
	uint8_t image[1024];
	struct prog prog = {
		.start = image
	};
	interpret(NULL);
	compile(&prog, (const char *[]){
			"; main",
			".entry nop",
			"       alloc #8 r3",
			"       set .ret :0",
			"       set sf r3/1",
			"       resume r3 .sub",
			".ret   trap",
			"       halt",
			"; sub",
			".sub   ",
			"       set #7 r3",
			"       add r3 #8 r5",
			"       resume :1 *:1",
			NULL });
	dump(&prog);
	dis(&prog);
	struct proc p = {
		.regs = {
			.r[R_PC] = (uint64_t)prog.start,
			.r[R_SF] = (uint64_t)frame
		}
	};
	interpret(&p);
	return 0;
}
