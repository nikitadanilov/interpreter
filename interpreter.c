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
	O_MUL           = 0x07,
	O_IF0           = 0x08,
	O_NR            = 0xff + 1
};

struct opcode {
	const char *o_name;
	void       *o_branch;
};

#define DEBUG (1)

#if DEBUG
#define ON_DEBUG(...) __VA_ARGS__
#else
#define ON_DEBUG(...)
#endif

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

static void trace(uint64_t p);

#define OI(x) OINIT(O_ ## x, L_ ## x, #x)
#define CONT ({					\
	ON_DEBUG(trace(regs->r[R_PC])); 		\
	goto *branches[*(uint8_t *)regs->r[R_PC]++];	\
})

enum { REGS = 16 };

struct regs {
	uint64_t r[REGS];
};

enum { R_PC = 0, R_SF = 1, R_SP = 2, R_REST = 3 };

struct proc {
	struct regs regs;
};

#define RF "%016"PRIx64

#define likely(x)       __builtin_expect((x), 1)
#define unlikely(x)     __builtin_expect((x), 0)

#define U64(x) ((uint64_t)(x))
#define P64(x) ((uint64_t *)(x))
#define DEREF(x) (*P64(x))
#define N8  (*(uint8_t *)regs->r[R_PC]++)

enum trapcode {
	T_TRAP = 0x00, /* Trap instruction. */
	T_ILL  = 0x01, /* Ill-formed instruction. */
	T_OOM  = 0x02  /* Out of memory. */
};

static void trap(struct proc *p, uint8_t code) {
	printf("trap: %02x\n", code);
	printf("pc "RF" ", U64(p->regs.r[R_PC]));
	printf("sf "RF" ", U64(p->regs.r[R_SF]));
	printf("sp "RF" ", U64(p->regs.r[R_SP]));
	for (int i = R_REST; i < ARRAY_SIZE(p->regs.r); ++i) {
		printf("r%01x "RF"%s", i, p->regs.r[i], i%4 == 3 ? "\n" : " ");
	}
	puts("");
	for (int i = 0; i < 8; ++i) {
		printf(":%01x "RF"%s", i, DEREF(p->regs.r[R_SF] + i),
		       i%4 == 3 ? "\n" : " ");
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
		addr = U64(regs->r[R_PC]);      	\
		regs->r[R_PC] += 8;			\
		break;					\
	case AM_SLOT:					\
		addr = U64(P64(regs->r[R_SF]) + idx);   \
		break;					\
	case AM_REG:					\
		addr = U64(&regs->r[idx]);		\
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

static void interpret(struct proc *p) {
	static void *branches[O_NR] = {};
	uint64_t     s0   = 0;
	uint64_t     s1   = 0;
	uint64_t     s2   = 0;
	struct regs *regs = &p->regs;

	if (0) {
	L_TRAP:
		trap(p, T_TRAP);
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
		ON_DEBUG(printf("    new("RF") == "RF"\n", DEREF(s0), s2));
		if (unlikely(s2 == 0)) {
			trap(p, T_OOM);
		}
		CONT;
	L_RESUME:
		s0 = ADDR;
		s1 = ADDR;
		DEREF(regs->r[R_SF]) = (uint64_t)regs->r[R_PC];
		regs->r[R_SF] = DEREF(s0);
		regs->r[R_PC] = DEREF(s1);
		CONT;
	L_SET:
		s0 = ADDR;
		s1 = ADDR;
		ON_DEBUG(printf("    *"RF" := "RF"\n", s1, DEREF(s0)));
		DEREF(s1) = DEREF(s0);
		CONT;
	L_ADD:
		s0 = ADDR;
		s1 = ADDR;
		s2 = ADDR;
		ON_DEBUG(printf("    *"RF" := "RF" + "RF" == "RF"\n", s2,
				DEREF(s0), DEREF(s1), DEREF(s0) + DEREF(s1)));
		DEREF(s2) = DEREF(s0) + DEREF(s1);
		CONT;
	L_MUL:
		s0 = ADDR;
		s1 = ADDR;
		s2 = ADDR;
		ON_DEBUG(printf("    *"RF" := "RF" * "RF" == "RF"\n", s2,
				DEREF(s0), DEREF(s1), DEREF(s0) * DEREF(s1)));
		DEREF(s2) = DEREF(s0) * DEREF(s1);
		CONT;
	L_IF0:
		s0 = ADDR;
		s1 = ADDR;
		ON_DEBUG(printf("    "RF" == 0?\n", DEREF(s0)));
		if (DEREF(s0) == 0)
			regs->r[R_PC] = DEREF(s1);
		CONT;
	} else if (p != NULL) {
		CONT;
	} else {
		OI(TRAP);
		OI(HALT);
		OI(NOP);
		OI(ALLOC);
		OI(RESUME);
		OI(SET);
		OI(ADD);
		OI(MUL);
		OI(IF0);
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

static int labellen(const char *s, int idx) {
	int end = idx;
	while (isalnum(s[end])) {
		++end;
	}
	assert(end > idx);
	assert(end - idx <= MAX_LABEL_NAME);
	return end - idx;
}

static struct label *add(struct prog *prog, const char *inst, int *idx, int loc) {
	int lidx;
	char name[MAX_LABEL_NAME + 1] = {};
	int len = labellen(inst, *idx);
	memcpy(name, inst + *idx, len);
	*idx += len;
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
		int n = sscanf(s + *idx, "%"SCNx64"%n", &val, &nob);
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
	{ "add",    O_ADD,    3 },
	{ "mul",    O_MUL,    3 },
	{ "if0",    O_IF0,    2 }
};

static void data(struct prog *prog, const char *s, int idx) {
	skip(s, &idx);
	if (in(s, &idx, "\"")) {
		while (s[idx] != '"') {
			out8(prog, s[idx++]);
		}
	} else {
		while (1) {
			int nob;
			uint8_t val;
			int n = sscanf(s + idx, " %"SCNx8"%n ", &val, &nob);
			if (n <= 0) /* NO_BUG_IN_ISO_C_CORRIGENDUM_1 */
				break;
			idx += nob;
			out8(prog, val);
		}
	}
}

static void parse1(const char *inst, struct prog *prog) {
	int idx = 0;
	skip(inst, &idx);
	if (in(inst, &idx, ".")) { /* A label. */
		add(prog, inst, &idx, prog->off);
	}
	if (in(inst, &idx, "=")) { /* Data. */
		return data(prog, inst, idx);
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
	char ch = prog->start[off];
	for (i = 0; i < ARRAY_SIZE(cmd); ++i) {
		if (ch == cmd[i].opc) {
			printf(RF"+%4x        %-6s ",
			       U64(prog->start + off), off, cmd[i].name);
			++off;
			for (int j = 0; j < cmd[i].arity; ++j) {
				off = disarg(prog, off);
				printf(" ");
			}
			puts("");
			break;
		}
	}
	if (i == ARRAY_SIZE(cmd)) {
		printf(RF"+%4x        data: %02x '%c'\n",
		       U64(prog->start + off), off, ch & 0xff,
		       isprint(ch) ? ch : '.');
		++off;
	}
	return off;
}

static void dis(const struct prog *prog)
{
	int off = 0;
	while (off < prog->off) {
		off = dis1(prog, off);
	}
}

static void trace(uint64_t p)
{
	const struct prog prog = {
		.start = (uint8_t *)(p),
	};
	dis1(&prog, 0);
}

enum { MAX_CLINE = 1024 };

#define OUT(s, pos, ...) ({						\
	char _scratch[MAX_CLINE] = {};					\
	strcpy(_scratch, s);						\
	pos += snprintf(_scratch + pos, MAX_CLINE - pos, __VA_ARGS__);	\
	assert(pos < MAX_CLINE);					\
	strcpy(s, _scratch);						\
})

#define OUT0(s, pos, ...) ({			\
	pos = 0;				\
	OUT(s, pos, __VA_ARGS__);		\
})

static const char *atoc(const char *s, int *idx, char *out, int pos, int lval) {
	int odx = 0;
	skip(s, idx);
	int ref = in(s, idx, "*");
	if (ref && lval) {
		lval = 0;
		ref = 0;
	}
	if (in(s, idx, "#")) { /* Immediate argument. */
		uint64_t val;
		int nob;
		int n = sscanf(s + *idx, "%"SCNx64"%n", &val, &nob);
		assert(n == 1);
		*idx += nob;
		if (lval) {
			OUT(out, odx,
			    "({ param%i = U64(0x%"PRIx64"ULL); &param%i; })",
			    pos, val, pos);
		} else {
			OUT(out, odx, "0x%"PRIx64"ULL", val);
		}
	} else if (in(s, idx, ":")) { /* Slot. */
		OUT(out, odx, "%s(P64(regs->r[R_SF]) + 0x%1x)",
		    lval ? "" : "DEREF", getnum(s, idx, 16));
	} else if (in(s, idx, "r")) { /* Register */
		OUT(out, odx, "%sregs->r[0x%1x]",
		    lval ? "&" : "", getnum(s, idx, 16));
	} else if (in(s, idx, "pc")) {
		OUT(out, odx, "%sregs->r[R_PC]", lval ? "&" : "");
	} else if (in(s, idx, "sp")) {
		OUT(out, odx, "%sregs->r[R_SP]", lval ? "&" : "");
	} else if (in(s, idx, "sf")) {
		OUT(out, odx, "%sregs->r[R_SF]", lval ? "&" : "");
	} else if (in(s, idx, ".")) { /* Label */
		int len = labellen(s, *idx);
		if (lval) {
			OUT(out, odx, "({ param%i = U64(&&%*.*s); &param%i; })",
			    pos, len, len, s + *idx, pos);
		} else {
			OUT(out, odx, "&&%*.*s", len, len, s + *idx);
		}
		*idx += len;
	} else {
		assert(0);
	}
	if (in(s, idx, "/")) { /* Slor. */
		OUT0(out, odx, "%s(P64(DEREF(%s)) + 0x%02x)",
		     lval ? "" : "DEREF", out, getnum(s, idx, 256));
	}
	if (ref) {
		OUT0(out, odx, "DEREF(%s)", out);
	}
	OUT0(out, odx, "U64(%s)", out);
	skip(s, idx);
	return out;
}

static const char *dtoc(const char *code, int *idx, char *out) {
	*idx = strlen(code);
	return out;
}

static char *ctoc1(const char *code, int lineno, char *out) {
	int idx = 0;
	int odx = 0;
	int post = 0;
	char scratch[3][MAX_CLINE] = {};

	skip(code, &idx);
	if (in(code, &idx, ".")) { /* A label. */
		int len = labellen(code, idx);
		OUT(out, odx, "%*.*s:\n", len, len, code + idx);
		idx += len;
	}
	skip(code, &idx);
	OUT(out, odx, "        { // %s\n", code);
	if (in(code, &idx, "=")) {
		OUT(out, odx, "%s", dtoc(code, &idx, scratch[0]));
	} else if (in(code, &idx, "trap")) {
		OUT(out, odx, "                trap(regs, T_TRAP);");
	} else if (in(code, &idx, "nop")) {
		OUT(out, odx, "                ;");
	} else if (in(code, &idx, "halt")) {
		OUT(out, odx, "                return;");
	} else if (in(code, &idx, "alloc")) {
		atoc(code, &idx, scratch[0], 0, 0);
		atoc(code, &idx, scratch[1], 1, 1);
		OUT(out, odx,
    "                uint64_t size = %s;\n"
    "                if (unlikely((DEREF(%s) = alloc(size)) == 0)) {\n"
    "                        trap(regs, T_OOM);\n"
    "                }",
		    scratch[0], scratch[1]);
	} else if (in(code, &idx, "resume")) {
		atoc(code, &idx, scratch[0], 0, 0);
		atoc(code, &idx, scratch[1], 1, 0);
		OUT(out, odx,
    "                uint64_t frame  = %s;\n"
    "                uint64_t target = %s;\n"
    "                DEREF(regs->r[R_SF]) = U64(&&_L_%04i);\n"
    "                regs->r[R_SF] = frame;\n"
    "                goto *(void *)target;",
		    scratch[0], scratch[1], lineno + 1);
		post = 1;
	} else if (in(code, &idx, "set")) {
		atoc(code, &idx, scratch[0], 0, 0);
		atoc(code, &idx, scratch[1], 1, 1);
		OUT(out, odx,
    "                uint64_t src = %s;\n"
    "                uint64_t dst = %s;\n"
    "                DEREF(dst) = src;",
		    scratch[0], scratch[1]);
	} else if (in(code, &idx, "add")) {
		atoc(code, &idx, scratch[0], 0, 0);
		atoc(code, &idx, scratch[1], 1, 0);
		atoc(code, &idx, scratch[2], 2, 1);
		OUT(out, odx,
    "                uint64_t a = %s;\n"
    "                uint64_t b = %s;\n"
    "                uint64_t c = %s;\n"
    "                DEREF(c) = a + b;",
		    scratch[0], scratch[1], scratch[2]);
	} else if (in(code, &idx, "mul")) {
		atoc(code, &idx, scratch[0], 0, 0);
		atoc(code, &idx, scratch[1], 1, 0);
		atoc(code, &idx, scratch[2], 2, 1);
		OUT(out, odx,
    "                uint64_t a = %s;\n"
    "                uint64_t b = %s;\n"
    "                uint64_t c = %s;\n"
    "                DEREF(c) = a * b;",
		    scratch[0], scratch[1], scratch[2]);
	} else if (in(code, &idx, "if0")) {
		atoc(code, &idx, scratch[0], 0, 0);
		atoc(code, &idx, scratch[1], 1, 0);
		OUT(out, odx,
    "                if (%s == 0) {\n"
    "                        goto *(void *)%s;\n"
    "                }",
		    scratch[0], scratch[1]);
	}
	skip(code, &idx);
	assert(code[idx] == 0);
	OUT(out, odx, "\n        }\n");
	if (post)
		OUT(out, odx, "_L_%04i:\n", lineno + 1);
	return out;
}

static void ctoc(const char **code) {
	for (int i = 0; code[i] != NULL; ++i) {
		char out[MAX_CLINE] = {};
		ctoc1(code[i], i, out);
		printf("%s", out);
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
			"       alloc #8 :1",
			"       set .ret :0",
			"       set sf :1/1",
			"       resume :1 .sub",
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
	prog = (struct prog){ .start = image };
	const char *as[] = {
			"       set #a :2",
			".fact",
			"       if0 :2 .end",
			"       alloc #8 :1",
			"       set sf :1/4",
			"       add :2 #ffffffffffffffff :1/2",
			"       resume :1 .fact",
			".ret   mul :2 :3 r4",
			"       if0 :4 .done",
			"       set r4 :4/3",
			"       resume :4 *:4",
			".end   set #1 :4/3",
			"       resume :4 *:4",
			".done  trap",
			"       halt",
			".data  = ac c0 1a de",
			".hello = \"Hello, world!\"",
			NULL };
	compile(&prog, as);
	dump(&prog);
	dis(&prog);
	p = (struct proc ){
		.regs = {
			.r[R_PC] = (uint64_t)prog.start,
			.r[R_SF] = (uint64_t)frame
		}
	};
	interpret(&p);
	ctoc(as);
	return 0;
}
