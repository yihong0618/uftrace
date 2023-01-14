#include <Python.h>

#include "uftrace.h"
#include "utils/rbtree.h"
#include "utils/symbol.h"

struct uftrace_py_state {
	PyObject *trace_func;
};

/* pointer to python tracing function (for libpython2.7) */
static PyObject *uftrace_func __attribute__((unused));

/* RB tree of python_symbol to map function name to address */
static struct rb_root name_tree = RB_ROOT;

/* simple sequence number to be used as symbol address */
static unsigned sym_num = 1;

struct uftrace_python_symbol {
	struct rb_node node;
	unsigned int addr;
	char *name;
};

static void (*cygprof_enter)(unsigned long child, unsigned long parent);
static void (*cygprof_exit)(unsigned long child, unsigned long parent);

static PyObject *uftrace_trace_python(PyObject *self, PyObject *args);

static PyMethodDef uftrace_py_methods[] = {
	{ "trace", uftrace_trace_python, METH_VARARGS,
	  PyDoc_STR("trace python function with uftrace.") },
	{ NULL, NULL, 0, NULL },
};

static void find_cygprof_funcs(const char *filename, unsigned long base_addr)
{
	struct uftrace_elf_data elf;
	struct uftrace_elf_iter iter;

	if (elf_init(filename, &elf) < 0)
		return;

	elf_for_each_shdr(&elf, &iter) {
		if (iter.shdr.sh_type == SHT_SYMTAB)
			break;
	}

	elf_for_each_symbol(&elf, &iter) {
		char *name = elf_get_name(&elf, &iter, iter.sym.st_name);

		if (!strcmp(name, "__cyg_profile_func_enter"))
			cygprof_enter = (void *)(iter.sym.st_value + base_addr);
		if (!strcmp(name, "__cyg_profile_func_exit"))
			cygprof_exit = (void *)(iter.sym.st_value + base_addr);
	}

	elf_finish(&elf);
}

static void find_libmcount_funcs(void)
{
	char *line = NULL;
	size_t len = 0;
	FILE *fp = fopen("/proc/self/maps", "r");

	if (fp == NULL)
		return;

	while (getline(&line, &len, fp) != -1) {
		unsigned long start, end;
		char prot[5];
		char path[PATH_MAX];

		if (sscanf(line, "%lx-%lx %s %*x %*x:%*x %*d %s\n", &start, &end, prot, path) != 4)
			continue;

		if (strncmp(basename(path), "libmcount", 9))
			continue;

		find_cygprof_funcs(path, start);
		break;
	}

	free(line);
	fclose(fp);
}

/* manage function name -> address (or index) */
static unsigned long find_function(struct rb_root *root, const char *name)
{
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;
	struct uftrace_python_symbol *iter, *new;
	int cmp;

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, struct uftrace_python_symbol, node);

		cmp = strcmp(iter->name, name);
		if (cmp == 0)
			return iter->addr;

		if (cmp < 0)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	new = xmalloc(sizeof(*new));
	new->name = xstrdup(name);
	new->addr = sym_num++;

	rb_link_node(&new->node, parent, p);
	rb_insert_color(&new->node, root);

	return new->addr;
}

/* resort symbol table by address */
static void sort_address(struct rb_root *root, struct uftrace_python_symbol *entry)
{
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;
	struct uftrace_python_symbol *iter;
	int cmp;

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, struct uftrace_python_symbol, node);

		cmp = iter->addr - entry->addr;
		if (cmp > 0)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	rb_link_node(&entry->node, parent, p);
	rb_insert_color(&entry->node, root);
}

static void write_symtab(const char *dirname)
{
	struct rb_node *node;
	struct rb_root addr_tree = RB_ROOT;
	struct uftrace_python_symbol *sym;
	char *filename = NULL;
	FILE *fp;

	xasprintf(&filename, "%s/%s.sym", dirname, PYTHON_MODULE_NAME);

	fp = fopen(filename, "a");
	if (fp == NULL) {
		pr_warn("writing symbol table of python program failed: %m");
		return;
	}

	/* symbol table assumes it's sorted by address */
	while (!RB_EMPTY_ROOT(&name_tree)) {
		node = rb_first(&name_tree);
		rb_erase(node, &name_tree);

		/* move it from name_tree to addr_tree */
		sym = rb_entry(node, struct uftrace_python_symbol, node);
		sort_address(&addr_tree, sym);
	}

	while (!RB_EMPTY_ROOT(&addr_tree)) {
		node = rb_first(&addr_tree);
		rb_erase(node, &addr_tree);

		sym = rb_entry(node, struct uftrace_python_symbol, node);
		fprintf(fp, "%x %c %s\n", sym->addr, 't', sym->name);

		free(sym->name);
		free(sym);
	}

	fprintf(fp, "%x %c %s\n", sym_num, 't', "__sym_end");
	fclose(fp);
}

static void init_uftrace(void)
{
	/* check if it's loaded in a uftrace session */
	if (getenv("UFTRACE_SHMEM") == NULL)
		return;

	find_libmcount_funcs();
}

#ifdef HAVE_LIBPYTHON3

/* this is called during GC traversal */
static int uftrace_py_traverse(PyObject *m, visitproc visit, void *arg)
{
	struct uftrace_py_state *state;

	state = PyModule_GetState(m);

	Py_VISIT(state->trace_func);

	return 0;
}

/* this is called before the module is deallocated */
static int uftrace_py_clear(PyObject *m)
{
	struct uftrace_py_state *state;

	state = PyModule_GetState(m);

	Py_CLEAR(state->trace_func);

	return 0;
}

static void uftrace_py_free(void *)
{
	/* do nothing for now */
}

static struct PyModuleDef uftrace_module = {
	PyModuleDef_HEAD_INIT,
	"uftrace_python",
	PyDoc_STR("C extension module to trace python functions with uftrace"),
	sizeof(struct uftrace_py_state),
	uftrace_py_methods,
	NULL, /* slots */
	uftrace_py_traverse,
	uftrace_py_clear,
	uftrace_py_free,
};

static PyObject *get_trace_function(void)
{
	PyObject *mod;
	struct uftrace_py_state *state;

	mod = PyState_FindModule(&uftrace_module);
	if (mod == NULL)
		return NULL;

	state = PyModule_GetState(mod);

	Py_INCREF(state->trace_func);
	return state->trace_func;
}

static char *get_c_string(PyObject *utf8)
{
	return (char *)PyUnicode_AsUTF8(utf8);
}

/* the name should be 'PyInit_' + <module name> */
PyMODINIT_FUNC PyInit_uftrace_python(void)
{
	PyObject *m, *d, *f;
	struct uftrace_py_state *s;

	outfp = stdout;
	logfp = stdout;

	m = PyModule_Create(&uftrace_module);
	if (m == NULL)
		return NULL;

	d = PyModule_GetDict(m);
	f = PyDict_GetItemString(d, "trace");

	/* keep the pointer to trace function as it's used as a return value */
	s = PyModule_GetState(m);
	s->trace_func = f;

	init_uftrace();
	return m;
}

#else /* HAVE_LIBPYTHON2 */

/* the name should be 'init' + <module name> */
PyMODINIT_FUNC inituftrace_python(void)
{
	PyObject *m, *d;

	outfp = stdout;
	logfp = stdout;

	m = Py_InitModule("uftrace_python", uftrace_py_methods);
	if (m == NULL)
		return;

	d = PyModule_GetDict(m);

	/* keep the pointer to trace function as it's used as a return value */
	uftrace_func = PyDict_GetItemString(d, "trace");

	init_uftrace();
}

static PyObject *get_trace_function(void)
{
	Py_INCREF(uftrace_func);
	return uftrace_func;
}

static char *get_c_string(PyObject *str)
{
	return (char *)PyString_AsString(str);
}

#endif /* HAVE_LIBPYTHON2 */

static unsigned long convert_function_addr(PyObject *frame)
{
	PyObject *code, *name, *global;
	char *func_name = NULL;
	unsigned long addr = 0;
	bool needs_free = false;

	code = PyObject_GetAttrString(frame, "f_code");
	if (code == NULL)
		return 0;

	if (PyObject_HasAttrString(code, "co_qualname"))
		name = PyObject_GetAttrString(code, "co_qualname");
	else
		name = PyObject_GetAttrString(code, "co_name");

	/* prepend module name if available */
	global = PyObject_GetAttrString(frame, "f_globals");
	if (global) {
		PyObject *mod = PyDict_GetItemString(global, "__name__");
		char *name_str = get_c_string(name);

		if (mod) {
			char *mod_str = get_c_string(mod);

			/* skip __main__. prefix for functions in the main module */
			if (strcmp(mod_str, "__main__") || !strcmp(name_str, "<module>")) {
				xasprintf(&func_name, "%s.%s", mod_str, name_str);
				needs_free = true;
			}
		}
		Py_XDECREF(mod);
		Py_DECREF(global);
	}

	if (func_name == NULL && name)
		func_name = get_c_string(name);
	if (func_name)
		addr = find_function(&name_tree, func_name);

	if (needs_free)
		free(func_name);
	Py_XDECREF(code);
	Py_XDECREF(name);
	return addr;
}

/*
 * This is the actual function when called for each function.
 */
static PyObject *uftrace_trace_python(PyObject *self, PyObject *args)
{
	PyObject *frame, *args_tuple;
	const char *event;

	if (!PyArg_ParseTuple(args, "OsO", &frame, &event, &args_tuple))
		Py_RETURN_NONE;

	if (!strcmp(event, "call")) {
		unsigned long addr;

		addr = convert_function_addr(frame);
		cygprof_enter(addr, 0);
	}
	else if (!strcmp(event, "return"))
		cygprof_exit(0, 0);

	return get_trace_function();
}

static void __attribute__((destructor)) uftrace_trace_python_finish(void)
{
	const char *dirname;

	dirname = getenv("UFTRACE_DIR");
	if (dirname == NULL)
		dirname = UFTRACE_DIR_NAME;

	write_symtab(dirname);
}
