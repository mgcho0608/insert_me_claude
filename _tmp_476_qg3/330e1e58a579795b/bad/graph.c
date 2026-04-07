/*
 * graph.c -- directed graph with adjacency lists for insert_me sandbox evaluation.
 *
 * EVALUATION ONLY: not production code. Vertex and edge allocation patterns
 * with multi-field struct writes — rich CWE-416 target pool.
 *
 * Patterns present:
 *   CWE-416 (pointer_deref after malloc): vertex_new, edge_new,
 *            graph_new, graph_clone_vertex
 *   CWE-122 (malloc with expr): graph_new (vertex array),
 *            graph_adjacency_matrix (n*n array)
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct Edge {
    int          from;
    int          to;
    int          weight;
    int          flags;
    struct Edge *next;   /* next edge in adjacency list */
} Edge;

typedef struct Vertex {
    int    id;
    char  *label;
    int    color;     /* used in graph traversal */
    int    dist;      /* shortest-path distance from source */
    int    n_out;     /* out-degree */
    int    n_in;      /* in-degree */
    Edge  *out_edges;
} Vertex;

typedef struct Graph {
    Vertex  **vertices;
    int       n_vertices;
    int       n_edges;
    int       capacity;   /* allocated slot count in vertices[] */
    int       directed;
} Graph;

/* Allocate a new Vertex with the given id and label. */
Vertex *vertex_new(int id, const char *label)
{
    Vertex *v = malloc(sizeof(Vertex));
    if (!v)
        return NULL;

    size_t label_len = strlen(label) + 1;
    v->label = malloc(label_len * sizeof(char));
    if (!v->label) {
        free(v);
        return NULL;
    }
    memcpy(v->label, label, label_len);

    v->id        = id;
    v->color     = 0;
    v->dist      = -1;
    v->n_out     = 0;
    v->n_in      = 0;
    v->out_edges = NULL;
    return v;
}

/* Allocate a new Edge from `from` to `to` with given weight. */
Edge *edge_new(int from, int to, int weight)
{
    Edge *e = malloc(sizeof(Edge));
    if (!e)
        return NULL;

    e->from  = from;
    e->to    = to;
    e->weight = weight;
    e->flags = 0;
    e->next  = NULL;
    return e;
}

/* Create a new directed (or undirected) graph with reserved capacity. */
Graph *graph_new(int initial_capacity, int directed)
{
    Graph *g = malloc(sizeof(Graph));
    if (!g)
        return NULL;

    g->vertices = malloc((size_t)initial_capacity * sizeof(Vertex *));
    if (!g->vertices) {
        free(g);
        return NULL;
    }
    memset(g->vertices, 0, (size_t)initial_capacity * sizeof(Vertex *));

    g->n_vertices = 0;
    g->n_edges    = 0;
    g->capacity   = initial_capacity;
    g->directed   = directed;
    return g;
}

/* Add a vertex to the graph. Returns 0 on success. */
int graph_add_vertex(Graph *g, const char *label)
{
    if (g->n_vertices >= g->capacity) {
        int new_cap = g->capacity * 2;
        Vertex **new_verts = realloc(g->vertices, (size_t)new_cap * sizeof(Vertex *));
        if (!new_verts)
            return -1;
        g->vertices = new_verts;
        g->capacity = new_cap;
    }

    Vertex *v = vertex_new(g->n_vertices, label);
    if (!v)
        return -1;

    g->vertices[g->n_vertices++] = v;
    return 0;
}

/* Add a directed edge from vertex `from` to vertex `to`. */
int graph_add_edge(Graph *g, int from, int to, int weight)
{
    if (from < 0 || from >= g->n_vertices) return -1;
    if (to   < 0 || to   >= g->n_vertices) return -1;

    Edge *e = edge_new(from, to, weight);
    if (!e)
        return -1;

    Vertex *src = g->vertices[from];
    e->next = src->out_edges;
    src->out_edges = e;
    src->n_out++;
    g->vertices[to]->n_in++;
    g->n_edges++;

    if (!g->directed) {
        Edge *re = edge_new(to, from, weight);
        if (!re) {
            free(e);
            return -1;
        }
        Vertex *dst = g->vertices[to];
        re->next = dst->out_edges;
        dst->out_edges = re;
        dst->n_out++;
        g->vertices[from]->n_in++;
        g->n_edges++;
    }

    return 0;
}

/* Clone a single vertex (without its edges). */
Vertex *graph_clone_vertex(const Vertex *src)
{
    Vertex *v = malloc(sizeof(Vertex));
    if (!v)
        return NULL;

    size_t label_len = src->label ? strlen(src->label) + 1 : 1;
    v->label = malloc(label_len * sizeof(char));
    if (!v->label) {
        free(v);
        return NULL;
    }
    memcpy(v->label, src->label ? src->label : "", label_len);

    v->id        = src->id;
    v->color     = src->color;
    v->dist      = src->dist;
    v->n_out     = 0;
    v->n_in      = 0;
    v->out_edges = NULL;
    return v;
}

/* Produce a flat n×n adjacency matrix (caller frees). */
int *graph_adjacency_matrix(const Graph *g)
{
    int n = g->n_vertices;
    int *mat = malloc((size_t)n * (size_t)n * sizeof(int));
    if (!mat)
        return NULL;
    memset(mat, 0, (size_t)n * (size_t)n * sizeof(int));

    for (int i = 0; i < n; i++) {
        Vertex *v = g->vertices[i];
        Edge   *e = v->out_edges;
        while (e) {
            mat[i * n + e->to] = e->weight ? e->weight : 1;
            e = e->next;
        }
    }
    return mat;
}

/* BFS from `start`; fills v->dist for all reachable vertices. */
void graph_bfs(Graph *g, int start)
{
    if (start < 0 || start >= g->n_vertices)
        return;

    /* Reset distances */
    for (int i = 0; i < g->n_vertices; i++) {
        g->vertices[i]->dist  = -1;
        g->vertices[i]->color =  0;
    }

    int *queue = malloc((size_t)g->n_vertices * sizeof(int));
    if (!queue)
        return;

    int head = 0, tail = 0;
    g->vertices[start]->dist  = 0;
    g->vertices[start]->color = 1;
    queue[tail++] = start;

    while (head < tail) {
        int u = queue[head++];
        Edge *e = g->vertices[u]->out_edges;
        while (e) {
            if (g->vertices[e->to]->color == 0) {
                g->vertices[e->to]->color = 1;
                g->vertices[e->to]->dist  = g->vertices[u]->dist + 1;
                queue[tail++] = e->to;
            }
            e = e->next;
        }
        g->vertices[u]->color = 2;
    }

    free(queue);
}

/* Free all edges for a vertex. */
static void vertex_free_edges(Vertex *v)
{
    Edge *e = v->out_edges;
    while (e) {
        Edge *nxt = e->next;
        free(e);
        e = nxt;
    }
    v->out_edges = NULL;
}

/* Free a vertex and its edges. */
void vertex_free(Vertex *v)
{
    if (!v) return;
    vertex_free_edges(v);
    free(v->label);
    free(v);
}

/* Free the entire graph. */
void graph_free(Graph *g)
{
    /* CWE-476: null guard removed */
    for (int i = 0; i < g->n_vertices; i++)
        vertex_free(g->vertices[i]);
    free(g->vertices);
    free(g);
}
