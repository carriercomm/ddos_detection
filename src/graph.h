/*!
 * \file graph.h
 * \brief Header file to graph functions library.
 * \author Jan Neuzil <neuzija1@fit.cvut.cz>
 * \date 2014
 */
/*
 * Copyright (C) 2014 ISEP
 */

#ifndef _GRAPH_
#define _GRAPH_

#include "host.h"
#include "cluster.h"

/*!
 * \brief Allocating graph function.
 * Function to allocate data structure of nodes and hosts.
 * \param[in] params Pointer to structure with all initialized parameters.
 * \return graph Pointer to allocated graph structure.
 */
graph_t *create_graph(params_t *params);

/*!
 * \brief Deallocating graph function.
 * Function to free data structure of nodes and hosts.
 * \param[in] graph Pointer to existing graph structure.
 */
void free_graph(graph_t *graph);

/*!
 * \brief Reseting graph function
 * Function to reset graph structure and transfer all the residues
 * to the next iteration of a time window.
 * \param[in] graph Pointer to existing graph structure.
 */
void reset_graph(graph_t *graph);

/*!
 * \brief Statistics graph function.
 * Function to print all statistics about hosts in graph into a file or create
 * a configuration for making a plot based on verbosity level.
 * \param[in] graph Pointer to existing graph structure.
 */
void print_graph(graph_t *graph);

#endif /* _GRAPH_ */
