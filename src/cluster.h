/*!
 * \file cluster.h
 * \brief Header file to detection logic library.
 * \author Jan Neuzil <neuzija1@fit.cvut.cz>
 * \date 2014
 */
/*
 * Copyright (C) 2014 ISEP
 */

#ifndef _CLUSTER_
#define _CLUSTER_

#include "graph.h"

/*!
 * \brief Allocating cluster function.
 * Function to allocate clusters to graph structure and return a pointer
 * to newly created clusters.
 * \param[in] params Pointer to structure with all initialized parameters.
 * \return Pointer to newly created clusters, otherwise NULL.
 */
cluster_t **create_cluster(params_t *params);

/*!
 * \brief Deallocating cluster function.
 * Function to free cluster structures with all associated allocations.
 * \param[in] clusters Pointer to existing cluster structures.
 * \param[in] k Number of clusters to be freed.
 */
void free_cluster(cluster_t **clusters, int k);

/*!
 * \brief K-means function
 * Function to put host addresses into clusters based on k-means algorithm.
 * \param[in] graph Pointer to existing graph structure.
 * \return Pointer to graph structure on success, otherwise NULL.
 */
graph_t *assign_cluster(graph_t *graph);

#endif /* _CLUSTER_ */
