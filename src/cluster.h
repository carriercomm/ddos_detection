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
 * \brief Centroid initialization.
 * Function to set given number of centroids based on real active values
 * from the host.
 * \param[in] graph Pointer to existing graph structure.
 * \return The number of initialized centroids. 
 */
int init_cluster(graph_t *graph);

/*!
 * \brief Distance calculation.
 * Function to calculate distances to centroids for each observation.
 * \param[in] graph Pointer to existing graph structure.
 */
void distance_cluster(graph_t *graph);

/*!
 * \brief Cluster assignment.
 * Function to assign cluster to each observation based on the shortest
 * Euclidean distance to the centroid.
 * \param[in] graph Pointer to existing graph structure.
 */
void assign_cluster(graph_t *graph);

/*!
 * \brief Previous assignment.
 * Function to store last cluster assignment to be compared in the next
 * iteration of the k-means algorithm.
 * \param[in] graph Pointer to existing graph structure.
 */
void previous_cluster(graph_t *graph);

/*!
 * \brief Centroid calculation.
 * Function to recalculate position of the centroid based on the observations
 * which have been assigned to the given cluster.
 * \param[in] graph Pointer to existing graph structure.
 */
void centroid_cluster(graph_t *graph);

/*!
 * \brief Change calculation.
 * Function to calculate changes of cluster to indicate whether the algorithm
 * should continue or to be stopped.
 * \param[in] graph Pointer to existing graph structure.
 * \return Number of cluster changes.
 */
int change_cluster(graph_t *graph);

/*!
 * \brief Controlling calculation.
 * Function to reduce false positives in the the cluster based on statistical
 * methods. It reassign the false positive if needed.
 * \param[in] graph Pointer to existing graph structure.
 */
void adjust_cluster(graph_t *graph);

/*!
 * \brief Batch k-means algorithm.
 * Function to put host addresses into clusters based on batched k-means algorithm.
 * \param[in] graph Pointer to existing graph structure.
 */
void batch_cluster(graph_t *graph);

/*!
 * \brief Online k-means algorithm.
 * Function to put host addresses into clusters based on online k-means algorithm.
 * \param[in] graph Pointer to existing graph structure.
 */
void online_cluster(graph_t *graph);

#endif /* _CLUSTER_ */
