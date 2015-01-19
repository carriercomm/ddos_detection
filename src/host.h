/*!
 * \file host.h
 * \brief Header file to host functions library.
 * \author Jan Neuzil <neuzija1@fit.cvut.cz>
 * \date 2014
 */
/*
 * Copyright (C) 2014 ISEP
 */

#ifndef _HOST_
#define _HOST_

#include "main.h"
#include "graph.h"

/*!
 * \brief Reseting ports function
 * Function to reset port array of structures after the array has been sorted.
 * \param[in,out] ports Pointer to existing port array of structures.
 */
void reset_port(port_t ports[ALL_PORTS]);

/*!
 * \brief Creating network port function.
 * Function to create or search network port node in binary tree.
 * \param[in] port Network port to add into binary tree.
 * \param[in] root Root of port binary tree.
 * \return Pointer to belonging node on success, otherwise NULL.
 */
node_t *search_port(uint16_t port, node_t *root);

/*!
 * \brief Cleaning function.
 * Function to free all allocated memory for binary tree structure
 * using recursion. At the end, it also free all associated port structure.
 * \param[in] node Node in binary tree to be freed.
 */
void free_port(node_t *node);

/*!
 * \brief Adding port function.
 * Function to add port to array of ports.
 * It also reallocates the array if needed.
 * \param[in,out] ports Array of pointers to the ports.
 * \param[in] port Pointer to structure to be added to the array.
 * \param[in,out] ports_cnt Number of ports in the array.
 * \param[in,out] ports_max Maximum number of ports in the array.
 * \return Pointer to array of ports on success, otherwise NULL.
 */
port_t **add_port(port_t **ports, port_t *port, uint16_t *ports_cnt, uint16_t *ports_max);

/*!
 * \brief Comparing function.
 * Function to compare two port structures based on times of accesses.
 * \param[in] elem1 Pointer to the first element to be compared.
 * \param[in] elem2 Pointer to the second element to be compared.
 * \return Number indicating greater, equal or less sign.
 */
int compare_port(const void *elem1, const void *elem2);

/*!
 \brief Allocating extra function
 * Function to allocate new extra information structure to a given host
 * and return a pointer to the allocated structure.
 * \return Pointer to newly created structure, otherwise NULL.
 */
extra_t *create_extra();

/*!
 * \brief Allocating host function.
 * Function to allocate new host to graph structure and return a pointer
 * to newly created host.
 * \param[in] ip IP address of new the host.
 * \param[in] params Pointer to structure with all initialized parameters.
 * \return Pointer to newly created host, otherwise NULL.
 */
host_t *create_host(in_addr_t ip, params_t *params);

/*!
 * \brief Creating IPv4 host function.
 * Function to create or search IPv4 address node in binary tree.
 * \param[in] ip IPv4 address to add into binary tree.
 * \param[in] root Root of IPv4 binary tree.
 * \return Pointer to belonging node on success, otherwise NULL.
 */
node_t *search_host(in_addr_t ip, node_t *root);

/*!
 * \brief Cleaning function.
 * Function to free all allocated memory for binary tree structure
 * using recursion. At the end, it also free all associated host structure.
 * \param[in] node Node in binary tree to be freed.
 */
void free_host(node_t *node);

/*!
 * \brief Adding host function.
 * Function to add host to array of hosts.
 * It also reallocates the array if needed.
 * \param[in,out] hosts Array of pointers to the hosts.
 * \param[in] host Pointer to structure to be added to the array.
 * \param[in,out] hosts_cnt Number of hosts in the array.
 * \param[in,out] hosts_max Maximum number of hosts in the array.
 * \return Pointer to array of hosts on success, otherwise NULL.
 */
host_t **add_host(host_t **hosts, host_t *host, uint64_t *hosts_cnt, uint64_t *hosts_max);

/*!
 * \brief Adding host function
 * Function to add given flow record to graph of hosts based on given
 * destination IP address as the main identifier.
 * \param[in] flow Pointer to flow record structure.
 * \param[in] graph Pointer to existing graph structure.
 * \return Pointer to graph structure on success, otherwise NULL.
 */
graph_t *get_host(graph_t *graph, flow_t *flow);

/*!
 * \brief Comparing function.
 * Function to compare two host structures based on times of accesses.
 * \param[in] elem1 Pointer to the first element to be compared.
 * \param[in] elem2 Pointer to the second element to be compared.
 * \return Number indicating greater, equal or less sign.
 */
int compare_host(const void *elem1, const void *elem2);

/*!
 * \brief Plotting function
 * Function to create a plot from the host structure to show
 * the anomaly in retrived data.
 * \param[in] graph Pointer to existing graph structure.
 * \param[in] idx Index of a host to be plotted.
 * \param[in] mode Type of DDoS detection mode.
 */
void print_host(graph_t *graph, int idx, int mode);

#endif /* _HOST_ */
