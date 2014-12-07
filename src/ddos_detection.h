/*!
 * \file ddos_detection.h
 * \brief Header file to DDoS detection system.
 * \author Jan Neuzil <neuzija1@fit.cvut.cz>
 * \author Alexandre Joubert <ajoubert@isep.fr>
 * \author Matthieu Caroy <mcaroy@isep.fr>
 * \author Boris Mineau <bmineau@isep.fr>
 * \date 2014
 */
/*
 * Copyright (C) 2014 ISEP
 *
 * LICENSE TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
 * This software is provided ``as is'', and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even
 * if advised of the possibility of such damage.
 *
 */

#ifndef _DDOS_DETECTION_
#define _DDOS_DETECTION_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/wait.h>

/*!
 * \name Default values
 * Defines macros used by p2p botnet detector.
 * \{ */
#define VERBOSITY 1 /*!< Default verbosity level. */
#define NUMBER_LEN 5 /*!< Maximal length of number for buffer. */
#define ARRAY_EXTRA 4 /*!< Extra array size for a circle buffer. */
#define PADDING 16 /*!< Padding width for log files. */

#define PROTOCOL_TCP 6 /*!< TCP protocol number. */
#define PROTOCOL_UDP 17 /*!< UDP protocol number. */

#define BUFFER_TMP 256 /*!< Size of a temporary buffer. */
#define BUFFER_SIZE 8192 /*!< Size of a buffer for reading standard input. */

#define HOSTS_INIT 32768 /*!< Init size of array with hosts. */

#define ALL_PORTS 65535 /*!< Maximum number of network ports. */

#define BITS_IP4 32 /*!< Number of bits in IPv4 address. */
#define MASK_IP4 0x80000000 /*!< Mask number for 32 bit address. */

#define FLUSH_ITER 0 /*!< Default number of iteration after the graph is flushed. */
#define ARRAY_MIN 32 /*!< Minimum number of intervals. */
#define INTERVAL 60 /*!< Default observation interval of SYN packets in seconds. */
#define PORT_WINDOW 300 /*!< Default observation port scan window in seconds before flushing ports. */
#define TIME_WINDOW 3600 /*!< Default observation time window defined in seconds. */

#define CLUSTERS 2 /*!< Default number of clusters to be used in k-means algorithm. */

#define DELIMITER ' ' /*!< Default delimiter for parsing CSV files. */
#define FILE_FORMAT "%Y-%m-%d_%H-%M" /*!< Default file name in time format. */
#define TIME_FORMAT "%a %b %d %Y %H:%M:%S" /*!< Default human readable time format. */
#define DATA_FILE "/tmp/data.txt" /*!< Data file location used by gnuplot.*/
#define GNUPLOT "/tmp/config.gpl" /*!< Gnuplot configuration file location.*/
#define OPTIONS "d:e:f:hHk:L:p:t:w:" /*!< Options for for command line. */
/*! \} */

/*!
 * \brief Verbose level enumeration.
 * Verbose level for printing data graph structure.
 */
enum verbose_level {
   VERBOSE_BRIEF = 1, /*!< Verbose level to print short brief information. */
   VERBOSE_BASIC = 2, /*!< Verbose level to print basic information about number of hosts and create plot of suspicious hosts. */
   VERBOSE_ADVANCED = 3, /*!< Verbose level to print information about every host in the graph. */
   VERBOSE_EXTRA = 4, /*!< Verbose level to print all data of every host, it can consume lot of disk memory. */
   VERBOSE_FULL = 5 /*!< Verbose level to print and translate domain name of hosts. */
};

/*!
 * \brief Mode enumeration.
 * Mode type of the DDoS detection.
 */
enum mode {
   MODE_SYN_FLOODING = 0x01, /*!< SYN flooding detection mode. */
   MODE_PORTSCAN_VER = 0x02, /*!< Portscan detection mode. */
   MODE_PORTSCAN_HOR = 0x04, /*!< Portscan detection mode. */
   MODE_ALL = 0x07, /*!< All detection modes. */
};

/*!
 * \brief Binary tree structure.
 * Structure containing pointers to left and right whether the bit
 * is 0 or 1, leafs also contains pointer to host structure.
 */
typedef struct node_t {
   struct node_t *left; /*!< Pointer to another node if result is 1. */
   struct node_t *right; /*!< Pointer to another node if result is 0. */
   void *host; /*!< Pointer to host strcuture if node is a leaf. */
} node_t;

/*!
 * \brief Interval structure
 * Structure of interval containing number of SYN packets in the given interval
 * and information of assigned cluster to determine whether the traffic in the given
 * interval is SYN flooding attack or not.
 */
typedef struct intvl_t {
    //char cluster; /*!< Flag of assigned cluster. */
    double syn_packets; /*!< Number of SYN packets. */
} intvl_t;

/*!
 * \brief Port structure
 * Structure of ports containing number of the destination port and times accesses
 * to detect if the host was under vertical port scan attack or not.
 */
typedef struct port_t {
    uint16_t port_num; /*!< Destination port number. */
    uint32_t accesses; /*!< Number of times the given address has been accessed. */
    struct port_t *next; /*!< Pointer to the next port. */
} port_t;

/*!
 * \brief Flow record structure
 * Structure containing all fields of a flow record.
 */
typedef struct flow_t {
    in_addr_t dst_ip; /*!< Destination IP address. */
    in_addr_t src_ip; /*!< Source IP address. */
    uint16_t dst_port; /*!< Destination port. */
    uint16_t src_port; /*!< Source port. */
    uint8_t protocol; /*!< Used protocol. */
    time_t time_first; /*!< Timestamp of the first packet. */
    time_t time_last; /*!< Timestamp of the last packet. */
    uint64_t bytes; /*!< Number of transmitted bytes. */
    uint32_t packets; /*!<  Number of transmitted packets. */
    uint8_t syn_flag; /*!< SYN flag. */
} flow_t;

/*!
 * \brief Local host structure.
 * Structure containing information about local host such as IP address and other
 * peers with whom was communicating during the given time period. It also contains
 * information about mutual contacts with other local hosts.
 */
typedef struct host_t {
   in_addr_t ip; /*!< IP address of the local host. */
   uint8_t stat; /*!< Host status for further examination. */
   uint32_t accesses; /*!< Number of times the given address has been accessed. */
   uint32_t ports_cnt; /*!< Number of different ports used to reach the given host. */
   struct intvl_t *intervals; /*!< Array of mutual contacts with same index as the pointers of the edges. */
   struct port_t *ports; /*!< Pointer to list of used ports structures. */
} host_t;

/*!
 * \brief Parameters structure
 * Structure of parameters containing default or set parameters during initialization
 * of module to be used in following functions.
 */
typedef struct params_t {
   int mode; /*!< Flag which type of DDoS detection mode should be used. */
   int clusters; /*!< Number of clusters to be used in k-means algorithm. */
   int flush_cnt; /*!< Counter of flush iterations. */
   int flush_iter; /*!< Number of iterations for flushing the graph. */
   int progress; /*!< Parameter for printing dots of received flows. */
   int level; /*!< Verbosity level for printing graph structure. */
   int interval; /*!< Observation interval of SYN packets in seconds. */
   int time_window; /*!< Observation time window in seconds. */
   char *file; /*!< CSV file to be processed by the algorithm. */
} params_t;


/*!
 * \brief Graph structure.
 * Structure containing pointers to allocated nodes and hosts in graph scheme
 * to be further examined.
 */
typedef struct graph_t {
   uint16_t interval_idx; /*!< Index number of given interval. */
   uint16_t interval_cnt; /*!< Number of reached intervals. */
   time_t interval_first; /*!< Given Unix timestamp of the interval begging. */
   time_t interval_last; /*!< Calculated Unix timestamp of the interval end. */
   time_t window_first; /*!< Given Unix timestamp of the time window begging. */
   time_t window_last; /*!< Calculated Unix timestamp of the time window end. */
   uint64_t hosts_cnt; /*!< Number of hosts determined by destination IP address in graph. */
   uint64_t hosts_max; /*!< Maximum number of hosts in graph. */
   struct params_t *params; /*!< Pointer to structure with all initialized parameters. */
   struct node_t *root; /*!< Pointer to root of binary tree with all local IPv4 addresses. */
   struct host_t **hosts; /*!< Pointer to array of hosts. */
} graph_t;

/*!
 * \brief Parameters initialization.
 * Function to initialize parameters with default values and parse parameters
 * given in command line.
 * \param[in] argc Number of given parameters.
 * \param[in] argv Array of given parameters.
 * \return Pointer to allocated structure with initialized parameters.
 */
params_t *params_init(int argc, char **argv);

/*!
 * \brief Parsing function.
 * Function to parse given line into tokens based on given delimeter.
 * \param[in,out] string Current pointer to token in line.
 * \param[in,out] len Current remaining characters in line.
 * \return Pointer to the beginning of the token, NULL for empty value.
 */
char *get_token(char **string, int *len);

/*!
 * \brief Parsing function.
 * Function to parse given line to tokens and convert them into values
 * of the flow record structure.
 * \param[in] graph Pointer to existing graph structure.
 * \param[in] flow Pointer to flow record structure.
 * \param[in] line Pointer to string with line to be parsed.
 * \param[in] len Length of the line in bytes.
 * \return EXIT_SUCCESS on success, otherwise EXIT_FAILURE.
 */
int parse_line(graph_t *graph, flow_t *flow, char *line, int len);

/*!
 * \brief Creating IPv4 host function.
 * Function to create or search IPv4 address node in binary tree.
 * \param[in] ip IPv4 address to add into binary tree.
 * \param[in] root Root of IPv4 binary tree.
 * \return Pointer to belonging node on success, otherwise NULL.
 */
node_t *create_node(in_addr_t ip, node_t *root);

/*!
 * \brief Searching IPv4 host function.
 * Function to search IPv4 address in binary tree.
 * \param[in] ip IPv4 address to be searched in binary tree.
 * \param[in] root Root of IPv4 binary tree.
 * \return Pointer to belonging node on success, otherwise NULL.
 */
node_t *search_node(in_addr_t ip, node_t *root);

/*!
 * \brief Cleaning function.
 * Function to free all allocated memory for binary tree structure
 * using recursion. At the end, it also free all associated local host structure.
 * \param[in] node Node in binary tree to be deleted.
 */
void delete_node(node_t *node);

/*!
 * \brief Allocating host function.
 * Function to allocate new host to graph structure and return a pointer
 * to newly created host.
 * \param[in] ip IP address of new the host.
 * \param[in] mode Mode type of the DDoS detection.
 * \return Pointer to newly created host, otherwise NULL.
 */
host_t *create_host(in_addr_t ip, int mode);

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
 * Function to compare two host structure based on times of accesses.
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

/*!
 * \brief Detection handler
 * Function to decide which detection mode and algorithm will be used
 * based on initialized parameters given in command line.
 * \param[in] graph Pointer to existing graph structure.
 * \return Pointer to graph structure on success, otherwise NULL.
 */
graph_t *detection_handler(graph_t *graph);

/*!
 * \brief Parsing data function
 * Function to parse data using forking process through pipe. It opens a pipe
 * to redirect standard output which receives all desired data. It creates a new graph
 * structure which is filled with the parsed data. After a time window is reached,
 * the detection handler is launched.
 * \param[in] params Pointer to structure with all initialized parameters.
 * \return Pointer to graph structure on success, otherwise NULL.
 */
graph_t *parse_data(params_t *params);

/*!
 * \brief Main function.
 * Main function to parse given arguments and run the DDoS detection system.
 * \param[in] argc Number of given parameters.
 * \param[in] argv Array of given parameters.
 * \return EXIT_SUCCESS on success, otherwise EXIT_FAILURE.
 */
int main(int argc, char **argv);

#endif /* _DDOS_DETECTION_ */
