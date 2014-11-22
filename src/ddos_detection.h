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
#include <getopt.h>
#include <netinet/in.h>

/*!
 * \name Default values
 * Defines macros used by p2p botnet detector.
 * \{ */
#define NUMBER_LEN 5 /*< Maximal length of number for buffer. */
#define PADDING 16 /*< Padding width for log files. */

#define PROTOCOL_TCP 6 /*< TCP protocol number. */
#define PROTOCOL_UDP 17 /*< UDP protocol number. */

#define BUFFER_TMP 256 /*< Size of a temporary buffer. */

#define HOSTS_INIT 32768 /*< Init size of array with hosts. */

#define BITS_IP4 32 /*< Number of bits in IPv4 address. */
#define MASK_IP4 0x80000000 /*< Mask number for 32 bit address. */

#define INTERVAL 60 /*< Default observation interval of SYN packets in seconds. */
#define TIME_WINDOW 3600 /*< Default observation time window defined in seconds. */

#define DELIMITER " " /*< Default delimiter for parsing CSV files. */
#define OPTIONS "d:f:hHL:p:t:w:" /*< Options for for command line. */
/*! \} */

/*!
 * \brief Mode enumeration.
 * Mode type of the DDoS detection.
 */
enum mode {
   MODE_SYN_FLOODING = 1, /*!< SYN flooding detection mode. */
   HOST_PORTSCAN_VER = 2, /*!< Portscan detection mode. */
   HOST_PORTSCAN_HOR = 3, /*!< Portscan detection mode. */
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
 * \brief Parameters structure
 * Structure of parameters containing default or set parameters during initialization
 * of module to be used in following functions.
 */
typedef struct params_t {
   int mode; /*!< Flag which type od DDoS detection mode should be used. */
   int progress; /*!< Parameter for printing dots of received flows. */
   int level; /*!< Verbosity level for printing graph structure. */
   int interval; /*!< Observation interval of SYN packets in seconds. */
   int time_window; /*!< Observation time window in seconds. */
   char *file; /*!< CSV file to be processed by the algorithm. */
} params_t;

/*!
 * \brief Local host structure.
 * Structure containing information about local host such as IP address and other
 * peers with whom was communicating during the given time period. It also contains
 * information about mutual contacts with other local hosts.
 */
typedef struct host_t {\
   in_addr_t ip; /*!< IP address of the local host. */
   uint8_t stat; /*!< Host status for further examination. */
   uint32_t *syn_packets; /*!< Array of mutual contacts with same index as the pointers of the edges. */
} host_t;

/*!
 * \brief Graph structure.
 * Structure containing pointers to allocated nodes and hosts in graph scheme
 * to be further examined.
 */
typedef struct graph_t {
   uint64_t hosts_cnt; /*!< Number of hosts determined by destination IP address in graph. */
   uint64_t hosts_max; /*!< Maximum number of hosts in graph. */
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
 * \brief Main function.
 * Main function to parse given arguments and run the DDoS detection system.
 * \param[in] argc Number of given parameters.
 * \param[in] argv Array of given parameters.
 * \return EXIT_SUCCESS on success, otherwise EXIT_FAILURE.
 */
int main(int argc, char **argv);

#endif /* _DDOS_DETECTION_ */
