/*!
 * \file ddos_detection.c
 * \brief DDoS detection system using clustering analysis.
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

#include "ddos_detection.h"

int array_max; /*!< Global maximum size of SYN packets array. */

params_t *params_init(int argc, char **argv)
{
   char *description, opt, usage[BUFFER_TMP], tmp[BUFFER_TMP];
   params_t *params;

   description =
      "DDoS Detection\n"
      "Module for detecting and analyzing potential DDoS attacks in computer networks.\n"
      "Special parameters:\n"
      "  -d NUM       Set the mode of DDoS detection, SYN flooding by default.\n"
      "  -f PATH      Set the path of CSV file to be examined.\n"
      "  -L LEVEL     Print graphs based on given verbosity level, range 1 to 5.\n"
      "  -p NUM       Show progress - print a dot every N flows.\n"
      "  -t TIME      Set the observation time window in seconds, 1 minute by default.\n"
      "  -w TIME      Set the observation time window in seconds, 1 hour by default.\n"
      "Detection modes:\n"
      "   1) SYN flooding detection\n"
      "   2) Horizontal port scanning detection\n"
      "   3) Vertical port scanning detection\n";


   params = (params_t *) calloc(1, sizeof(params_t));
   if (params == NULL) {
      fprintf(stderr, "Error: Not enough memory for parameters structure.\n");
      return NULL;
   }

   params->mode = MODE_SYN_FLOODING;
   params->progress = 0;
   params->level = 0;
   params->interval = INTERVAL;
   params->time_window = TIME_WINDOW;
   params->file = NULL;

   snprintf(usage, BUFFER_TMP, "Usage: %s [OPTION]...\nTry `%s -h' for more information.\n", argv[0], argv[0]);

   while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
      switch (opt) {
         case 'd':
            if (strlen(optarg) > 1 || sscanf(optarg, "%d%s", &params->mode, tmp) != 1 || params->mode < 0) {
              fprintf(stderr, "Error: Invalid detection mode number.\n");
              goto error;
            }
            break;
         case 'f':
            params->file = optarg;
            break;
         case 'h':
            fprintf(stderr, "%s\n", description);
            break;
         case 'H':
            fprintf(stderr, "%s\n", description);
            break;
         case 'L':
            if (strlen(optarg) > 1 || sscanf(optarg, "%d%s", &params->level, tmp) != 1 || params->level < 0 || params->level > NUMBER_LEN) {
              fprintf(stderr, "Error: Invalid verbosity level.\n");
              goto error;
            }
            break;
         case 'p':
            if (strlen(optarg) > NUMBER_LEN || sscanf(optarg, "%d%s", &params->progress, tmp) != 1 || params->progress < 0) {
              fprintf(stderr, "Error: Invalid progress dot number.\n");
              goto error;
            }
            break;
         case 't':
            if (strlen(optarg) > NUMBER_LEN || sscanf(optarg, "%d%s", &params->interval, tmp) != 1 || params->interval <= 0) {
              fprintf(stderr, "Error: Invalid SYN packets observation interval.\n");
              goto error;
            }
            break;
         case 'w':
            if (strlen(optarg) > NUMBER_LEN || sscanf(optarg, "%d%s", &params->time_window, tmp) != 1 || params->time_window <= 0) {
              fprintf(stderr, "Error: Invalid observation time window.\n");
              goto error;
            }
            break;
         default:
            fprintf(stderr, "Error: Too many arguments.\n");
            fprintf(stderr, "%s", usage);
            goto error;
      }
   }

   // Determining maximum number for SYN packets array based on time window and observation intervals.
   array_max = params->time_window / params->interval;
   if (array_max <= 1) {
      fprintf(stderr, "Error: Time window cannot be less or equal than observation interval.\n");
      goto error;
   }

   return params;

   // Cleaning up after error.
   error:
      if (params != NULL) {
         free(params);
      }
      return NULL;
}

node_t *create_node(in_addr_t ip, node_t *root)
{
   int i;
   uint32_t mask;
   node_t *node, *tmp;

   mask = MASK_IP4;
   node = root;

   for (i = 0; i < BITS_IP4; i ++) {
      if (ip & mask) {
         // Creating new node to the left.
         if (node->left == NULL) {
            tmp = (node_t *) calloc(1, sizeof(node_t));
            if (tmp == NULL) {
               fprintf(stderr, "Error: Not enough memory for node structure.\n");
               return NULL;
            }
            node->left = tmp;
            node = tmp;
         }
         // Continuing in binary tree.
         else {
            node = node->left;
         }
      }

      else {
         // Creating new node to the right.
         if (node->right == NULL) {
            tmp = (node_t *) calloc(1, sizeof(node_t));
            if (tmp == NULL) {
               fprintf(stderr, "Error: Not enough memory for node structure.\n");
               return NULL;
            }
            node->right = tmp;
            node = tmp;
         }
         // Continuing in binary tree.
         else {
            node = node->right;
         }
      }

      // Pushing one bit to the left.
      ip <<= 1;
   }

   return node;
}

node_t *search_node(in_addr_t ip, node_t *root)
{
   int i;
   uint32_t mask;
   node_t *node;

   mask = MASK_IP4;
   node = root;

   for (i = 0; i < BITS_IP4; i ++) {
      if (ip & mask) {
         // Host does not exist.
         if (node->left == NULL) {
            return NULL;
         }
         // Continuing in binary tree.
         else {
            node = node->left;
         }
      }
      else {
         // Host does not exist.
         if (node->right == NULL) {
            return NULL;
         }
         // Continuing in binary tree.
         else {
            node = node->right;
         }
      }

      // Pushing one bit to the left.
      ip <<= 1;
   }

   return node;
}

void delete_node(node_t *node)
{
    // Deleting siblings to the left if exist.
    if (node->left != NULL) {
       delete_node(node->left);
    }

    // Deleting siblings to the right if exist.
    if (node->right != NULL) {
       delete_node(node->right);
    }

    // Deleting host structure if exists.
    if (node->host != NULL) {
       host_t *host = (host_t *) node->host;
       if (host->intervals != NULL) {
          free(host->intervals);
       }
       free(host);
    }

    // Deleting current node.
    free(node);
}

host_t *create_host(in_addr_t ip, int mode)
{
   host_t *host;

   host = (host_t *) calloc(1, sizeof(host_t));
   if (host == NULL) {
       fprintf(stderr, "Error: Not enough memory for host structure.\n");
       return NULL;
   }
   host->ip = ip;
   host->stat = 0;
   host->intervals = NULL;

   if (mode == MODE_SYN_FLOODING) {
      host->intervals = (intvl_t *) calloc(array_max, sizeof(intvl_t));
      if (host->intervals == NULL) {
          fprintf(stderr, "Error: Not enough memory for  host structure.\n");
          return NULL;
      }
   }
   return host;
}

graph_t *create_graph(params_t *params)
{
   graph_t *graph;

   graph = (graph_t *) calloc(1, sizeof(graph_t));
   if (graph == NULL) {
      fprintf(stderr, "Error: Not enough memory for graph structure.\n");
      return NULL;
   }

   // Initializing structure.
   graph->hosts_cnt = 0;
   graph->hosts_max = HOSTS_INIT;
   graph->params = params;
   graph->root = NULL;
   graph->hosts = NULL;

   graph->root = (node_t *) calloc(1, sizeof(node_t));
   if (graph->root == NULL) {
      fprintf(stderr, "Error: Not enough memory for node structure.\n");
      goto error;
   }

   graph->hosts = (host_t **) calloc(graph->hosts_max, sizeof(host_t *));
   if (graph->hosts == NULL) {
      fprintf(stderr, "Error: Not enough memory for hosts array.\n");
      goto error;
   }

   return graph;

   // Cleaning up after error.
   error:
      free_graph(graph);
      return NULL;
}

void free_graph(graph_t *graph)
{
   if (graph->root != NULL) {
      delete_node(graph->root);
   }
   if (graph->hosts != NULL) {
      free(graph->hosts);
   }
   if (graph != NULL) {
      free(graph);
   }
}

char *get_token(char **string, int *len)
{
   int i;
   char *tmp;

   tmp = *string;
   for (i = 0; i < *len; i ++) {

      if (tmp[i] == DELIMITER) {
         tmp[i] = 0;
         *string += i + 1;
         *len -= i + 1;
         if (i == 0) {
            return NULL;
         } else {
            return tmp;
         }
      }
   }
   *len -= i;
   return tmp;
}

int parse_line(graph_t *graph, flow_t *flow, char *line, int len)
{
   char *bytes, *dst_ip, *dst_port, *packets, *protocol, *src_ip, *src_port, *syn_flag, *time_first, *time_last;

   // Retrieving tokens.
   dst_ip = get_token(&line, &len);
   if (dst_ip == NULL) {
      fprintf(stderr, "Warning: Missing destination IP address, parsing interrupted.\n");
      return EXIT_FAILURE;
   }
   if (inet_pton(AF_INET, dst_ip, &(flow->dst_ip)) != 1) {
         fprintf(stderr, "Warning: Cannot convert string to destination IP address, parsing interrupted.\n");
         return EXIT_FAILURE;
   }

   src_ip = get_token(&line, &len);
   if (src_ip == NULL) {
      fprintf(stderr, "Warning: Missing source IP address, parsing interrupted.\n");
      return EXIT_FAILURE;
   }
   if (inet_pton(AF_INET, src_ip, &(flow->src_ip)) != 1) {
         fprintf(stderr, "Warning: Cannot convert string to source IP address, parsing interrupted.\n");
         return EXIT_FAILURE;
   }

   dst_port = get_token(&line, &len);
   if (dst_port == NULL) {
      fprintf(stderr, "Warning: Missing destination port, parsing interrupted.\n");
      return EXIT_FAILURE;
   }
   flow->dst_port = atoi(dst_port);

   src_port = get_token(&line, &len);
   if (src_port == NULL) {
      fprintf(stderr, "Warning: Missing source port, parsing interrupted.\n");
      return EXIT_FAILURE;
   }
   flow->src_port = atoi(src_port);

   protocol = get_token(&line, &len);
   if (protocol == NULL) {
      fprintf(stderr, "Warning: Missing used protocol, parsing interrupted.\n");
      return EXIT_FAILURE;
   }
   flow->protocol = atoi(protocol);

   time_first = get_token(&line, &len);
   if (time_first == NULL) {
      fprintf(stderr, "Warning: Missing time of the first packet, parsing interrupted.\n");
      return EXIT_FAILURE;
   }
   flow->time_first = atoi(time_first);

   // Unknown field, skipping token.
   get_token(&line, &len);

   time_last = get_token(&line, &len);
   if (time_last == NULL) {
      fprintf(stderr, "Warning: Missing time of the last packet, parsing interrupted.\n");
      return EXIT_FAILURE;
   }
   flow->time_last = atoi(time_last);

   bytes = get_token(&line, &len);
   if (bytes == NULL) {
      fprintf(stderr, "Warning: Missing number of transmitted bytes, parsing interrupted.\n");
      return EXIT_FAILURE;
   }
   flow->bytes = atoi(bytes);

   packets = get_token(&line, &len);
   if (packets == NULL) {
      fprintf(stderr, "Warning: Missing number of transmitted packets, parsing interrupted.\n");
      return EXIT_FAILURE;
   }
   flow->packets = atoi(packets);

   syn_flag = get_token(&line, &len);
   if (syn_flag == NULL) {
      fprintf(stderr, "Warning: Missing SYN flag, parsing interrupted.\n");
      return EXIT_FAILURE;
   }
   flow->syn_flag = atoi(syn_flag);

   return EXIT_SUCCESS;
}

host_t **add_host(host_t **hosts, host_t *host, uint64_t *hosts_cnt, uint64_t *hosts_max)
{
   // Reallocating array if needed.
   if (*hosts_cnt == *hosts_max) {
      *hosts_max *= 2;
      if (*hosts_max == 0) {
         fprintf(stderr, "Warning: Too many hosts in graph, next time it might overflow.\n");
         *hosts_max -= 1;
      }
      host_t **tmp = (host_t **) realloc(hosts, (*hosts_max) * sizeof(host_t *));
      if (tmp == NULL) {
         fprintf(stderr, "Error: Not enough memory for hosts array.\n");
         free(hosts);
         return NULL;
      }
      hosts = tmp;
   }

   // Adding new host to array of hosts and updating counter.
   hosts[(*hosts_cnt)++] = host;
   return hosts;
}

graph_t *get_host(graph_t *graph, flow_t *flow)
{
   node_t *node;
   host_t *host;
   
   if (graph->params->mode == MODE_SYN_FLOODING && flow->syn_flag != 1) {
      // SYN flag is not set, skipping line.
      return graph;
   }

   // Finding host with destination IP address.
   node = create_node(flow->dst_ip, graph->root);

   // Creating new host with destination address if not present.
   if (node->host == NULL) {
      host = create_host(flow->dst_ip, graph->params->mode);
      if (host == NULL) {
         goto error;
      }
      node->host = host;
      graph->hosts = add_host(graph->hosts, host, &(graph->hosts_cnt), &(graph->hosts_max));
      if (graph->hosts == NULL) {
         goto error;
      }
   } else {
      host = (host_t *) node->host;
   }


   if (graph->params->mode == MODE_SYN_FLOODING) {
      //fprintf(stderr, "To be completed.\n");

      return graph;
   }

   // TODO Complete other modes of detection.
   else if (graph->params->mode == MODE_PORTSCAN_VER) {
      fprintf(stderr, "To be completed.\n");

      return graph;
   }

   else {
      fprintf(stderr, "To be completed.\n");

      return graph;
   }

   // Cleaning up after error.
   error:
      if (graph != NULL) {
         free_graph(graph);
      }
      return NULL;
}

graph_t *parse_data(graph_t *graph)
{
   int i, j, k, len, pid, pipefd[2], ret, status;
   char buffer[BUFFER_SIZE], *tmp;
   uint32_t bytes;
   uint64_t cnt_flows;
   flow_t flow;

   j = 0;
   k = 0;
   cnt_flows = 0;
   status = 0;
   tmp = buffer;

   // Creating pipe for standard output.
   if (pipe(pipefd) != 0) {
      fprintf(stderr, "Error: Cannot create a pipe.\n");
      goto error;
   }

   // Forking process to receive data.
   if ((pid = fork()) == 0) {
      close(pipefd[0]);

      dup2(pipefd[1], 1);

      close(pipefd[1]);

      // Opening file with flows data.
      if (graph->params->file != NULL) {
         if ((execl("/bin/cat", "cat", graph->params->file, NULL)) < 0) {
            fprintf(stderr, "Error: Cannot open given file.\n");
            goto error;
         }
      }

      // Getting data from standard input.
      else {
         pipefd[0] = STDIN_FILENO;
      }
   }

   // Error while forking the process
   else if (pid < 0) {
      fprintf(stderr, "Error: Cannot fork process.\n");
      goto error;
   }

   // Parent process
   else {
      close(pipefd[1]);

      // Reading whole output.
      while ((bytes = read(pipefd[0], tmp, BUFFER_SIZE - k)) != 0) {

         // Parsing for lines
         j = 0;
         tmp = buffer;
         for (i = 0; i < bytes + k; i ++) {

            // Parsing line.
            if (buffer[i] == '\n') {
               len = i - j;
               buffer[i] = 0;
               // Skipping comment line
               if (buffer[j] == '#') {
                  goto next;
               }

               // Parsing for words.
               ret = parse_line(graph, &flow, tmp, len);
               if (ret == EXIT_SUCCESS) {
                  cnt_flows ++;
               }

               // Adding host structure to graph.
               graph = get_host(graph, &flow);
               if (graph == NULL) {
                  goto error;
               }

               if (graph->params->progress > 0 && cnt_flows % graph->params->progress == 0) {
                fprintf(stderr, ".");
                fflush(stderr);
               }

               next:
                  j += len + 1;
                  tmp += len + 1;
            }
         }

         // Shifting remaining bytes if the line was interrupted.
         if (j != bytes) {
            len = bytes + k - j;
            memcpy(buffer, tmp, len);
            tmp = buffer;
            tmp += len;
            k = len;
         } else {
            k = 0;
            tmp = buffer;
         }
      }

      // Waiting for child.
      close(pipefd[0]);
      if (wait(&status) < 0) {
         fprintf(stderr, "Error: Child process does not respond.\n");
         goto error;;
      }
   }

   if (graph->params->level > 0) {
      fprintf(stderr,"Info: All data have been successfully parsed and stored into memory.\n");
   }

   return graph;

   // Cleaning up after error.
   error:
      if (graph != NULL) {
         free_graph(graph);
      }
      return NULL;
}

int detect_syn_flooding(graph_t *graph)
{

   return EXIT_SUCCESS;
}

graph_t *detection_handler(params_t *params)
{
   int ret;
   graph_t *graph;

   graph = create_graph(params);
   if (graph == NULL) {
      goto error;
   }

   graph = parse_data(graph);
   if (graph == NULL) {
      goto error;
   }

   if (params->mode == MODE_SYN_FLOODING) {
      if (params->level != 0) {
         fprintf(stderr, "Info: Starting SYN flooding detection.\n");
      }
      ret = detect_syn_flooding(graph);
      if (ret == EXIT_FAILURE) {
         goto error;
      }
   }

   else if (params->mode == MODE_PORTSCAN_VER) {
      if (params->level != 0) {
         fprintf(stderr, "Info: Starting vertical port scan detection.\n");
      }
      // TODO Implement detection technique
      // graph = detect_ver_portscan(graph);
   }

   else if (params->mode == MODE_PORTSCAN_HOR) {
      if (params->level != 0) {
         fprintf(stderr, "Info: Starting horizontal port scan detection.\n");
      }
      // TODO Implement detection technique
      // graph = detect_hor_portscan(graph);
   }

   else {
      if (params->level != 0) {
         fprintf(stderr, "Error: Unknown detection mode.\n");
      }
   }

   return graph;

   // Cleaning up after error.
   error:
      if (graph != NULL) {
         free_graph(graph);
      }
      return NULL;
}

int main(int argc, char **argv)
{
   int failure;
   params_t *params;
   graph_t *graph;

   failure = 0;
   
   // Parsing input parameters.
   params = params_init(argc, argv);
   if (params == NULL) {
      failure = 1;
      goto cleanup;
   }

   graph = detection_handler(params);
   if (graph == NULL) {
      failure = 1;
      goto cleanup;
   }

   // Cleaning up allocated structures.
   cleanup:
      if (params != NULL) {
         free(params);
      }
      if (graph != NULL) {
         free_graph(graph);
      }

   // Ending with failure.
   if (failure == 1) {
      return EXIT_FAILURE;
   }

   // Ending without failure.
   else {
      return EXIT_SUCCESS;
   }
}
