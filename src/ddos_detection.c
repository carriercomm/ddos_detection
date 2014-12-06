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

#include <netdb.h>

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
      "  -d NUM       Set the mode bit of DDoS detection, SYN flooding by default.\n"
      "  -e NUM       Set the number of iterations to flush the graph, 0 by default.\n"
      "  -f PATH      Set the path of CSV file to be examined.\n"
      "  -k NUM       Set the number of clusters used by k-means algorithm, 2 by default.\n"
      "  -L LEVEL     Print graphs based on given verbosity level, range 1 to 5.\n"
      "  -p NUM       Show progress - print a dot every N flows.\n"
      "  -t TIME      Set the observation time window in seconds, 1 minute by default.\n"
      "  -w TIME      Set the observation time window in seconds, 1 hour by default.\n"
      "Detection modes:\n"
      "   1) SYN flooding detection only.\n"
      "   2) Vertical port scanning detection only.\n"
      "   3) SYN flooding and vertical port scanning detection.\n"
      "   4) Vertical port scanning detection only.\n"
      "   5) SYN flooding and horizontal port scanning detection.\n"
      "   6) Vertical and horizontal port scanning detection.\n"
      "   7) All detections combined.\n";


   params = (params_t *) calloc(1, sizeof(params_t));
   if (params == NULL) {
      fprintf(stderr, "Error: Not enough memory for parameters structure.\n");
      return NULL;
   }

   params->mode = MODE_SYN_FLOODING;
   params->clusters = CLUSTERS;
   params->file_cnt = 1;
   params->flush_cnt = 1;
   params->flush_iter = FLUSH_ITER;
   params->progress = 0;
   params->level = VERBOSITY;
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
         case 'e':
            if (strlen(optarg) > NUMBER_LEN || sscanf(optarg, "%d%s", &params->flush_iter, tmp) != 1 || params->flush_iter < 0) {
              fprintf(stderr, "Error: Invalid flush iteration number.\n");
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
         case 'k':
            if (strlen(optarg) > 1 || sscanf(optarg, "%d%s", &params->clusters, tmp) != 1 || params->clusters < CLUSTERS || params->clusters > NUMBER_LEN) {
              fprintf(stderr, "Error: Invalid number of clusters to be used in k-means algorithm.\n");
              goto error;
            }
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

   if (graph->time_first == 0) {
      graph->time_first = flow->time_first;
      graph->time_last = flow->time_first + graph->params->time_window;
   }

   // Delayed flow record, skipping line.
   if (flow->time_first < graph->time_first) {
      fprintf(stderr, "Warning: Delayed flow record, parsing interrupted.\n");
      return EXIT_FAILURE;
   }

   return EXIT_SUCCESS;
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
   port_t *tmp;

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
      if (host->ports != NULL) {
         while (host->ports != NULL) {
            tmp = host->ports;
            host->ports = host->ports->next;
            free (tmp);
         }
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
   host->stat = 1;
   host->accesses = 1;
   host->ports_cnt = 0;
   host->intervals = NULL;
   host->ports = NULL;

   if ((mode & MODE_SYN_FLOODING) == MODE_SYN_FLOODING) {
      host->intervals = (intvl_t *) calloc(array_max + 1, sizeof(intvl_t));
      if (host->intervals == NULL) {
          fprintf(stderr, "Error: Not enough memory for  host structure.\n");
          return NULL;
      }
   }
   return host;
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
   int cnt, first, i, last, seconds;
   char flag;
   float pps;
   time_t diff;
   node_t *node;
   host_t *host;
   port_t *head, *port;

   if (graph->params->mode == MODE_SYN_FLOODING && flow->syn_flag != 1) {
      // SYN flag is not set, skipping line.
      return graph;
   }

   // Setting flag if time window has been reached.
   flag = 0;

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
      host->stat = 1;
      host->accesses ++;
   }

   // Completing data of ports.
   if ((graph->params->mode & MODE_SYN_FLOODING) == MODE_SYN_FLOODING) {
      // Getting indexes of the interval array.
      first = ((graph->params->time_window + (flow->time_first - graph->time_first)) / graph->params->interval) - graph->params->interval;
      last = ((graph->params->time_window + (flow->time_last - graph->time_first)) / graph->params->interval) - graph->params->interval;

      // Adding all SYN packets in the same interval.
      if (first == last) {
         host->intervals[first].syn_packets += flow->packets;
      }

      // Distributing SYN packets among various intervals using linear function.
      else {
         diff = flow->time_last - flow->time_first;
         cnt = last - first;
         pps = ((float) flow->packets) / ((float) diff);

         // Calculating the seconds residue of the first interval.
         seconds = ((first + 1) * graph->params->interval) - (flow->time_first - graph->time_first);
         host->intervals[first].syn_packets += (seconds * pps);

         // Time window reached, distributing the residue for next iteration.
         if (flow->time_last >= graph->time_last) {
            host->intervals[array_max].syn_packets += ((diff - seconds) * pps);
            flag = 1;
         }

         if (flag == 0) {
            if (cnt > 2) {
              for (i = 0; i < cnt - 2; i ++) {
                 host->intervals[first+i+1].syn_packets += (graph->params->interval * pps);
              }
            }

            // Calculating the seconds residue of the first interval.
            seconds = (flow->time_last - graph->time_first) - (last * graph->params->interval);
            host->intervals[last].syn_packets += (seconds * pps);
         }
      }
   }

   // Completing data of ports.
   if ((graph->params->mode & MODE_PORTSCAN_VER) == MODE_PORTSCAN_VER) {
      head = host->ports;

      // Adding first port to the list.
      if (head == NULL) {
            port = (port_t *) calloc(1, sizeof(port_t));
            if (port == NULL) {
                fprintf(stderr, "Error: Not enough memory for port structure.\n");
                goto error;
            }
            host->ports_cnt = 1;
            host->ports = port;
            port->port_num = flow->dst_port;
            port->accesses = 1;
            port->next = NULL;
      }

      // Adding new head destination port.
      else if (flow->dst_port < head->port_num) {
         port = (port_t *) calloc(1, sizeof(port_t));
         if (port == NULL) {
             fprintf(stderr, "Error: Not enough memory for port structure.\n");
             goto error;
         }
         host->ports_cnt ++;
         host->ports = port;
         port->port_num = flow->dst_port;
         port->accesses = 1;
         port->next = head;
      }

      // Adding destination port to the list.
      else {
         while (head != NULL) {
            // Destination port already exists, incrementing counter.
            if (flow->dst_port == head->port_num) {
               head->accesses ++;
               break;
            }

            // Adding new port to the list.
            else if ((flow->dst_port > head->port_num && head->next == NULL)
                    || (flow->dst_port > head->port_num && flow->dst_port < head->next->port_num)) {
               port = (port_t *) calloc(1, sizeof(port_t));
               if (port == NULL) {
                   fprintf(stderr, "Error: Not enough memory for port structure.\n");
                   goto error;
               }
               host->ports_cnt ++;
               port->port_num = flow->dst_port;
               port->accesses = 1;
               port->next = head->next;
               head->next = port;
               break;
            }
            head = head->next;
         }
      }
   }

   if ((graph->params->mode & MODE_PORTSCAN_HOR) == MODE_PORTSCAN_HOR) {
      fprintf(stderr, "To be completed.\n");
   }

   return graph;

   // Cleaning up after error.
   error:
      if (graph != NULL) {
         free_graph(graph);
      }
      return NULL;
}

int compare_host(const void *elem1, const void *elem2)
{
   host_t *host1, *host2;

   host1 = *(host_t * const *)elem1;
   host2 = *(host_t * const *)elem2;
   return (host2->accesses - host1->accesses);
}

void print_host(graph_t *graph, int idx, int mode)
{
   int i, pid, status;
   char ip[INET_ADDRSTRLEN], buffer[BUFFER_TMP];
   struct tm *time;
   FILE *f, *g;
   port_t *head;

   f = fopen(DATA_FILE, "w");
   if (f == NULL) {
      fprintf(stderr, "Warning: Cannot create empty data file in temporary folder, plot omitted.\n");
      return;
   }

   g = fopen(GNUPLOT, "w");
   if (f == NULL) {
      fprintf(stderr, "Warning: Cannot create gnuplot configuration folder, plot omitted.\n");
      fclose(f);
      return;
   }

   // Configuring gnuplot configuration file.
   time = localtime(&(graph->time_first));
   if (time == NULL) {
      fprintf(stderr, "Warning: Cannot convert UNIX timestamp, plot omitted.\n");
      return;
   }
   if (strftime(buffer, BUFFER_TMP, TIME_FORMAT, time) == 0) {
      fprintf(stderr, "Warning: Cannot convert UNIX timestamp, plot omitted.\n");
      return;
   }
   inet_ntop(AF_INET, &(graph->hosts[idx]->ip), ip, INET_ADDRSTRLEN);
   fprintf(g, "set terminal pngcairo font \",8\" enhanced\n"
              "set title \"Destination address: %s\\nTime first: %s\"\n"
              "unset key\n", ip, buffer);

   if (mode == MODE_SYN_FLOODING) {
      // Storing SYN flooding data.
      for (i = 0; i < array_max; i ++) {
         fprintf(f, "%d %.0lf\n", i, graph->hosts[idx]->intervals[i].syn_packets);
      }
      fclose(f);

      fprintf(g, "set xlabel \"Minute\"\n"
                 "set ylabel \"# SYN packets\"\n"
                 "set y2label \"# SYN packets\"\n"
                 "set output \"res/SYN%01d_%03d(%s).png\"\n"
                 "plot \"%s\" using 1:2 with line\n",
              graph->params->file_cnt, idx, ip, DATA_FILE);
      fclose(g);
   }

   else if (mode == MODE_PORTSCAN_VER) {
      // Storing vertical port scan data.
      head = graph->hosts[idx]->ports;
      while (head != NULL) {
         fprintf(f, "%d %u\n", head->port_num, head->accesses);
         head = head->next;
      }
      fclose(f);

      fprintf(g, "set xlabel \"Destination port\"\n"
                 "set xrange [0:%d]\n"
                 "set yrange [0:]\n"
                 "set ylabel \"# Accesses\"\n"
                 "set y2label \"# Accesses\"\n"
                 "set output \"res/VPS%01d_%03d(%s).png\"\n"
                 "plot \"%s\" using 1:2 with dots\n",
              ALL_PORTS, graph->params->file_cnt, idx, ip, DATA_FILE);
      fclose(g);
   }

   // Running gnuplot in a child process
   if ((pid = fork()) == 0) {
      if ((execl("/usr/bin/gnuplot", "gnuplot", GNUPLOT, NULL)) < 0) {
         fprintf(stderr, "Warning: Cannot run gnuplot, plot omitted.\n");
      }
   }

   // Error while forking the process
   else if (pid < 0) {
      fprintf(stderr, "Error: Cannot fork process.\n");
      return;
   }

   else {
      if (wait(&status) < 0) {
         fprintf(stderr, "Error: Child process does not respond.\n");
         return;
      }
   }
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
   graph->time_first = graph->time_last = 0;
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

void reset_graph(graph_t *graph)
{
   int i, syn_packets;
   port_t *tmp;

   if ((graph->params->mode & MODE_SYN_FLOODING) == MODE_SYN_FLOODING) {
      for (i = 0; i < graph->hosts_cnt; i ++) {
         graph->hosts[i]->stat = 0;
         syn_packets = graph->hosts[i]->intervals[array_max].syn_packets;
         memset(graph->hosts[i]->intervals, 0, array_max + 1);
         graph->hosts[i]->intervals[0].syn_packets = syn_packets;
      }
   }

   if ((graph->params->mode & MODE_SYN_FLOODING) == MODE_SYN_FLOODING) {
      for (i = 0; i < graph->hosts_cnt; i ++) {
         if (graph->hosts[i]->ports != NULL) {
            while (graph->hosts[i]->ports != NULL) {
               tmp = graph->hosts[i]->ports;
               graph->hosts[i]->ports = graph->hosts[i]->ports->next;
               free (tmp);
            }
         }
         graph->hosts[i]->stat = 0;
         graph->hosts[i]->ports_cnt = 0;
         graph->hosts[i]->ports = NULL;
      }
   }
}

void print_graph(graph_t *graph)
{
   int i, j, p, sum;
   char ip[INET_ADDRSTRLEN], name[BUFFER_TMP];
   FILE *f;
   struct hostent *he;
   port_t *head;

   sum = 0;
   p = PADDING;
   he = NULL;

   if (graph->params == NULL || graph == NULL || graph->params->level == 0) {
      return;
   }

   snprintf(name, BUFFER_TMP, "res/flows_stats_%05d.txt", graph->params->file_cnt);

   f = fopen(name, "w");
   if (f == NULL) {
      fprintf(stderr, "Warning: Cannot create empty file in given directory, output omitted.\n");
      return;
   }

   if (graph->params->level == VERBOSE_FULL) {
      fprintf(stderr, "Warning: Check for disk space, very large output may follow.\n");
   }

   for (i = 0; i < graph->hosts_cnt; i ++) {
      if (graph->hosts[i]->stat == 1) {
         sum ++;
      }
   }

   fprintf(f, "Number of active hosts:            %*d\n", p, sum);

   // Brief level
   if (graph->params->level == VERBOSE_BRIEF) {
      fclose(f);
      return;
   }

   fprintf(f, "\nK-means algorithm parameters:\n");
   fprintf(f, "* Clusters:                        %*d\n", p, graph->params->clusters);

   qsort(graph->hosts, graph->hosts_cnt, sizeof(host_t *), compare_host);

   // Printing information about hosts.
   fprintf(f, "\nHosts:\n");
   for (i = 0; i < graph->hosts_cnt; i ++) {
      if (graph->hosts[i]->stat != 0) {
         inet_ntop(AF_INET, &(graph->hosts[i]->ip), ip, INET_ADDRSTRLEN);
         fprintf(f, "* Destination IP address:          %*s\n"
                    "* Times accessed:                  %*d\n",
                 p, ip, p, graph->hosts[i]->accesses);
         if ((graph->params->mode & MODE_PORTSCAN_VER) == MODE_PORTSCAN_VER) {
            fprintf(f, "* Ports used:                      %*u\n", p, graph->hosts[i]->ports_cnt);
         }

         // Creating plot of possible DDoS attack victims.
         if (graph->params->level >= VERBOSE_ADVANCED) {
            if ((graph->params->mode & MODE_SYN_FLOODING) == MODE_SYN_FLOODING) {
               if (i < 32) {
                  print_host(graph, i, MODE_SYN_FLOODING);
               }
            }
            if ((graph->params->mode & MODE_PORTSCAN_VER) == MODE_PORTSCAN_VER) {
               if (i < 32) {
                  print_host(graph, i, MODE_PORTSCAN_VER);
               }
            }
         }

         // Translating IP address to domain name.
         if (graph->params->level >= VERBOSE_EXTRA) {
            he = gethostbyaddr(&(graph->hosts[i]->ip), sizeof(in_addr_t), AF_INET);
            if (he != NULL) {
               fprintf(f, "* Domain:                          %*s\n", p, he->h_name);
            }
         }

         // Printing information additional information from host structure, not recommended.
         if (graph->params->level == VERBOSE_FULL) {
            if ((graph->params->mode & MODE_SYN_FLOODING) == MODE_SYN_FLOODING) {
               // Printing number of SYN packets and assigned cluster in each observation interval.
               fprintf(f, "* Observation intervals:\n");
               for (j = 0; j < array_max; j ++) {
                  fprintf(f, "* \t%02d) SYN packets:           %*.0lf\n"
                             "* \t%02d) Cluster:               %*d\n",
                          j, p, graph->hosts[i]->intervals[j].syn_packets,
                          j, p, graph->hosts[i]->intervals[j].cluster);
               }
            }
            if ((graph->params->mode & MODE_PORTSCAN_VER) == MODE_PORTSCAN_VER) {
               // Printing number of SYN packets and assigned cluster in each observation interval.
               fprintf(f, "* Times port accessed:\n");
               head = graph->hosts[i]->ports;
               while (head != NULL) {
                  fprintf(f, "* \tDestination port:          %*d\n"
                             "* \tTimes accessed:            %*u\n",
                          p, head->port_num, p, head->accesses);
                  head = head->next;
               }
            }
         }
         fprintf(f, "*\n");
      }
   }

   graph->params->file_cnt ++;
   fclose(f);
}

graph_t *detection_handler(graph_t *graph)
{
   //int i;

   if ((graph->params->mode & MODE_SYN_FLOODING) == MODE_SYN_FLOODING) {
      if (graph->params->level > VERBOSITY) {
         fprintf(stderr, "Info: Starting SYN flooding detection.\n");
      }
      //for (i = 0; i < graph->hosts_cnt; i ++) {
         // TO BE DONE
      //}
   }

   if ((graph->params->mode & MODE_PORTSCAN_VER) == MODE_PORTSCAN_VER) {
      if (graph->params->level > VERBOSITY) {
         fprintf(stderr, "Info: Starting vertical port scan detection.\n");
      }
      // TODO Implement detection technique
      // graph = detect_ver_portscan(graph);
   }

   if ((graph->params->mode & MODE_PORTSCAN_HOR) == MODE_PORTSCAN_HOR) {
      if (graph->params->level > VERBOSITY) {
         fprintf(stderr, "Info: Starting horizontal port scan detection.\n");
      }
      // TODO Implement detection technique
      // graph = detect_hor_portscan(graph);
   }

   print_graph(graph);
   if (graph->params->level > VERBOSITY) {
      fprintf(stderr, "Info: Detection for given time window finished, results available.\n");
   }
   return graph;

   // Cleaning up after error.
   /*error:
      if (graph != NULL) {
         free_graph(graph);
      }
      return NULL;*/
}

graph_t *parse_data(params_t *params)
{
   int i, j, k, len, pid, pipefd[2], ret, status;
   char buffer[BUFFER_SIZE], *tmp;
   uint32_t bytes;
   uint64_t cnt_flows;
   flow_t flow;
   graph_t *graph;

   j = 0;
   k = 0;
   cnt_flows = 0;
   status = 0;
   memset(buffer, 0, BUFFER_SIZE);
   tmp = buffer;
   graph = NULL;

   if (params->mode > MODE_ALL) {
      fprintf(stderr, "Error: Unknown detection mode.\n");
      goto error;
   }

   graph = create_graph(params);
   if (graph == NULL) {
      goto error;
   }

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
               // Skipping empty line
               if (i == j) {
                  goto next;
               }
               // Skipping comment line
               if (buffer[j] == '#') {
                  goto next;
               }

               // Parsing for words.
               ret = parse_line(graph, &flow, tmp, len);
               if (ret == EXIT_SUCCESS) {
                  cnt_flows ++;
               } else {
                  goto next;
               }

               // Time window reached, starting detection.
               if (flow.time_first >= graph->time_last) {
                  if (graph->params->progress > 0) {
                     fprintf(stderr, "\n");
                  }
                  graph = detection_handler(graph);
                  if (graph == NULL) {
                     goto error;
                  }
                  if (params->flush_cnt == params->flush_iter) {
                     free_graph(graph);
                     graph = create_graph(params);
                     if (graph == NULL) {
                        goto error;
                     }
                  } else {
                     reset_graph(graph);
                     params->flush_cnt ++;
                  }
                  graph->time_first = flow.time_first;
                  graph->time_last = flow.time_first + params->time_window;
               }

               // Adding host structure to graph.
               graph = get_host(graph, &flow);
               if (graph == NULL) {
                  goto error;
               }

               if ((params->progress > 0) && (cnt_flows % params->progress == 0)) {
                fprintf(stderr, ".");
                fflush(stderr);
               }

               next:
                  j += len + 1;
                  tmp += len + 1;
            }
         }

         // Shifting remaining bytes if the line was interrupted.
         if (j != (bytes + k)) {
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

   if (graph->params->progress > 0) {
      fprintf(stderr, "\n");
   }
   fprintf(stderr,"Info: All data have been successfully processed, processing residues.\n");
   graph = detection_handler(graph);
   if (graph == NULL) {
      goto error;
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

   graph = parse_data(params);
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
