/*!
 * \file graph.c
 * \brief Graph functions library.
 * \author Jan Neuzil <neuzija1@fit.cvut.cz>
 * \date 2014
 */
/*
 * Copyright (C) 2014 ISEP
 */

#include "graph.h"

graph_t *create_graph(params_t *params)
{
   graph_t *graph;

   graph = (graph_t *) calloc(1, sizeof(graph_t));
   if (graph == NULL) {
      fprintf(stderr, "Error: Not enough memory for graph structure.\n");
      return NULL;
   }

   // Initializing structure.
   graph->interval_idx = graph->interval_cnt = 0;
   graph->window_cnt = 0;
   graph->interval_first = graph->interval_last = 0;
   graph->window_first = graph->window_last = 0;
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
      delete_host(graph->root);
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
   int i, j;

   if (((graph->params->mode & MODE_SYN_FLOODING) == MODE_SYN_FLOODING) && (graph->window_cnt != 0)) {
      for (i = 0; i < graph->hosts_cnt; i ++) {
         graph->hosts[i]->stat = 0;
         graph->hosts[i]->intervals[(graph->interval_idx+ARRAY_EXTRA)%graph->params->intvl_max].syn_packets = 0;
      }
   }

   if ((graph->params->mode & MODE_PORTSCAN_VER) == MODE_PORTSCAN_VER) {
      graph->interval_cnt ++;
      if (graph->interval_cnt == graph->params->iter_max) {
         fprintf(stderr, "Info: Flushing all used ports after %d intervals.\n", graph->params->iter_max);
         graph->interval_cnt = 0;
         for (i = 0; i < graph->hosts_cnt; i ++) {
            for (j = 0; j < graph->hosts[i]->ports_cnt; j ++) {
               graph->hosts[i]->ports[j]->accesses = 0;
            }
            graph->hosts[i]->stat = 0;
         }
      }
   }
}

void print_graph(graph_t *graph)
{
   int i, j, p, sum;
   char buffer[BUFFER_TMP], ip[INET_ADDRSTRLEN], name[BUFFER_TMP];
   FILE *f;
   struct tm *time;
   struct hostent *he;

   sum = 0;
   p = PADDING;
   he = NULL;

   if (graph->params == NULL || graph == NULL || graph->params->level == 0) {
      return;
   }

   // Setting file name based on a minute.
   time = localtime(&(graph->interval_first));
   if (time == NULL) {
      fprintf(stderr, "Warning: Cannot convert UNIX timestamp, output omitted.\n");
      return;
   }
   if (strftime(buffer, BUFFER_TMP, FILE_FORMAT, time) == 0) {
      fprintf(stderr, "Warning: Cannot convert UNIX timestamp, output omitted.\n");
      return;
   }
   snprintf(name, BUFFER_TMP, "res/%s.log", buffer);
   if (strftime(buffer, BUFFER_TMP, TIME_FORMAT, time) == 0) {
      fprintf(stderr, "Warning: Cannot convert UNIX timestamp, output omitted.\n");
      return;
   }

   f = fopen(name, "w");
   if (f == NULL) {
      fprintf(stderr, "Warning: Cannot create empty file in given directory, output omitted.\n");
      return;
   }

   if (graph->params->level > VERBOSE_BASIC) {
      fprintf(stderr, "Warning: Check for disk space, very large output may follow.\n");
   }

   for (i = 0; i < graph->hosts_cnt; i ++) {
      if (graph->hosts[i]->stat == 1) {
         sum ++;
      }
   }

   fprintf(f, "Time:                      %*s\n", p, buffer);
   fprintf(f, "Number of active hosts:            %*d\n", p, sum);
   fprintf(f, "\nK-means algorithm parameters:\n");
   fprintf(f, "* Clusters:                        %*d\n", p, graph->params->clusters);

   if (graph->params->level >= VERBOSE_BASIC) {
      qsort(graph->hosts, graph->hosts_cnt, sizeof(host_t *), compare_host);
      // Creating plot of possible DDoS attack victims.
      in_addr_t ip;
      inet_pton(AF_INET, "82.254.111.99", &ip);
      for (i = 0; i < graph->hosts_cnt; i ++) {
         if ((graph->params->mode & MODE_SYN_FLOODING) == MODE_SYN_FLOODING) {
            if (graph->hosts[i]->ip == ip) {
               print_host(graph, i, MODE_SYN_FLOODING);
            }
         }
         if ((graph->params->mode & MODE_PORTSCAN_VER) == MODE_PORTSCAN_VER) {
            if (graph->hosts[i]->ip == ip) {
               print_host(graph, i, MODE_PORTSCAN_VER);
               break;
            }
         }
      }
   }

   // Printing information about hosts.
   if (graph->params->level >= VERBOSE_ADVANCED) {
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
                  for (j = 0; j < graph->params->interval; j ++) {
                     fprintf(f, "* \t%02d) SYN packets:           %*.0lf\n",
                             j, p, graph->hosts[i]->intervals[(graph->interval_idx+ARRAY_EXTRA+j)%graph->params->intvl_max].syn_packets);
                  }
               }
               if ((graph->params->mode & MODE_PORTSCAN_VER) == MODE_PORTSCAN_VER) {
                  // Printing number of SYN packets and assigned cluster in each observation interval.
                  fprintf(f, "* Times port accessed:\n");
                  for (j = 0; j < graph->hosts[i]->ports_cnt; j ++) {
                     if (graph->hosts[i]->ports[j]->accesses > 0) {
                        fprintf(f, "* \tDestination port:          %*d\n"
                                   "* \tTimes accessed:            %*u\n",
                                p, graph->hosts[i]->ports[j]->port_num, p, graph->hosts[i]->ports[j]->accesses);
                     }
                  }
               }
            }
            fprintf(f, "*\n");
         }
      }
   }

   fclose(f);
}
