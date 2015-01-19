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
   graph->host_level = LEVEL_INFO;
   graph->interval_idx = graph->interval_cnt = 0;
   graph->window_cnt = 0;
   graph->ports_ver = 0;
   graph->ports_hor = 0;
   reset_port(graph->ports);
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
   graph->root->left = NULL;
   graph->root->right = NULL;
   graph->hosts = (host_t **) calloc(graph->hosts_max, sizeof(host_t *));
   if (graph->hosts == NULL) {
      fprintf(stderr, "Error: Not enough memory for hosts array.\n");
      goto error;
   }

   if ((graph->params->mode & SYN_FLOODING) == SYN_FLOODING) {
      graph->clusters = create_cluster(params);
      if (graph->clusters == NULL) {
         goto error;
      }
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
      free_host(graph->root);
   }
   if (graph->hosts != NULL) {
      free(graph->hosts);
   }
   if (graph->clusters != NULL) {
      free_cluster(graph->clusters, graph->params->clusters);
   }
   if (graph != NULL) {
      free(graph);
   }
}

void reset_graph(graph_t *graph)
{
   int i, j;

   graph->attack = 0;
   graph->ports_ver = 0;
   graph->ports_hor = 0;

   for (i = 0; i < graph->hosts_cnt; i ++) {
      graph->hosts[i]->accesses = 0;
   }
   
   if (((graph->params->mode & SYN_FLOODING) == SYN_FLOODING) && (graph->window_cnt != 0)) {
      for (i = 0; i < graph->hosts_cnt; i ++) {
         graph->hosts[i]->stat = 0;
         graph->hosts[i]->cluster = 0;
         graph->hosts[i]->intervals[(graph->interval_idx+ARRAY_EXTRA)%graph->params->intvl_max].syn_packets = 0;
      }
   }

   if (((graph->params->mode & VER_PORTSCAN) == VER_PORTSCAN) || ((graph->params->mode & HOR_PORTSCAN) == HOR_PORTSCAN)) {
      reset_port(graph->ports);
      graph->interval_cnt ++;
      if (graph->host_level > LEVEL_INFO) {
         if (graph->interval_cnt == graph->params->iter_max) {
            fprintf(stderr, "Info: Flushing all used ports of given host after %d intervals.\n", graph->params->iter_max);
            graph->interval_cnt = 0;
            for (i = 0; i < graph->hosts_cnt; i ++) {
               for (j = 0; j < graph->hosts[i]->extra->ports_cnt; j ++) {
                  graph->hosts[i]->extra->ports[j]->accesses = 0;
               }
               graph->hosts[i]->stat = 0;
            }
         }
      }
   }
}

void print_graph(graph_t *graph)
{
   int i, j, p, sum;
   char buffer[BUFFER_TMP], date[BUFFER_TMP], ip[INET_ADDRSTRLEN], name[BUFFER_TMP];
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
   graph->params->name = buffer;
   snprintf(name, BUFFER_TMP, "res/%s.log", buffer);
   if (strftime(date, BUFFER_TMP, TIME_FORMAT, time) == 0) {
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
      if (graph->hosts[i]->accesses > 0) {
         sum ++;
      }
   }

   fprintf(f, "Time:                      %*s\n", p, date);
   fprintf(f, "Number of active hosts:            %*d\n", p, sum);

   if ((graph->params->mode & VER_PORTSCAN) == VER_PORTSCAN) {
      fprintf(f, "Number of ports used:              %*d\n", p, graph->ports_ver);
   }
   if ((graph->params->mode & HOR_PORTSCAN) == HOR_PORTSCAN) {
      fprintf(f, "Maximum port accesses:             %*u\n", p, graph->ports_hor);
   }
   if ((graph->params->mode & SYN_FLOODING) == SYN_FLOODING) {
      if (graph->window_cnt != 0) {
         fprintf(f, "Number of clusters:                %*d\n", p, graph->params->clusters);
         for (i = 0; i < graph->params->clusters; i ++) {
            fprintf(f, "* Hosts in cluster %d:              %*lu\n", i + 1, p, graph->clusters[i]->hosts_cnt);
         }
         fprintf(f, "\nSYN flooding attack brief:\n");
      }
   }

   if (graph->params->level >= VERBOSE_BASIC) {
      qsort(graph->hosts, graph->hosts_cnt, sizeof(host_t *), compare_host);
      // Creating plot of possible DDoS attack victims.
      for (i = 0; i < graph->hosts_cnt; i ++) {
         if ((graph->attack & SYN_FLOODING) == SYN_FLOODING) {
            if (graph->window_cnt != 0) {
               if ((graph->hosts[i]->stat != 0) && (graph->hosts[i]->cluster == graph->cluster_idx)) {
                  inet_ntop(AF_INET, &(graph->hosts[i]->ip), ip, INET_ADDRSTRLEN);
                  fprintf(f, "* Destination IP address:          %*s\n", p, ip);
                  print_host(graph, i, SYN_FLOODING);
               }
            }
         }
         if ((graph->attack & VER_PORTSCAN) == VER_PORTSCAN) {
            if ((graph->hosts[i]->accesses > 0) && (graph->hosts[i]->level == LEVEL_TRACE)) {
               print_host(graph, i, ALL_ATTACKS);
            }
         }
      }

      if ((graph->attack & VER_PORTSCAN) == VER_PORTSCAN) {
         print_host(graph, 0, VER_PORTSCAN);
      }

      if ((graph->attack & HOR_PORTSCAN) == HOR_PORTSCAN) {
         print_host(graph, 0, HOR_PORTSCAN);
         fprintf(f, "\nHorizontal port scan attack brief:\n");
         for (i = 0; i < TOP_ACCESSED; i ++) {
            fprintf(f, "* Destination port:                %*d\n"
                       "* Times accessed:                  %*u\n",
                    p, graph->ports[i].port_num, p, graph->ports[i].accesses);
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
            if (graph->hosts[i]->level > LEVEL_INFO) {
               fprintf(f, "* Ports used:                      %*u\n", p, graph->hosts[i]->extra->ports_cnt);
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
               if ((graph->params->mode & SYN_FLOODING) == SYN_FLOODING) {
                  // Printing number of SYN packets in each observation interval.
                  fprintf(f, "* Observation intervals:\n");
                  for (j = 0; j < graph->params->interval; j ++) {
                     fprintf(f, "* \t%02d) SYN packets:           %*.0lf\n",
                             j, p, graph->hosts[i]->intervals[(graph->interval_idx+ARRAY_EXTRA+j)%graph->params->intvl_max].syn_packets);
                  }
               }
               if (graph->hosts[i]->level > LEVEL_INFO) {
                  // Printing number of accesses on each port in the observation interval.
                  fprintf(f, "* Times port accessed:\n");
                  for (j = 0; j < graph->hosts[i]->extra->ports_cnt; j ++) {
                     if (graph->hosts[i]->extra->ports[j]->accesses > 0) {
                        fprintf(f, "* \tDestination port:          %*d\n"
                                   "* \tTimes accessed:            %*u\n",
                                p, graph->hosts[i]->extra->ports[j]->port_num, p, graph->hosts[i]->extra->ports[j]->accesses);
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
