/*!
 * \file host.c
 * \brief Host functions library.
 * \author Jan Neuzil <neuzija1@fit.cvut.cz>
 * \date 2014
 */
/*
 * Copyright (C) 2014 ISEP
 */

#include "host.h"

node_t *search_port(uint16_t port, node_t *root)
{
   int i;
   uint32_t mask;
   node_t *node, *tmp;

   mask = MASK_PORT;
   node = root;

   for (i = 0; i < BITS_PORT; i ++) {
      if (port & mask) {
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
      port <<= 1;
   }

   return node;
}

void delete_port(node_t *node)
{
   // Deleting siblings to the left if exist.
   if (node->left != NULL) {
      delete_port(node->left);
   }

   // Deleting siblings to the right if exist.
   if (node->right != NULL) {
      delete_port(node->right);
   }

   // Deleting host structure if exists.
   if (node->val != NULL) {
      free(node->val);
   }

   // Deleting current node.
   free(node);
}

port_t **add_port(port_t **ports, port_t *port, uint16_t *ports_cnt, uint16_t *ports_max)
{
   // Reallocating array if needed.
   if (*ports_cnt == *ports_max) {
      *ports_max *= 2;
      if (*ports_max == 0) {
         *ports_max -= 1;
      }
      port_t **tmp = (port_t **) realloc(ports, (*ports_max) * sizeof(port_t *));
      if (tmp == NULL) {
         fprintf(stderr, "Error: Not enough memory for ports array.\n");
         free(ports);
         return NULL;
      }
      ports = tmp;
   }

   // Adding new port to array of ports and updating counter.
   ports[(*ports_cnt)++] = port;
   return ports;
}

host_t *create_host(in_addr_t ip, int mode, int array_max)
{
   host_t *host;

   host = (host_t *) calloc(1, sizeof(host_t));
   if (host == NULL) {
       fprintf(stderr, "Error: Not enough memory for host structure.\n");
       goto error;
   }
   host->ip = ip;
   host->stat = 1;
   host->accesses = 1;
   host->ports_cnt = 0;
   host->ports_max = PORTS_INIT;
   host->root = NULL;
   host->intervals = NULL;
   host->ports = NULL;

   if ((mode & MODE_SYN_FLOODING) == MODE_SYN_FLOODING) {
      host->intervals = (intvl_t *) calloc(array_max, sizeof(intvl_t));
      if (host->intervals == NULL) {
          fprintf(stderr, "Error: Not enough memory for host structure.\n");
          goto error;
      }
   }

   if ((mode & MODE_PORTSCAN_VER) == MODE_PORTSCAN_VER) {
      host->root = (node_t *) calloc(1, sizeof(node_t));
      if (host->root == NULL) {
         fprintf(stderr, "Error: Not enough memory for node structure.\n");
         goto error;
      }
      host->ports = (port_t **) calloc(host->ports_max, sizeof(port_t *));
      if (host->ports == NULL) {
         fprintf(stderr, "Error: Not enough memory for ports array.\n");
         goto error;
      }
   }
   return host;

   error:
      if (host->intervals != NULL) {
         free(host->intervals);
      }
      if (host->root != NULL) {
         free(host->root);
      }
      if (host->ports != NULL) {
         free(host->ports);
      }
      if (host != NULL) {
         free(host);
      }
      return NULL;
}

node_t *search_host(in_addr_t ip, node_t *root)
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

void delete_host(node_t *node)
{
   // Deleting siblings to the left if exist.
   if (node->left != NULL) {
      delete_host(node->left);
   }

   // Deleting siblings to the right if exist.
   if (node->right != NULL) {
      delete_host(node->right);
   }

   // Deleting host structure if exists.
   if (node->val != NULL) {
      host_t *host = (host_t *) node->val;
      if (host->intervals != NULL) {
         free(host->intervals);
      }
      if (host->root != NULL) {
         delete_port(host->root);
      }
      if (host->ports != NULL) {
         free(host->ports);
      }
      free(host);
   }

   // Deleting current node.
   free(node);
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
   int cnt, i, seconds;
   float pps;
   time_t diff;
   node_t *node;
   host_t *host;
   port_t *port;

   if (graph->params->mode == MODE_SYN_FLOODING && flow->syn_flag != 1) {
      // SYN flag is not set, skipping line.
      return graph;
   }

   // Finding host with destination IP address.
   node = search_host(flow->dst_ip, graph->root);

   // Creating new host with destination address if not present.
   if (node->val == NULL) {
      host = create_host(flow->dst_ip, graph->params->mode, graph->params->intvl_max);
      if (host == NULL) {
         goto error;
      }
      node->val = host;
      graph->hosts = add_host(graph->hosts, host, &(graph->hosts_cnt), &(graph->hosts_max));
      if (graph->hosts == NULL) {
         goto error;
      }
   } else {
      host = (host_t *) node->val;
      host->stat = 1;
      host->accesses ++;
   }

   // Completing data of ports.
   if ((graph->params->mode & MODE_SYN_FLOODING) == MODE_SYN_FLOODING) {

      // Adding all SYN packets in the same interval.
      if (flow->time_last < graph->interval_last) {
         host->intervals[graph->interval_idx].syn_packets += flow->packets;
      }

      // Distributing SYN packets among various intervals using linear function.
      else {
         diff = flow->time_last - flow->time_first;
         pps = ((float) flow->packets) / ((float) diff);

         // Calculating the seconds residue of the intervals.
         seconds = graph->interval_last - flow->time_first;
         host->intervals[graph->interval_idx].syn_packets += (seconds * pps);
         seconds = diff - seconds;
         if (seconds <= graph->params->interval) {
            host->intervals[(graph->interval_idx+1)%graph->params->intvl_max].syn_packets += (seconds * pps);
         }
         else {
            cnt = seconds / graph->params->interval;
            for (i = 0; i < cnt; i ++) {
               host->intervals[(graph->interval_idx+i+1)%graph->params->intvl_max].syn_packets += (graph->params->interval * pps);
            }
            host->intervals[(graph->interval_idx+cnt+1)%graph->params->intvl_max].syn_packets += ((seconds % graph->params->interval) * pps);
         }
      }
   }

   // Completing data of ports.
   if ((graph->params->mode & MODE_PORTSCAN_VER) == MODE_PORTSCAN_VER) {
         // Finding port with destination port number.
         node = search_port(flow->dst_port, host->root);

         // Creating new port with destination port number if not present.
         if (node->val == NULL) {
            port = (port_t *) calloc(1, sizeof(port_t));
            if (port == NULL) {
               fprintf(stderr, "Error: Not enough memory for port structure.\n");
               goto error;
            }
            node->val = port;
            port->port_num = flow->dst_port;
            port->accesses = 1;
            host->ports = add_port(host->ports, port, &(host->ports_cnt), &(host->ports_max));
            if (host->ports == NULL) {
               goto error;
            }
         } else {
            port = (port_t *) node->val;
            port->accesses ++;
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
   time = localtime(&(graph->window_first));
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
      if (graph->window_cnt == 0) {
         for (i = 0; i < graph->interval_idx; i ++) {
            fprintf(f, "%d %.0lf\n", i, graph->hosts[idx]->intervals[i].syn_packets);
         }
      } else {
         for (i = 0; i < (graph->params->intvl_max - ARRAY_EXTRA); i ++) {
            fprintf(f, "%d %.0lf\n", i, graph->hosts[idx]->intervals[(graph->interval_idx+ARRAY_EXTRA+i)%graph->params->intvl_max].syn_packets);
         }
      }
      fclose(f);

      fprintf(g, "set xlabel \"Time interval\"\n"
                 "set ylabel \"# SYN packets\"\n"
                 "set y2label \"# SYN packets\"\n"
                 "set xrange [0:%d]\n"
                 "set output \"res/%s_SYN_w%d_t%02d.png\"\n"
                 "plot \"%s\" using 1:2 with line\n",
              graph->params->intvl_max - ARRAY_EXTRA - 1, ip, graph->params->window_sum, 
              (graph->interval_idx - 1 + (graph->window_cnt * ARRAY_EXTRA)) % graph->params->intvl_max, DATA_FILE);
      fclose(g);
   }

   else if (mode == MODE_PORTSCAN_VER) {
      // Storing vertical port scan data.
      for (i = 0; i < graph->hosts[idx]->ports_cnt; i ++) {
         if (graph->hosts[idx]->ports[i]->accesses > 0) {
            fprintf(f, "%d %u\n", graph->hosts[idx]->ports[i]->port_num, graph->hosts[idx]->ports[i]->accesses);
         }
      }
      fclose(f);

      fprintf(g, "set xlabel \"Destination port\"\n"
                 "set xrange [0:%d]\n"
                 "set yrange [0:]\n"
                 "set ylabel \"# Accesses\"\n"
                 "set y2label \"# Accesses\"\n"
                 "set output \"res/%s_VPS_w%d_t%02d.png\"\n"
                 "plot \"%s\" using 1:2\n",
              ALL_PORTS, ip, graph->params->window_sum, 
              (graph->interval_idx - 1 + (graph->window_cnt * ARRAY_EXTRA)) % graph->params->intvl_max, DATA_FILE);
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
