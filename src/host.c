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

void reset_port(port_t ports[ALL_PORTS])
{
   int i;

   for (i = 0; i < ALL_PORTS; i ++) {
      ports[i].accesses = 0;
      ports[i].port_num = i;
   }
}

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

void free_port(node_t *node)
{
   // Deleting siblings to the left if exist.
   if (node->left != NULL) {
      free_port(node->left);
   }

   // Deleting siblings to the right if exist.
   if (node->right != NULL) {
      free_port(node->right);
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

int compare_port(const void *elem1, const void *elem2)
{
   port_t *port1, *port2;

   port1 = (port_t *) elem1;
   port2 = (port_t *) elem2;
   return (port2->accesses - port1->accesses);
}

extra_t *create_extra()
{
   extra_t *extra;

   extra = (extra_t *) calloc(1, sizeof(extra_t));
   if (extra == NULL) {
       fprintf(stderr, "Error: Not enough memory for extra host structure.\n");
       goto error;
   }

   extra->ports_cnt = 0;
   extra->ports_max = PORTS_INIT;
   extra->root = NULL;
   extra->ports = NULL;

   extra->root = (node_t *) calloc(1, sizeof(node_t));
   if (extra->root == NULL) {
      fprintf(stderr, "Error: Not enough memory for node structure.\n");
      goto error;
   }
   extra->root->left = NULL;
   extra->root->right = NULL;
   extra->ports = (port_t **) calloc(extra->ports_max, sizeof(port_t *));
   if (extra->ports == NULL) {
      fprintf(stderr, "Error: Not enough memory for ports array.\n");
      goto error;
   }

   error:
      if (extra->root != NULL) {
         free(extra->root);
      }
      if (extra->ports != NULL) {
         free(extra->ports);
      }
      if (extra != NULL) {
         free(extra);
      }
      return NULL;
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
   host->level = LEVEL_INFO;
   host->cluster = 0;
   host->distance = 0.0;
   host->accesses = 1;
   host->intervals = NULL;
   host->extra = NULL;

   if ((mode & SYN_FLOODING) == SYN_FLOODING) {
      host->intervals = (intvl_t *) calloc(array_max, sizeof(intvl_t));
      if (host->intervals == NULL) {
          fprintf(stderr, "Error: Not enough memory for host structure.\n");
          goto error;
      }
   }
   return host;

   error:
      if (host->intervals != NULL) {
         free(host->intervals);
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

void free_host(node_t *node)
{
   // Deleting siblings to the left if exist.
   if (node->left != NULL) {
      free_host(node->left);
   }

   // Deleting siblings to the right if exist.
   if (node->right != NULL) {
      free_host(node->right);
   }

   // Deleting host structure if exists.
   if (node->val != NULL) {
      host_t *host = (host_t *) node->val;
      if (host->intervals != NULL) {
         free(host->intervals);
      }
      if (host->extra != NULL) {
         if (host->extra->root != NULL) {
            free_port(host->extra->root);
         }
         if (host->extra->ports != NULL) {
            free(host->extra->ports);
         }
         free(host->extra);
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

   if (graph->params->mode == SYN_FLOODING && flow->syn_flag != 1) {
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
   if ((graph->params->mode & SYN_FLOODING) == SYN_FLOODING) {

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
   if (((graph->params->mode & VER_PORTSCAN) == VER_PORTSCAN) || ((graph->params->mode & HOR_PORTSCAN) == HOR_PORTSCAN)) {
      // Adding simple information about port scan attacks.
      graph->ports[flow->dst_port].accesses ++;
   }

   // Adding additional information about host.
   if (host->stat == LEVEL_TRACE) {
      // Finding port with destination port number.
      node = search_port(flow->dst_port, host->extra->root);

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
         host->extra->ports = add_port(host->extra->ports, port, &(host->extra->ports_cnt), &(host->extra->ports_max));
         if (host->extra->ports == NULL) {
            goto error;
         }
      } else {
         port = (port_t *) node->val;
         port->accesses ++;
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
   if (mode == SYN_FLOODING) {
      time = localtime(&(graph->window_first));
   } else {
      time = localtime(&(graph->interval_first));
   }
   if (time == NULL) {
      fprintf(stderr, "Warning: Cannot convert UNIX timestamp, plot omitted.\n");
      return;
   }
   if (strftime(buffer, BUFFER_TMP, TIME_FORMAT, time) == 0) {
      fprintf(stderr, "Warning: Cannot convert UNIX timestamp, plot omitted.\n");
      return;
   }
   fprintf(g, "set terminal pngcairo font \",8\" enhanced\nunset key\n");

   if (mode == SYN_FLOODING) {
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
      inet_ntop(AF_INET, &(graph->hosts[idx]->ip), ip, INET_ADDRSTRLEN);
      fprintf(g, "set title \"Destination address: %s\\nTime first: %s\"\n"
                 "set xlabel \"Time interval\"\n"
                 "set ylabel \"# SYN packets\"\n"
                 "set y2label \"# SYN packets\"\n"
                 "set xrange [0:%d]\n"
                 "set output \"res/%s_SYN_w%d_t%02d_%s.png\"\n"
                 "plot \"%s\" using 1:2 with line\n",
              ip, buffer, graph->params->intvl_max - ARRAY_EXTRA - 1, graph->params->name, graph->params->window_sum,
              (graph->interval_idx - 1 + (graph->window_cnt * ARRAY_EXTRA)) % graph->params->intvl_max, ip, DATA_FILE);
      fclose(g);
   }
   
   else if (mode == VER_PORTSCAN) {
      // Storing port scan data.
      for (i = 0; i < ALL_PORTS; i ++) {
         if (graph->ports[i].accesses > 0) {
            fprintf(f, "%d %u\n", graph->ports[i].port_num, graph->ports[i].accesses);
         }
      }
      fclose(f);

      fprintf(g, "set title \"Number of ports used: %d\\nTime first: %s\"\n"
                 "set xlabel \"Destination port\"\n"
                 "set xrange [0:%d]\n"
                 "set yrange [0:]\n"
                 "set ylabel \"# Accesses\"\n"
                 "set y2label \"# Accesses\"\n"
                 "set output \"res/%s_VPS_w%d_t%02d.png\"\n"
                 "plot \"%s\" using 1:2\n",
              graph->ports_ver, buffer, ALL_PORTS, graph->params->name, graph->params->window_sum,
              (graph->interval_idx - 1 + (graph->window_cnt * ARRAY_EXTRA)) % graph->params->intvl_max, DATA_FILE);
      fclose(g);
   }

   else if (mode == HOR_PORTSCAN) {
      // Storing port scan data.
      for (i = 0; i < TOP_ACCESSED; i ++) {
         if (graph->ports[i].accesses > 0) {
            fprintf(f, "%d %u\n", graph->ports[i].port_num, graph->ports[i].accesses);
         }
      }
      fclose(f);

      fprintf(g, "set title \"Maximum port accesses: %u\\nTime first: %s\"\n"
                 "set xlabel \"Destination port\"\n"
                 "set xrange [0:%d]\n"
                 "set yrange [0:]\n"
                 "set ylabel \"# Accesses\"\n"
                 "set y2label \"# Accesses\"\n"
                 "set output \"res/%s_HPS_w%d_t%02d.png\"\n"
                 "plot \"%s\" using 1:2\n",
              graph->ports_hor, buffer, ALL_PORTS, graph->params->name, graph->params->window_sum,
              (graph->interval_idx - 1 + (graph->window_cnt * ARRAY_EXTRA)) % graph->params->intvl_max, DATA_FILE);
      fclose(g);
   }

   else if (mode == ALL_ATTACKS) {
      // Storing vertical port scan data.
      for (i = 0; i < graph->hosts[idx]->extra->ports_cnt; i ++) {
         if (graph->hosts[idx]->extra->ports[i]->accesses > 0) {
            fprintf(f, "%d %u\n", graph->hosts[idx]->extra->ports[i]->port_num, graph->hosts[idx]->extra->ports[i]->accesses);
         }
      }
      fclose(f);
      inet_ntop(AF_INET, &(graph->hosts[idx]->ip), ip, INET_ADDRSTRLEN);
      fprintf(g, "set title \"Destination address: %s\\nTime first: %s\"\n"
                 "set xlabel \"Destination port\"\n"
                 "set xrange [0:%d]\n"
                 "set yrange [0:]\n"
                 "set ylabel \"# Accesses\"\n"
                 "set y2label \"# Accesses\"\n"
                 "set output \"res/%s_VPS_w%d_t%02d_%s.png\"\n"
                 "plot \"%s\" using 1:2\n",
              ip, buffer, ALL_PORTS, graph->params->name, graph->params->window_sum,
              (graph->interval_idx - 1 + (graph->window_cnt * ARRAY_EXTRA)) % graph->params->intvl_max, ip, DATA_FILE);
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
