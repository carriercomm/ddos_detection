/*!
 * \file cluster.c
 * \brief Data clustering library.
 * \author Jan Neuzil <neuzija1@fit.cvut.cz>
 * \date 2014
 */
/*
 * Copyright (C) 2014 ISEP
 */

#include "cluster.h"

cluster_t **create_cluster(params_t *params)
{
   int i;
   cluster_t **clusters;

   clusters = (cluster_t **) calloc(params->clusters, sizeof(cluster_t *));
   if (clusters == NULL) {
      fprintf(stderr, "Error: Not enough memory for cluster structures.\n");
      goto error;
   }
   for (i = 0; i < params->clusters; i ++) {
      clusters[i] = (cluster_t *) calloc(1, sizeof(cluster_t));
      if (clusters[i] == NULL) {
         fprintf(stderr, "Error: Not enough memory for cluster structure.\n");
         goto error;
      }
      clusters[i]->centroid = (intvl_t *) calloc(params->intvl_max, sizeof(intvl_t));
      if (clusters[i]->centroid == NULL) {
         fprintf(stderr, "Error: Not enough memory for centroid structure.\n");
         goto error;
      }
   }

   return clusters;

   // Cleaning up after error.
   error:
      if (clusters != NULL) {
         free_cluster(clusters, params->clusters);
      }
      return NULL;
}

void free_cluster(cluster_t **clusters, int k)
{
   int i;

   if (clusters != NULL) {
      for (i = 0; i < k; i ++) {
         if (clusters[i] != NULL) {
            if (clusters[i]->centroid != NULL) {
               free(clusters[i]->centroid);
            }
            free(clusters[i]);
         }
      }
      free(clusters);
   }
}

graph_t *assign_cluster(graph_t *graph)
{
   int i, j, k, m, v;
   double d, x, y, z;
   uint8_t p, q;
   uint64_t h, n, stop;

   // Number of observations
   n = graph->hosts_cnt;
   // Number of values.
   v = graph->params->intvl_max;
   // Number of clusters.
   k = graph->params->clusters;

   // Initializing centroids based on number of clusters.
   if (n < k) {
      fprintf(stderr, "Error: Not enough data to start SYN flooding detection.\n");
      goto error;
   }
   for (j = 0; j < k; j ++) {
      graph->clusters[j]->hosts_cnt = 0;
      for (m = 0; m < v; m ++) {
         graph->clusters[j]->centroid[m].syn_packets = graph->hosts[j]->intervals[m].syn_packets;
      }
   }

   // Assigning each host to the cluster based on a distance.
   for (i = 0; i < n; i ++) {
      if (graph->hosts[i]->stat != 0) {
         x = INFINITY;
         for (j = 0; j < k; j ++) {
            y = 0.0;
            for (m = 0; m < v; m ++) {
               z = graph->hosts[i]->intervals[m].syn_packets - graph->clusters[j]->centroid[m].syn_packets;
               y += square(z);
            }
            if (y < x) {
               x = y;
               graph->hosts[i]->cluster = j;
            }
         }
      }
      graph->clusters[graph->hosts[i]->cluster]->hosts_cnt ++;
   }

   // Calculating the mean and sum of squares for each cluster.
   for (i = 0; i < k; i ++) {
      graph->clusters[i]->dev = 0.0;
      for (j = 0; j < v; j ++) {
         graph->clusters[i]->centroid[j].syn_packets = 0.0;
      }
   }

   for (i = 0; i < n; i ++) {
      if (graph->hosts[i]->stat != 0) {
         for (j = 0; j < v; j ++) {
            graph->clusters[graph->hosts[i]->cluster]->centroid[j].syn_packets += graph->hosts[i]->intervals[j].syn_packets;
         }
      }
   }

   for (i = 0; i < k; i ++) {
      for (j = 0; j < v; j ++) {
         graph->clusters[i]->centroid[j].syn_packets /= (double) graph->clusters[i]->hosts_cnt;
      }
   }

   for (i = 0; i < n; i ++) {
      if (graph->hosts[i]->stat != 0) {
         p = graph->hosts[i]->cluster;
         for (j = 0; j < v; j ++) {
            x = graph->hosts[i]->intervals[j].syn_packets - graph->clusters[p]->centroid[j].syn_packets;
            y = square(x);
            graph->hosts[i]->distance += y;
            graph->clusters[p]->dev += y;
         }
      }
   }

   for (i = 0; i < n; i ++) {
      p = graph->hosts[i]->cluster;
      h = graph->clusters[p]->hosts_cnt;

      // Checking for outliers.
      if (h >= 2) {
         graph->hosts[i]->distance = graph->hosts[i]->distance * h / (h - 1);
      }
   }

   // Repeat the process until the centroids are convergent.
   stop = 1;
   while(stop != 0) {
      stop = 0;
      for (i = 0; i < n; i ++) {
         if (graph->hosts[i]->stat != 0) {
            p = graph->hosts[i]->cluster;
            q = p;

            // Checking for minimum observations in the cluster.
            if (graph->clusters[p]->hosts_cnt > OBSERVATIONS) {
               d = graph->hosts[i]->distance;

               for (j = 0; j < k; j ++) {
                  if (j != p) {
                     x = (double) graph->clusters[j]->hosts_cnt;
                     x /= (x + 1.0);

                     y = 0.0;
                     for (m = 0; m < v; m ++) {
                        z = graph->hosts[i]->intervals[m].syn_packets - graph->clusters[j]->centroid[m].syn_packets;
                        y += square(z) * x;
                     }

                     // Changing cluster if the distance is shorter.
                     if (y < d) {
                        d = y;
                        p = j;
                     }
                  }
               }

               // Making reassignment if the cluster has changed.
               if (p != q) {
                  for (m = 0; m < v; m ++) {
                     x = graph->clusters[q]->centroid[m].syn_packets * graph->clusters[q]->hosts_cnt - graph->hosts[i]->intervals[m].syn_packets;
                     graph->clusters[graph->hosts[i]->cluster]->centroid[m].syn_packets = x / (graph->clusters[q]->hosts_cnt - 1);
                     y = graph->clusters[p]->centroid[m].syn_packets * graph->clusters[p]->hosts_cnt - graph->hosts[i]->intervals[m].syn_packets;
                     graph->clusters[graph->hosts[i]->cluster]->centroid[m].syn_packets = y / (graph->clusters[p]->hosts_cnt + 1);
                  }

                  graph->clusters[q]->dev -= graph->hosts[i]->distance;
                  graph->clusters[p]->dev += y;
                  graph->clusters[q]->hosts_cnt --;
                  graph->clusters[p]->hosts_cnt ++;
                  graph->hosts[i]->cluster = p;

                  for (j = 0; j < n; j ++) {
                     if (graph->hosts[j]->cluster == p || graph->hosts[j]->cluster == q) {
                        graph->hosts[j]->distance = 0.0;
                        for (m = 0; m < v; m ++) {
                           x = graph->hosts[j]->intervals[m].syn_packets - graph->clusters[graph->hosts[j]->cluster]->centroid[m].syn_packets;
                           graph->hosts[j]->distance += square(x);
                        }
                        h = graph->clusters[graph->hosts[j]->cluster]->hosts_cnt;
                        graph->hosts[j]->distance = graph->hosts[i]->distance * h / (h - 1);
                     }
                  }

                  stop ++;
               }
            }
         }
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
