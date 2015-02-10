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
#include "main.h"

cluster_t **create_cluster(params_t *params)
{
   int i;
   cluster_t **clusters;

   clusters = (cluster_t **) calloc(params->clusters, sizeof(cluster_t *));
   if (clusters == NULL) {
      fprintf(stderr, "%sNot enough memory for cluster structures.\n", ERROR);
      goto error;
   }
   for (i = 0; i < params->clusters; i ++) {
      clusters[i] = (cluster_t *) calloc(1, sizeof(cluster_t));
      if (clusters[i] == NULL) {
         fprintf(stderr, "%sNot enough memory for cluster structure.\n", ERROR);
         goto error;
      }
      clusters[i]->centroid = (intvl_t *) calloc(params->intvl_max, sizeof(intvl_t));
      if (clusters[i]->centroid == NULL) {
         fprintf(stderr, "%sNot enough memory for centroid structure.\n", ERROR);
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

int init_cluster(graph_t *graph)
{
   int cnt, i, idx, j, m;

   idx = 0;
   cnt = 0;
   for (j = 0; j < graph->params->clusters; j ++) {
      graph->clusters[j]->hosts_cnt = 0;
      for (i = idx; i < graph->hosts_cnt; i ++) {
         if (graph->hosts[i]->stat != 0) {
            for (m = 0; m < graph->interval_max; m ++) {
               graph->clusters[j]->centroid[m].syn_packets = graph->hosts[j]->intervals[m].syn_packets;
            }
            idx = i + 1;
            cnt ++;
            break;
         }
      }
   }
   return cnt;
}

void distance_cluster(graph_t *graph)
{
   int i, j, m;
   double x;

   for (i = 0; i < graph->hosts_cnt; i ++) {
      if (graph->hosts[i]->stat != 0) {
         for (j = 0; j < graph->params->clusters; j ++) {
            graph->hosts[i]->distances[j] = 0.0;
            for (m = 0; m < graph->interval_max; m ++) {
               x = graph->hosts[i]->intervals[m].syn_packets - graph->clusters[j]->centroid[m].syn_packets;
               graph->hosts[i]->distances[j] += square(x);
            }
         }
      }
   }
}

void assign_cluster(graph_t *graph)
{
   int i, idx, j;
   double x;

   for (j = 0; j < graph->params->clusters; j ++) {
      graph->clusters[j]->hosts_cnt = 0;
   }

   for (i = 0; i < graph->hosts_cnt; i ++) {
      if (graph->hosts[i]->stat != 0) {
         idx = 0;
         x = INFINITY;

         for (j = 0; j < graph->params->clusters; j ++) {
             if (graph->hosts[i]->distances[j] < x) {
                 idx = j;
                 x = graph->hosts[i]->distances[j];
             }
         }
         graph->hosts[i]->cluster = idx;
         graph->clusters[idx]->hosts_cnt ++;
      }
   }
}

void previous_cluster(graph_t *graph)
{
   int i;

   for (i = 0; i < graph->hosts_cnt; i ++) {
      if (graph->hosts[i]->stat != 0) {
         graph->hosts[i]->previous = graph->hosts[i]->cluster;
      }
   }
}

void centroid_cluster(graph_t *graph)
{
   int i, j, m;

   for (j = 0; j < graph->params->clusters; j ++) {
      for (m = 0; m < graph->interval_max; m ++) {
         graph->clusters[j]->centroid[m].syn_packets = 0.0;
      }
   }

   for (i = 0; i < graph->hosts_cnt; i ++) {
      if (graph->hosts[i]->stat != 0) {
         for (m = 0; m < graph->interval_max; m ++) {
            graph->clusters[graph->hosts[i]->cluster]->centroid[m].syn_packets += graph->hosts[i]->intervals[m].syn_packets;
         }
      }
   }

   for (j = 0; j < graph->params->clusters; j ++) {
      if (graph->clusters[j]->hosts_cnt == 0) {
         fprintf(stderr, "%sEmpty cluster %d.\n", WARNING, j + 1);
         continue;
      }
      for (m = 0; m < graph->interval_max; m ++) {
         graph->clusters[j]->centroid[m].syn_packets /= (double) graph->clusters[j]->hosts_cnt;
      }
   }
}

int change_cluster(graph_t *graph)
{
   int cnt, i;

   cnt = 0;

   for (i = 0; i < graph->hosts_cnt; i ++ ) {
     if (graph->hosts[i]->stat != 0) {
        if (graph->hosts[i]->cluster != graph->hosts[i]->previous) {
           cnt ++;
        }
     }
   }

   return cnt;
}

void adjust_cluster(graph_t *graph)
{
   int i, idx, j, k, m, v;
   double dev, max, mean, x;
   uint64_t min;

   min = graph->clusters[0]->hosts_cnt;
   graph->cluster_idx = 0;
   for (j = 1; j < graph->params->clusters; j ++) {
      if (graph->clusters[j]->hosts_cnt == 0) {
         fprintf(stderr, "%sEmpty cluster found after the convergence.\n", WARNING);
         return;
      }
      if (graph->clusters[j]->hosts_cnt < min) {
         min = graph->clusters[j]->hosts_cnt;
         graph->cluster_idx = j;
      }
   }

   // Determining the cluster with not attacked addresses.
   if (graph->cluster_idx > 0) {
      k = 0;
   } else {
      k = 1;
   }

   if (graph->window_cnt == 0) {
      idx = 0;
      v = graph->interval_idx;
   } else {
      idx = graph->interval_idx + ARRAY_EXTRA;
      v = graph->params->intvl_max - ARRAY_EXTRA;
   }
   for (i = 0; i < graph->hosts_cnt; i ++) {
      if (graph->hosts[i]->stat != 0 && graph->hosts[i]->cluster == graph->cluster_idx) {
         // Calculating mean and maximum of SYN flooding packets.
         mean = 0.0;
         max = 0.0;
         for (m = 0; m < v; m ++) {
            x = graph->hosts[i]->intervals[(idx+m)%graph->params->intvl_max].syn_packets;
            mean += x;
            if (x > max) {
               max = x;
            }
         }
         graph->hosts[i]->peak = max;
         graph->hosts[i]->mean = (mean - max) / (v - 1);
         mean /= v;
         dev = 0.0;
         // Calculating standard deviation of SYN flooding packets.
         for (m = 0; m < v; m ++) {
            x = graph->hosts[i]->intervals[(idx+m)%graph->params->intvl_max].syn_packets - mean;
            dev += square(x);
         }
         dev = sqrt(dev / (v - 1));
         
         // Determining attack or not.
         if (dev < (2 * mean) || max < SYN_THRESHOLD) {
            graph->hosts[i]->cluster = k;
            graph->clusters[graph->cluster_idx]->hosts_cnt --;
            graph->clusters[k]->hosts_cnt ++;
         }
      }
   }

   // Setting SYN flooding attack flag.
   if (graph->clusters[graph->cluster_idx]->hosts_cnt > 0) {
      graph->attack += SYN_FLOODING;
      fprintf(stderr, "%sSYN flooding attack detected!\n", WARNING);
   }
}

void batch_cluster(graph_t *graph)
{
   // Determining the dimension of the data.
   if (graph->window_cnt == 0) {
      graph->interval_max = graph->interval_idx;
   } else {
      graph->interval_max = graph->params->intvl_max;
   }

   // Initializing centroids of the cluster with first values in the graph.
   if ((init_cluster(graph)) != graph->params->clusters) {
      fprintf(stderr, "%sNot enough data to start SYN flooding detection.\n", WARNING);
      return;
   }
   // Calculating the Euclidean distance to each centroid.
   distance_cluster(graph);
   // Assigning cluster to each observations.
   assign_cluster(graph);
   // Making backup to detect changes in next iterations.
   previous_cluster(graph);

   // Repeat the process until the centroids are convergent.
   while (1) {
      // Calculating new centroids coordinates.
      centroid_cluster(graph);

      distance_cluster(graph);
      assign_cluster(graph);
      if ((change_cluster(graph)) == 0) {
         break;
      }
      previous_cluster(graph);
   }

   // Checking for false positives.
   adjust_cluster(graph);
}

void online_cluster(graph_t *graph)
{
   int cnt, i, j, k, m, v;
   double d, x, y, z;
   uint8_t p, q;
   uint64_t h, n;

   // Number of observations
   n = graph->hosts_cnt;
   // Number of clusters.
   k = graph->params->clusters;

   // Determining the dimension of the data.
   if (graph->window_cnt == 0) {
      v = graph->interval_idx;
   } else {
      v = graph->params->intvl_max;
   }

   // Initializing centroids of the cluster with first values in the graph.
   if ((init_cluster(graph)) != graph->params->clusters) {
      fprintf(stderr, "%sNot enough data to start SYN flooding detection.\n", WARNING);
      return;
   }

   // Assigning each host to the cluster based on a Euclidean distances.
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
         graph->clusters[graph->hosts[i]->cluster]->hosts_cnt ++;
      }
   }

   // Calculating the mean and sum of squares for each cluster.
   for (i = 0; i < k; i ++) {
      graph->clusters[i]->dev = 0.0;
      for (m = 0; m < v; m ++) {
         graph->clusters[i]->centroid[m].syn_packets = 0.0;
      }
   }

   for (i = 0; i < n; i ++) {
      if (graph->hosts[i]->stat != 0) {
         for (m = 0; m < v; m ++) {
            graph->clusters[graph->hosts[i]->cluster]->centroid[m].syn_packets += graph->hosts[i]->intervals[m].syn_packets;
         }
      }
   }

   for (i = 0; i < k; i ++) {
      for (m = 0; m < v; m ++) {
         graph->clusters[i]->centroid[m].syn_packets /= (double) graph->clusters[i]->hosts_cnt;
      }
   }

   for (i = 0; i < n; i ++) {
      if (graph->hosts[i]->stat != 0) {
         graph->hosts[i]->distances[0] = 0.0;
         p = graph->hosts[i]->cluster;
         for (m = 0; m < v; m ++) {
            x = graph->hosts[i]->intervals[m].syn_packets - graph->clusters[p]->centroid[m].syn_packets;
            y = square(x);
            graph->hosts[i]->distances[0] += y;
            graph->clusters[p]->dev += y;
         }
      }
   }

   for (i = 0; i < n; i ++) {
      p = graph->hosts[i]->cluster;
      h = graph->clusters[p]->hosts_cnt;
      if (h > 1) {
         graph->hosts[i]->distances[0] = graph->hosts[i]->distances[0] * h / (h - 1);
      }
   }

   // Repeat the process until the centroids are convergent.
   while (1) {
      cnt = 0;
      for (i = 0; i < n; i ++) {
         if (graph->hosts[i]->stat != 0) {
            p = graph->hosts[i]->cluster;
            q = p;

            d = graph->hosts[i]->distances[0];

            for (j = 0; j < k; j ++) {
               if (j != p) {
                  x = (double) graph->clusters[j]->hosts_cnt;
                  x /= (x + 1.0);

                  y = 0.0;
                  for (m = 0; m < v; m ++) {
                     z = graph->hosts[i]->intervals[m].syn_packets - graph->clusters[j]->centroid[m].syn_packets;
                     y += square(z) * x;
                  }

                  // Changing cluster if the distances is shorter.
                  if (y < d) {
                     d = y;
                     p = j;
                  }
               }
            }

            // Making reassignment if the cluster has changed.
            if (p != q) {
               graph->clusters[q]->dev -= graph->hosts[i]->distances[0];
               graph->clusters[p]->dev += d;
               graph->clusters[q]->hosts_cnt --;
               graph->clusters[p]->hosts_cnt ++;

               for (m = 0; m < v; m ++) {
                  x = graph->clusters[q]->centroid[m].syn_packets * graph->clusters[q]->hosts_cnt - graph->hosts[i]->intervals[m].syn_packets;
                  graph->clusters[q]->centroid[m].syn_packets = x / (graph->clusters[q]->hosts_cnt - 1);
                  y = graph->clusters[p]->centroid[m].syn_packets * graph->clusters[p]->hosts_cnt + graph->hosts[i]->intervals[m].syn_packets;
                  graph->clusters[p]->centroid[m].syn_packets = y / (graph->clusters[p]->hosts_cnt + 1);
               }

               graph->hosts[i]->cluster = p;

               for (j = 0; j < n; j ++) {
                  if ((graph->hosts[j]->stat != 0) && (graph->hosts[j]->cluster == p || graph->hosts[j]->cluster == q)) {
                     graph->hosts[j]->distances[0] = 0.0;
                     for (m = 0; m < v; m ++) {
                        x = graph->hosts[j]->intervals[m].syn_packets - graph->clusters[graph->hosts[j]->cluster]->centroid[m].syn_packets;
                        graph->hosts[j]->distances[0] += square(x);
                     }
                     h = graph->clusters[graph->hosts[j]->cluster]->hosts_cnt;
                     graph->hosts[j]->distances[0] = graph->hosts[j]->distances[0] * h / (h - 1);
                  }
               }
               cnt ++;
            }
         }
      }

      // K-means has converged.
      if (cnt == 0) {
         break;
      }
   }

   // Checking for false positives.
   adjust_cluster(graph);
}
