/*!
 * \file ddos_detection.c
 * \brief Detection logic library.
 * \author Jan Neuzil <neuzija1@fit.cvut.cz>
 * \date 2014
 */
/*
 * Copyright (C) 2014 ISEP
 */

#include "ddos_detection.h"

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
      fprintf(stderr, "Info: Detection for given interval finished, results available.\n");
   }
   return graph;

   // Cleaning up after error.
   /*error:
      if (graph != NULL) {
         free_graph(graph);
      }
      return NULL;*/
}
