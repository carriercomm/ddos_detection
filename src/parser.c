/*!
 * \file parser.c
 * \brief Parsing functions library.
 * \author Jan Neuzil <neuzija1@fit.cvut.cz>
 * \date 2014
 */
/*
 * Copyright (C) 2014 ISEP
 */

#include "parser.h"

params_t *parse_params(int argc, char **argv)
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
      "  -t TIME      Set the observation interval in seconds, 1 minute by default.\n"
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
   params->flush_cnt = 1;
   params->flush_iter = FLUSH_ITER;
   params->progress = 0;
   params->level = VERBOSITY;
   params->interval = INTERVAL;
   params->time_window = TIME_WINDOW;
   params->file = NULL;
   params->window_sum = 0;

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
   params->intvl_max = (params->time_window / params->interval) + ARRAY_EXTRA;
   if (params->intvl_max <= ARRAY_MIN) {
      fprintf(stderr, "Error: Time window cannot be less or closely equal than observation interval.\n");
      goto error;
   }
   params->iter_max = PORT_WINDOW / params->interval;

   return params;

   // Cleaning up after error.
   error:
      if (params != NULL) {
         free(params);
      }
      return NULL;
}

char *parse_token(char **string, int *len)
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
   dst_ip = parse_token(&line, &len);
   if (dst_ip == NULL) {
      fprintf(stderr, "Warning: Missing destination IP address, parsing interrupted.\n");
      return EXIT_FAILURE;
   }
   if (inet_pton(AF_INET, dst_ip, &(flow->dst_ip)) != 1) {
         fprintf(stderr, "Warning: Cannot convert string to destination IP address, parsing interrupted.\n");
         return EXIT_FAILURE;
   }

   src_ip = parse_token(&line, &len);
   if (src_ip == NULL) {
      fprintf(stderr, "Warning: Missing source IP address, parsing interrupted.\n");
      return EXIT_FAILURE;
   }
   if (inet_pton(AF_INET, src_ip, &(flow->src_ip)) != 1) {
         fprintf(stderr, "Warning: Cannot convert string to source IP address, parsing interrupted.\n");
         return EXIT_FAILURE;
   }

   dst_port = parse_token(&line, &len);
   if (dst_port == NULL) {
      fprintf(stderr, "Warning: Missing destination port, parsing interrupted.\n");
      return EXIT_FAILURE;
   }
   flow->dst_port = atoi(dst_port);

   src_port = parse_token(&line, &len);
   if (src_port == NULL) {
      fprintf(stderr, "Warning: Missing source port, parsing interrupted.\n");
      return EXIT_FAILURE;
   }
   flow->src_port = atoi(src_port);

   protocol = parse_token(&line, &len);
   if (protocol == NULL) {
      fprintf(stderr, "Warning: Missing used protocol, parsing interrupted.\n");
      return EXIT_FAILURE;
   }
   flow->protocol = atoi(protocol);

   time_first = parse_token(&line, &len);
   if (time_first == NULL) {
      fprintf(stderr, "Warning: Missing time of the first packet, parsing interrupted.\n");
      return EXIT_FAILURE;
   }
   flow->time_first = atoi(time_first);

   // Unknown field, skipping token.
   parse_token(&line, &len);

   time_last = parse_token(&line, &len);
   if (time_last == NULL) {
      fprintf(stderr, "Warning: Missing time of the last packet, parsing interrupted.\n");
      return EXIT_FAILURE;
   }
   flow->time_last = atoi(time_last);

   bytes = parse_token(&line, &len);
   if (bytes == NULL) {
      fprintf(stderr, "Warning: Missing number of transmitted bytes, parsing interrupted.\n");
      return EXIT_FAILURE;
   }
   flow->bytes = atoi(bytes);

   packets = parse_token(&line, &len);
   if (packets == NULL) {
      fprintf(stderr, "Warning: Missing number of transmitted packets, parsing interrupted.\n");
      return EXIT_FAILURE;
   }
   flow->packets = atoi(packets);

   syn_flag = parse_token(&line, &len);
   if (syn_flag == NULL) {
      fprintf(stderr, "Warning: Missing SYN flag, parsing interrupted.\n");
      return EXIT_FAILURE;
   }
   flow->syn_flag = atoi(syn_flag);

   if (graph->window_first == 0) {
      graph->interval_first = flow->time_first;
      graph->interval_last = flow->time_first + graph->params->interval;
      graph->window_first = flow->time_first;
      graph->window_last = flow->time_first + graph->params->time_window;
   }

   // Delayed flow record, skipping line.
   if (flow->time_first < graph->interval_first) {
      fprintf(stderr, "Warning: Delayed flow record, parsing interrupted.\n");
      return EXIT_FAILURE;
   }

   return EXIT_SUCCESS;
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

               // Interval reached, starting detection.
               if (flow.time_first >= graph->interval_last) {
                  if (graph->params->progress > 0) {
                     fprintf(stderr, "\n");
                  }
                  // Shifting to the next interval.
                  graph->interval_idx = (graph->interval_idx + 1) % graph->params->intvl_max;
                  graph = detection_handler(graph);
                  if (graph == NULL) {
                     goto error;
                  }
                  // Time window reached.
                  if (flow.time_first >= graph->window_last) {
                     graph->params->window_sum ++;
                     graph->window_cnt ++;
                     // Cleaning graph.
                     if (params->flush_cnt == params->flush_iter) {
                        fprintf(stderr, "Info: Time window reached, flushing whole graph.\n");
                        params->flush_cnt = 1;
                        free_graph(graph);
                        graph = create_graph(params);
                        if (graph == NULL) {
                           goto error;
                        }
                        graph->interval_first = flow.time_first;
                        graph->interval_last = flow.time_first + graph->params->interval;
                        graph->window_first = flow.time_first;
                        graph->window_last = flow.time_first + graph->params->time_window;
                        goto get;
                     } else {
                        params->flush_cnt ++;
                        graph->window_last = graph->window_last + params->time_window;
                     }
                  }
                  // Shifting beginning of window, if not first window.
                  if (graph->window_cnt != 0) {
                     graph->window_first += params->interval;
                  }
                  reset_graph(graph);
                  graph->interval_first = graph->interval_last;
                  graph->interval_last = graph->interval_last + params->interval;
               }

               get:
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
   graph->interval_idx = (graph->interval_idx + 1) % graph->params->intvl_max;
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
