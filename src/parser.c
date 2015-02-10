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

static uint16_t known_ports[KNOWN_PORTS] = {
   20, // FTP
   21, // FTP
   22, // SSH
   23, // Telnet
   25, // SMTP
   53, // DNS
   80, // HTTP
   110, // POP3
   143, // IMAP
   161, // SNMP
   443, // HTTPS
   3389, // RDP
   4949, // Munin
   5800, // VNC
   5900, // VNC
   10050 // Zabbix
}; /*!< List of well known ports. */

params_t *parse_params(int argc, char **argv)
{
   char *description, opt, usage[BUFFER_TMP], tmp[BUFFER_TMP];
   params_t *params;

   description =
      "DDoS Detection\n"
      "Module for detecting and analyzing potential DDoS attacks in computer networks.\n"
      "\nSpecial parameters:\n"
      "  -d NUM       Set the mode bit of DDoS detection, SYN flooding by default.\n"
      "  -e NUM       Set the number of iterations to flush the graph, 0 by default.\n"
      "  -f PATH      Set the path of CSV file to be examined.\n"
      "  -k NUM       Set the number of clusters used by k-means algorithm, 2 by default.\n"
      "  -L LEVEL     Print graphs based on given verbosity level, range 1 to 5.\n"
      "  -M LIMIT     Set the threshold for vertical port scan attack, 8192 by default.\n"
      "  -N LIMIT     Set the threshold for horizontal port scan attack, 4096 by default.\n"
      "  -p NUM       Show progress - print a dot every N flows.\n"
      "  -t TIME      Set the observation interval in seconds, 1 minute by default.\n"
      "  -w TIME      Set the observation time window in seconds, 1 hour by default.\n"
      "\nDetection modes:\n"
      "   1) SYN flooding detection only.\n"
      "   2) Vertical port scanning detection only.\n"
      "   3) SYN flooding and vertical port scanning detection.\n"
      "   4) Horizontal port scanning detection only.\n"
      "   5) SYN flooding and horizontal port scanning detection.\n"
      "   6) Vertical and horizontal port scanning detection.\n"
      "   7) All detections combined.\n"
      "\nK-means parameters:\n"
      "   - Number of clusters can be assigned between 2 and 255.\n";


   params = (params_t *) calloc(1, sizeof(params_t));
   if (params == NULL) {
      fprintf(stderr, "%sNot enough memory for parameters structure.\n", ERROR);
      return NULL;
   }

   params->mode = SYN_FLOODING;
   params->clusters = CLUSTERS;
   params->flush_cnt = 1;
   params->flush_iter = FLUSH_ITER;
   params->progress = 0;
   params->level = VERBOSITY;
   params->interval = INTERVAL;
   params->time_window = TIME_WINDOW;
   params->window_sum = 0;
   params->ver_threshold = VERTICAL_THRESHOLD;
   params->hor_threshold = HORIZONTAL_THRESHOLD;
   params->file = NULL;
   params->name = NULL;

   snprintf(usage, BUFFER_TMP, "Usage: %s -f FILE [OPTION]...\nTry `%s -h' for more information.\n", argv[0], argv[0]);

   while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
      switch (opt) {
         case 'd':
            if (strlen(optarg) > 1 || sscanf(optarg, "%d%s", &params->mode, tmp) != 1 || params->mode < 0 || params->mode > ALL_ATTACKS) {
              fprintf(stderr, "%sInvalid detection mode number.\n", ERROR);
              goto error;
            }
            break;
         case 'e':
            if (strlen(optarg) > NUMBER_LEN || sscanf(optarg, "%d%s", &params->flush_iter, tmp) != 1 || params->flush_iter < 0) {
              fprintf(stderr, "%sInvalid flush iteration number.\n", ERROR);
              goto error;
            }
            break;
         case 'f':
            params->file = optarg;
            break;
         case 'h':
            fprintf(stderr, "%s\n", description);
            return params;
         case 'H':
            fprintf(stderr, "%s\n", description);
            return params;
         case 'k':
            if (strlen(optarg) > 1 || sscanf(optarg, "%d%s", &params->clusters, tmp) != 1 || params->clusters < CLUSTERS || params->clusters > CLUSTERS_MAX) {
              fprintf(stderr, "%sInvalid number of clusters to be used in k-means algorithm.\n", ERROR);
              goto error;
            }
         case 'L':
            if (strlen(optarg) > 1 || sscanf(optarg, "%d%s", &params->level, tmp) != 1 || params->level < 0 || params->level > NUMBER_LEN) {
              fprintf(stderr, "%sInvalid verbosity level.\n", ERROR);
              goto error;
            }
            break;
         case 'M':
            if (strlen(optarg) > NUMBER_LEN || sscanf(optarg, "%d%s", &params->ver_threshold, tmp) != 1 || params->interval <= 0) {
              fprintf(stderr, "%sInvalid vertical port scan threshold.\n", ERROR);
              goto error;
            }
            break;
         case 'N':
            if (strlen(optarg) > NUMBER_LEN || sscanf(optarg, "%d%s", &params->hor_threshold, tmp) != 1 || params->interval <= 0) {
              fprintf(stderr, "%sInvalid horizontal port scan threshold.\n", ERROR);
              goto error;
            }
            break;
         case 'p':
            if (strlen(optarg) > NUMBER_LEN || sscanf(optarg, "%d%s", &params->progress, tmp) != 1 || params->progress < 0) {
              fprintf(stderr, "%sInvalid progress dot number.\n", ERROR);
              goto error;
            }
            break;
         case 't':
            if (strlen(optarg) > NUMBER_LEN || sscanf(optarg, "%d%s", &params->interval, tmp) != 1 || params->interval <= 0) {
              fprintf(stderr, "%sInvalid SYN packets observation interval.\n", ERROR);
              goto error;
            }
            break;
         case 'w':
            if (strlen(optarg) > NUMBER_LEN || sscanf(optarg, "%d%s", &params->time_window, tmp) != 1 || params->time_window <= 0) {
              fprintf(stderr, "%sInvalid observation time window.\n", ERROR);
              goto error;
            }
            break;
         default:
            fprintf(stderr, "%sToo many arguments.\n", ERROR);
            goto error;
      }
   }

   if (params->file == NULL) {
      fprintf(stderr, "%sYou must specify a data file.\n", ERROR);
      goto error;
   }

   // Determining maximum number for SYN packets array based on time window and observation intervals.
   params->intvl_max = (params->time_window / params->interval) + ARRAY_EXTRA;
   if (params->intvl_max <= ARRAY_MIN) {
      fprintf(stderr, "%sTime window cannot be less or closely equal than observation interval.\n", ERROR);
      goto error;
   }
   params->iter_max = PORT_WINDOW / params->interval;

   return params;

   // Cleaning up after error.
   error:
      fprintf(stderr, "%s", usage);
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
      fprintf(stderr, "%sMissing destination IP address, parsing interrupted.\n", WARNING);
      return EXIT_FAILURE;
   }
   if (inet_pton(AF_INET, dst_ip, &(flow->dst_ip)) != 1) {
         fprintf(stderr, "%sCannot convert string to destination IP address, parsing interrupted.\n", WARNING);
         return EXIT_FAILURE;
   }

   src_ip = parse_token(&line, &len);
   if (src_ip == NULL) {
      fprintf(stderr, "%sMissing source IP address, parsing interrupted.\n", WARNING);
      return EXIT_FAILURE;
   }
   if (inet_pton(AF_INET, src_ip, &(flow->src_ip)) != 1) {
         fprintf(stderr, "%sCannot convert string to source IP address, parsing interrupted.\n", WARNING);
         return EXIT_FAILURE;
   }

   dst_port = parse_token(&line, &len);
   if (dst_port == NULL) {
      fprintf(stderr, "%sMissing destination port, parsing interrupted.\n", WARNING);
      return EXIT_FAILURE;
   }
   flow->dst_port = atoi(dst_port);
   if (flow->dst_port < 0 || flow->dst_port > ALL_PORTS) {
      fprintf(stderr, "%sInvalid destination port number, parsing interrupted.\n", WARNING);
      return EXIT_FAILURE;
   }

   src_port = parse_token(&line, &len);
   if (src_port == NULL) {
      fprintf(stderr, "%sMissing source port, parsing interrupted.\n", WARNING);
      return EXIT_FAILURE;
   }
   flow->src_port = atoi(src_port);
   if (flow->dst_port < 0 || flow->dst_port > ALL_PORTS) {
      fprintf(stderr, "%sInvalid source port number, parsing interrupted.\n", WARNING);
      return EXIT_FAILURE;
   }

   protocol = parse_token(&line, &len);
   if (protocol == NULL) {
      fprintf(stderr, "%sMissing used protocol, parsing interrupted.\n", WARNING);
      return EXIT_FAILURE;
   }
   flow->protocol = atoi(protocol);

   time_first = parse_token(&line, &len);
   if (time_first == NULL) {
      fprintf(stderr, "%sMissing time of the first packet, parsing interrupted.\n", WARNING);
      return EXIT_FAILURE;
   }
   flow->time_first = atoi(time_first);

   // Unknown field, skipping token.
   parse_token(&line, &len);

   time_last = parse_token(&line, &len);
   if (time_last == NULL) {
      fprintf(stderr, "%sMissing time of the last packet, parsing interrupted.\n", WARNING);
      return EXIT_FAILURE;
   }
   flow->time_last = atoi(time_last);

   bytes = parse_token(&line, &len);
   if (bytes == NULL) {
      fprintf(stderr, "%sMissing number of transmitted bytes, parsing interrupted.\n", WARNING);
      return EXIT_FAILURE;
   }
   flow->bytes = atoi(bytes);

   packets = parse_token(&line, &len);
   if (packets == NULL) {
      fprintf(stderr, "%sMissing number of transmitted packets, parsing interrupted.\n", WARNING);
      return EXIT_FAILURE;
   }
   flow->packets = atoi(packets);

   syn_flag = parse_token(&line, &len);
   if (syn_flag == NULL) {
      fprintf(stderr, "%sMissing SYN flag, parsing interrupted.\n", WARNING);
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
      fprintf(stderr, "%sDelayed flow record, parsing interrupted.\n", WARNING);
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

   j = k = 0;
   cnt_flows = 0;
   status = 0;
   memset(buffer, 0, BUFFER_SIZE);
   tmp = buffer;
   graph = NULL;

   graph = create_graph(params);
   if (graph == NULL) {
      goto error;
   }

   // Creating pipe for standard output.
   if (pipe(pipefd) != 0) {
      fprintf(stderr, "%sCannot create a pipe.\n", ERROR);
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
            fprintf(stderr, "%sCannot open given file.\n", ERROR);
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
      fprintf(stderr, "%sCannot fork process.\n", ERROR);
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
                  graph->interval_cnt ++;
                  if (graph->params->progress > 0) {
                     fprintf(stderr, "\n");
                  }
                  // Shifting to the next interval.
                  graph->interval_idx = (graph->interval_idx + 1) % graph->params->intvl_max;

                  // Starting detection.
                  parse_detection(graph);

                  // Time window reached.
                  if (flow.time_first >= graph->window_last) {
                     graph->params->window_sum ++;
                     graph->window_cnt ++;
                     // Cleaning graph.
                     if (params->flush_cnt == params->flush_iter) {
                        fprintf(stderr, "%sTime window reached, flushing whole graph.\n", INFO);
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
         fprintf(stderr, "%sChild process does not respond.\n", ERROR);
         goto error;;
      }
   }

   if (graph->params->progress > 0) {
      fprintf(stderr, "\n");
   }
   fprintf(stderr,"%sAll data have been successfully processed, processing residues.\n", INFO);
   graph->interval_idx = (graph->interval_idx + 1) % graph->params->intvl_max;
   parse_detection(graph);
   return graph;

   // Cleaning up after error.
   error:
      if (graph != NULL) {
         free_graph(graph);
      }
      return NULL;
}

void parse_detection(graph_t *graph)
{
   char flag;
   int i, j;

   if (((graph->params->mode & SYN_FLOODING) == SYN_FLOODING) && (graph->interval_cnt > CONVERGENCE)) {
      if (graph->params->level > VERBOSITY) {
         fprintf(stderr, "%sStarting SYN flooding detection.\n", INFO);
      }
      batch_cluster(graph);
   }

   if ((graph->params->mode & VER_PORTSCAN) == VER_PORTSCAN) {
      if (graph->params->level > VERBOSITY) {
         fprintf(stderr, "%sStarting vertical port scan detection.\n", INFO);
      }
      for (i = 0; i < ALL_PORTS; i ++) {
         if (graph->ports[i].accesses > 0) {
            graph->ports_ver ++;
         }
      }
      if (graph->ports_ver > graph->params->ver_threshold) {
         graph->attack += VER_PORTSCAN;
         fprintf(stderr, "%sVertical port scan attack detected!\n", WARNING);
      }
   }

   if ((graph->params->mode & HOR_PORTSCAN) == HOR_PORTSCAN) {
      if (graph->params->level > VERBOSITY) {
         fprintf(stderr, "%sStarting horizontal port scan detection.\n", INFO);
      }
      qsort(graph->ports, ALL_PORTS, sizeof(port_t), compare_port);
      for (i = 0; i < ALL_PORTS; i ++) {
         flag = 0;
         for (j = 0; j < KNOWN_PORTS; j ++) {
            if (graph->ports[i].port_num == known_ports[j]) {
               flag = 1;
               break;
            }
         }

         // Non well-known port found among the highest accesses values.
         if (flag == 0) {
            graph->ports_hor = graph->ports[i].accesses;
            break;
         }
      }
      if (graph->ports_hor > graph->params->hor_threshold) {
         graph->attack += HOR_PORTSCAN;
         fprintf(stderr, "%sHorizontal port scan attack detected!\n", WARNING);
      }
   }

   print_graph(graph);
   if (graph->params->level > VERBOSITY) {
      fprintf(stderr, "%sDetection for given interval finished, results available.\n", INFO);
   }
}
