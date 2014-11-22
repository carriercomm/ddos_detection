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

#include "ddos_detection.h"

static char failure = 0; /*!< Global error flag. */

params_t *params_init(int argc, char **argv)
{
   char *description, opt, usage[BUFFER_TMP], tmp[BUFFER_TMP];
   params_t *params;

   description =
      "DDoS Detection\n"
      "Module for detecting and analyzing potential DDoS attacks in computer networks.\n"
      "Special parameters:\n"
      "  -d NUM       Set the mode of DDoS detection, SYN flooding by default.\n"
      "  -f PATH      Set the path of CSV file to be examined.\n"
      "  -L LEVEL     Print graphs based on given verbosity level, range 1 to 5.\n"
      "  -p NUM       Show progress - print a dot every N flows.\n"
      "  -t TIME      Set the observation time window in seconds, 1 minute by default.\n"
      "  -w TIME      Set the observation time window in seconds, 1 hour by default.\n"
      "Detection modes:\n"
      "   1) SYN flooding detection\n"
      "   2) Horizontal port scanning detection\n"
      "   3) Vertical port scanning detection\n";


   params = (params_t *) calloc(1, sizeof(params_t));
   if (params == NULL) {
      fprintf(stderr, "Error: Not enough memory for parameters structure.\n");
      return NULL;
   }

   params->mode = MODE_SYN_FLOODING;
   params->progress = 0;
   params->level = 0;
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
         case 'f':
            params->file = optarg;
            break;
         case 'h':
            fprintf(stderr, "%s\n", description);
            break;
         case 'H':
            fprintf(stderr, "%s\n", description);   
            break;
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
   return params;

   // Cleaning up after error.
   error:
      if (params != NULL) {
         free(params);
      }
      return NULL;
}

int main(int argc, char **argv)
{
   params_t *params;
   
   
   // Parsing input parameters.
   params = params_init(argc, argv);
   if (params == NULL) {
      failure = 1;
      goto cleanup;
   }
   
   // Cleaning up allocated structures.
   cleanup:
      if (params != NULL) {
         free(params);
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
