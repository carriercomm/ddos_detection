/*!
 * \file main.c
 * \brief DDoS detection system using clustering analysis.
 * \author Jan Neuzil <neuzija1@fit.cvut.cz>
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

#include "parser.h"

int main(int argc, char **argv)
{
   int failure;
   params_t *params;
   graph_t *graph;

   failure = 0;
   graph = NULL;

   // Parsing input parameters.
   params = parse_params(argc, argv);
   if (params == NULL) {
      failure = 1;
      goto cleanup;
   }

   // Running the help mode, end of program.
   if (params->file == NULL) {
      goto cleanup; 
   }

   // Running the detection.
   graph = parse_data(params);
   if (graph == NULL) {
      failure = 1;
      goto cleanup;
   }

   // Cleaning up allocated structures.
   cleanup:
      if (graph != NULL) {
         free_graph(graph);
      }
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
