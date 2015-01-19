/*!
 * \file parser.h
 * \brief Header file to parsing functions library.
 * \author Jan Neuzil <neuzija1@fit.cvut.cz>
 * \date 2014
 */
/*
 * Copyright (C) 2014 ISEP
 */

#ifndef _PARSER_
#define _PARSER_

#include "graph.h"

/*!
 * \brief Parameters initialization.
 * Function to initialize parameters with default values and parse parameters
 * given in command line.
 * \param[in] argc Number of given parameters.
 * \param[in] argv Array of given parameters.
 * \return Pointer to allocated structure with initialized parameters.
 */
params_t *parse_params(int argc, char **argv);

/*!
 * \brief Parsing function.
 * Function to parse given line into tokens based on given delimeter.
 * \param[in,out] string Current pointer to token in line.
 * \param[in,out] len Current remaining characters in line.
 * \return Pointer to the beginning of the token, NULL for empty value.
 */
char *parse_token(char **string, int *len);

/*!
 * \brief Parsing function.
 * Function to parse given line to tokens and convert them into values
 * of the flow record structure.
 * \param[in] graph Pointer to existing graph structure.
 * \param[in] flow Pointer to flow record structure.
 * \param[in] line Pointer to string with line to be parsed.
 * \param[in] len Length of the line in bytes.
 * \return EXIT_SUCCESS on success, otherwise EXIT_FAILURE.
 */
int parse_line(graph_t *graph, flow_t *flow, char *line, int len);

/*!
 * \brief Parsing data function
 * Function to parse data using forking process through pipe. It opens a pipe
 * to redirect standard output which receives all desired data. It creates a new graph
 * structure which is filled with the parsed data. After a time window is reached,
 * the detection handler is launched.
 * \param[in] params Pointer to structure with all initialized parameters.
 * \return Pointer to graph structure on success, otherwise NULL.
 */
graph_t *parse_data(params_t *params);

/*!
 * \brief Detection handler
 * Function to decide which detection mode and algorithm will be used
 * based on initialized parameters given in command line.
 * \param[in] graph Pointer to existing graph structure.
 */
void parse_detection(graph_t *graph);

#endif /* _PARSER_ */
