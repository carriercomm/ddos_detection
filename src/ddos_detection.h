/*!
 * \file ddos_detection.h
 * \brief Header file to detection logic library.
 * \author Jan Neuzil <neuzija1@fit.cvut.cz>
 * \date 2014
 */
/*
 * Copyright (C) 2014 ISEP
 */

#ifndef _DDOS_DETECTION_
#define _DDOS_DETECTION_

#include "graph.h"

/*!
 * \brief Detection handler
 * Function to decide which detection mode and algorithm will be used
 * based on initialized parameters given in command line.
 * \param[in] graph Pointer to existing graph structure.
 * \return Pointer to graph structure on success, otherwise NULL.
 */
graph_t *detection_handler(graph_t *graph);

#endif /* _DDOS_DETECTION_ */
