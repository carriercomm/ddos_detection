/*!
 * \file ddos_detection.h
 * \brief Header file to DDoS detection system.
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

#ifndef _DDOS_DETECTION_
#define _DDOS_DETECTION_

#include <stdio.h>
#include <stdlib.h>

/*!
 * \brief Main function.
 * Main function to parse given arguments and run the DDoS detection system.
 * \param[in] argc Number of given parameters.
 * \param[in] argv Array of given parameters.
 * \return EXIT_SUCCESS on success, otherwise EXIT_FAILURE.
 */
int main(int argc, char **argv);

#endif /* _DDOS_DETECTION_ */
