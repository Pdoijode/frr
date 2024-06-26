// SPDX-License-Identifier: GPL-2.0-or-later
/* ospfd memory type declarations
 *
 * Copyright (C) 2015  David Lamparter
 */

#ifndef _QUAGGA_OSPF_MEMORY_H
#define _QUAGGA_OSPF_MEMORY_H

#include "memory.h"

DECLARE_MGROUP(OSPFD);
DECLARE_MTYPE(OSPF_TOP);
DECLARE_MTYPE(OSPF_AREA);
DECLARE_MTYPE(OSPF_AREA_RANGE);
DECLARE_MTYPE(OSPF_NETWORK);
DECLARE_MTYPE(OSPF_NEIGHBOR_STATIC);
DECLARE_MTYPE(OSPF_IF);
DECLARE_MTYPE(OSPF_NEIGHBOR);
DECLARE_MTYPE(OSPF_ROUTE);
DECLARE_MTYPE(OSPF_TMP);
DECLARE_MTYPE(OSPF_LSA);
DECLARE_MTYPE(OSPF_LSA_DATA);
DECLARE_MTYPE(OSPF_LSDB);
DECLARE_MTYPE(OSPF_PACKET);
DECLARE_MTYPE(OSPF_FIFO);
DECLARE_MTYPE(OSPF_VERTEX);
DECLARE_MTYPE(OSPF_VERTEX_PARENT);
DECLARE_MTYPE(OSPF_NEXTHOP);
DECLARE_MTYPE(OSPF_PATH);
DECLARE_MTYPE(OSPF_VL_DATA);
DECLARE_MTYPE(OSPF_CRYPT_KEY);
DECLARE_MTYPE(OSPF_EXTERNAL_INFO);
DECLARE_MTYPE(OSPF_DISTANCE);
DECLARE_MTYPE(OSPF_IF_INFO);
DECLARE_MTYPE(OSPF_IF_PARAMS);
DECLARE_MTYPE(OSPF_MESSAGE);
DECLARE_MTYPE(OSPF_MPLS_TE);
DECLARE_MTYPE(OSPF_ROUTER_INFO);
DECLARE_MTYPE(OSPF_PCE_PARAMS);
DECLARE_MTYPE(OSPF_SR_PARAMS);
DECLARE_MTYPE(OSPF_EXT_PARAMS);
DECLARE_MTYPE(OSPF_GR_HELPER);
DECLARE_MTYPE(OSPF_EXTERNAL_RT_AGGR);
DECLARE_MTYPE(OSPF_P_SPACE);
DECLARE_MTYPE(OSPF_Q_SPACE);
DECLARE_MTYPE(OSPF_LSA_LIST);
DECLARE_MTYPE(OSPF_LSDB_NODE);

#endif /* _QUAGGA_OSPF_MEMORY_H */
