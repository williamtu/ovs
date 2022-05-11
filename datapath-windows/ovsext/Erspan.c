/*
 * Copyright (c) 2022 VMware, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "precomp.h"

#include "Atomic.h"
#include "Debug.h"
#include "Flow.h"
#include "Gre.h"
#include "IpHelper.h"
#include "NetProto.h"
#include "Offload.h"
#include "PacketIO.h"
#include "PacketParser.h"
#include "Switch.h"
#include "User.h"
#include "Util.h"
#include "Vport.h"

static NDIS_STATUS
OvsDoEncapErspan(POVS_VPORT_ENTRY vport,
                 PNET_BUFFER_LIST curNbl,
                 const OvsIPTunnelKey *tunKey,
                 const POVS_FWD_INFO fwdInfo,
                 POVS_PACKET_HDR_INFO layers,
                 POVS_SWITCH_CONTEXT switchContext,
                 PNET_BUFFER_LIST *newNbl);

/*
 * --------------------------------------------------------------------------
 * OvsInitErspanTunnel --
 *    Initialize ERSPAN tunnel module.
 * --------------------------------------------------------------------------
 */
NTSTATUS
OvsInitErspanTunnel(POVS_VPORT_ENTRY vport)
{
    POVS_ERSPAN_VPORT ersPort;

    ersPort = (POVS_ERSPAN_VPORT)OvsAllocateMemoryWithTag(sizeof(*ersPort),
                                                          OVS_ERSPAN_POOL_TAG);
	if (!ersPort) {
		OVS_LOG_ERROR("can't allocate OVS_ERSPAN_VPORT");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(ersPort, sizeof(*ersPort));
	vport->priv = (PVOID)ersPort;
	return STATUS_SUCCESS;
}

/*
 * --------------------------------------------------------------------------
 * OvsCleanupErspanTunnel --
 *    Cleanup ERSPAN Tunnel module.
 * --------------------------------------------------------------------------
 */
void
OvsCleanupErspanTunnel(POVS_VPORT_ENTRY vport)
{
	if (vport->ovsType != OVS_VPORT_TYPE_ERSPAN ||
		vport->priv == NULL) {
		return;
	}
	OvsFreeMemoryWithTag(vport->priv, OVS_ERSPAN_POOL_TAG);
	vport->priv = NULL;
}

/*
 * --------------------------------------------------------------------------
 * OvsEncapErspan --
 *     Encapsulates a packet with an ERSPAN header.
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
OvsEncapErspan(POVS_VPORT_ENTRY vport,
               PNET_BUFFER_LIST curNbl,
               OvsIPTunnelKey *tunKey,
               POVS_SWITCH_CONTEXT switchContext,
               POVS_PACKET_HDR_INFO layers,
               PNET_BUFFER_LIST *newNbl,
               POVS_FWD_INFO switchFwdInfo)
{
    OVS_FWD_INFO fwdInfo;
    NDIS_STATUS status;

    if (tunKey->dst.si_family != AF_INET) {
        return NDIS_STATUS_FAILURE;
    }

    status = OvsLookupIPhFwdInfo(tunKey->src, tunKey->dst, &fwdInfo);
    if (status != STATUS_SUCCESS) {
        OvsFwdIPHelperRequest(NULL, 0, tunKey, NULL, NULL, NULL);
        return NDIS_STATUS_FAILURE;
    }

    RtlCopyMemory(switchFwdInfo->value, fwdInfo.value, sizeof fwdInfo.value);

    status = OvsDoEncapErspan(vport, curNbl, tunKey, &fwdInfo, layers,
                              switchContext, newNbl);
    return status;
}

/*
 * --------------------------------------------------------------------------
 * OvsDoEncapErspan --
 *    Internal utility function which actually does the ERSPAN encap.
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
OvsDoEncapErspan(POVS_VPORT_ENTRY vport,
                 PNET_BUFFER_LIST curNbl,
                 const OvsIPTunnelKey *tunKey,
                 const POVS_FWD_INFO fwdInfo,
                 POVS_PACKET_HDR_INFO layers,
                 POVS_SWITCH_CONTEXT switchContext,
                 PNET_BUFFER_LIST *newNbl)
{
    NDIS_STATUS status;
    PNET_BUFFER curNb;
    PMDL curMdl;
    PUINT8 bufferStart;
    EthHdr *ethHdr;
    IPHdr *ipHdr;
    PGREHdr greHdr;
    PERSPANDHdr ersHdr;
    POVS_ERSPAN_VPORT vportErs;
    PCHAR pChk = NULL;
    UINT32 headRoom = 16; 
#if DBG
    UINT32 counterHeadRoom;
#endif
    UINT32 packetLength;
    ULONG mss = 0;
	UINT32 seqno = 0;
    ASSERT(*newNbl == NULL);

    curNb = NET_BUFFER_LIST_FIRST_NB(curNbl);
    packetLength = NET_BUFFER_DATA_LENGTH(curNb);

    if (layers->isTcp) {
        mss = OVSGetTcpMSS(curNbl);

        OVS_LOG_TRACE("MSS %u packet len %u", mss,
                      packetLength);
        if (mss) {
            OVS_LOG_TRACE("l4Offset %d", layers->l4Offset);
            *newNbl = OvsTcpSegmentNBL(switchContext, curNbl, layers,
                                       mss, headRoom, FALSE);
            if (*newNbl == NULL) {
                OVS_LOG_ERROR("Unable to segment NBL");
                return NDIS_STATUS_FAILURE;
            }
            /* Clear out LSO flags after this point */
            NET_BUFFER_LIST_INFO(*newNbl, TcpLargeSendNetBufferListInfo) = 0;
        }
    }

    vportErs = (POVS_ERSPAN_VPORT)GetOvsVportPriv(vport);
    ASSERT(vportErs);

    /* If we didn't split the packet above, make a copy now. */
    if (*newNbl == NULL) {
        *newNbl = OvsPartialCopyNBL(switchContext, curNbl, 0, headRoom
                                    FALSE /* NBL info */);//why copy
        if (*newNbl == NULL) {
            OVS_LOG_ERROR("Unable to copy NBL");
            return NDIS_STATUS_FAILURE;
        }

        NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO csumInfo;
        csumInfo.Value = NET_BUFFER_LIST_INFO(curNbl,
                                              TcpIpChecksumNetBufferListInfo);
        status = OvsApplySWChecksumOnNB(layers, *newNbl, &csumInfo);
        if (status != NDIS_STATUS_SUCCESS) {
            goto ret_error;
        }
    }

    curNbl = *newNbl;
    for (curNb = NET_BUFFER_LIST_FIRST_NB(curNbl); curNb != NULL;
         curNb = curNb->Next) {
#if DBG
        counterHeadRoom = headRoom;
#endif
        status = NdisRetreatNetBufferDataStart(curNb, headRoom, 0, NULL);
        if (status != NDIS_STATUS_SUCCESS) {
            goto ret_error;
        }

        curMdl = NET_BUFFER_CURRENT_MDL(curNb);
        bufferStart = (PUINT8)OvsGetMdlWithLowPriority(curMdl);
        if (!bufferStart) {
            status = NDIS_STATUS_RESOURCES;
            goto ret_error;
        }

        bufferStart += NET_BUFFER_CURRENT_MDL_OFFSET(curNb);
        if (NET_BUFFER_NEXT_NB(curNb)) {
            OVS_LOG_TRACE("nb length %u next %u",
                          NET_BUFFER_DATA_LENGTH(curNb),
                          NET_BUFFER_DATA_LENGTH(curNb->Next));
        }

        /* L2 header */
        ethHdr = (EthHdr *)bufferStart;
        NdisMoveMemory(ethHdr->Destination, fwdInfo->dstMacAddr,
                       sizeof ethHdr->Destination);
        NdisMoveMemory(ethHdr->Source, fwdInfo->srcMacAddr,
                       sizeof ethHdr->Source);
        ethHdr->Type = htons(ETH_TYPE_IPV4);
#if DBG
        counterHeadRoom -= sizeof *ethHdr;
#endif
        /* IP header */
        ipHdr = (IPHdr *)((PCHAR)ethHdr + sizeof *ethHdr);

        ipHdr->ihl = sizeof *ipHdr / 4;
        ipHdr->version = IPPROTO_IPV4;
        ipHdr->tos = tunKey->tos;
        ipHdr->tot_len = htons(NET_BUFFER_DATA_LENGTH(curNb) - sizeof *ethHdr);
        ipHdr->id = (uint16)atomic_add64(&vportErs->ipId,
                                         NET_BUFFER_DATA_LENGTH(curNb));
        ipHdr->frag_off = (tunKey->flags & OVS_TNL_F_DONT_FRAGMENT) ?
                          IP_DF_NBO : 0;
        ipHdr->ttl = tunKey->ttl ? tunKey->ttl : 64;
        ipHdr->protocol = IPPROTO_GRE;
#if DBG
        counterHeadRoom -= sizeof *ipHdr;
#endif
        /* GRE base header */
        greHdr = (GREHdr *)((PCHAR)ipHdr + sizeof *ipHdr);
        greHdr->flags = GRE_SEQ; /* ERSPAN has fixed GRE header */
        greHdr->protocolType = htons(ETH_P_ERSPAN);

		/* GRE sequence number */
        PCHAR currentOffset = (PCHAR)greHdr + sizeof *greHdr;
		seqno = htonl(vportErs->seqno++);
        RtlCopyMemory(currentOffset, &seqno, sizeof seqno);

        /* ERSPAN header, check erspan_build_header, erspan_xmit */
		/* Build ERSPAN base header */
		ersHdr = (ERSPANHdr *)((PCHAR)greHdr + 8);
        ersHdr->ver = ERSPAN_VERSION;
        ersHdr->cos = TosToCos(ipHdr->tos); 
		ersHdr->en = ERSPAN_ENCAP_NOVLAN;
		ersHdr->t = 0;

		SetVlan(ersHdr, vportErs->vlan);
		/* Use tunnel ID as session ID */
        UINT32 key = (tunKey->tunnelId >> 32);
		SetSessionId(ersHdr, key);
		idx = (ovs_be32 *)(ersHdr + 1);	
		*idx = 0; 
#if DBG
        counterHeadRoom -= sizeof *greHdr;
#endif

        if (tunKey->flags & OVS_TNL_F_CSUM) {
			OVS_LOG_WARN("ERSPAN does not support CSUM");
        }

        if (tunKey->flags & OVS_TNL_F_KEY) {
            RtlZeroMemory(currentOffset, 4);
            UINT32 key = (tunKey->tunnelId >> 32);
            RtlCopyMemory(currentOffset, &key, sizeof key);
            currentOffset += 4;
        }
    }
    return STATUS_SUCCESS;

ret_error:
    OvsCompleteNBL(switchContext, *newNbl, TRUE);
    *newNbl = NULL;
    return satus;
}

/*
 * --------------------------------------------------------------------------
 * OvsDecapErspan --
 *    Decapsulates a packet with an ERSPAN header.
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
OvsDecapErspan(POVS_SWITCH_CONTEXT switchContext,
               PNET_BUFFER_LIST curNbl,
               OvsIPTunnelKey *tunKey,
               PNET_BUFFER_LIST *newNbl)
{
    PNET_BUFFER curNb;
    PMDL curMdl;
    EthHdr *ethHdr;
    IPHdr *ipHdr;
    GREHdr *greHdr;
    ERSPANHdr *ersHdr;
    UINT32 tunnelSize, packetLength;
    UINT32 headRoom = 0;
    UINT32 maxGreLen;
    PUNIT8 bufferStart;
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    PCHAR tempBuf = NULL;
    OVS_PACKET_HDR_INFO layers;
    const greHdrLen = 8, ersHdrLen = 8; /* Fixed GRE/ERSPAN header. */

    ASSERT(*newNbl == NULL);
    *newNbl = NULL;

    if (tunKey->dst.si_family != AF_INET) {
        return NDIS_STATUS_FAILURE;
    }

    status = OvsExtractLayers(curNbl, &layers);
    if (status != NDIS_STATUS_SUCCESS) {
        return status;
    }

    curNb = NET_BUFFER_LIST_FIRST_NB(curNbl);
    packetLength = NET_BUFFER_DATA_LENGTH(curNb);
    curMdl = NET_BUFFER_CURRENT_MLD(curNb);
    tunnelSize = GreHdrLen + ersHdrLen;
    if (packetLength <= tunnelSize) {
        return NDIS_STATUS_INVALID_LENGTH;
    }
    maxGreLen = GreMaxLengthFromLayers(&layers) + ersHdrLen;

    /* Get a contiguous buffer for the maximum length of a GRE header */
    bufferStart = NdisGetDataBuffer(curNb, maxGreLen, NULL, 1, 0);
    if (!bufferStart) {
        /* Documentation is unclear on where the packet can be fragmented.
         * For the moment allocate the buffer needed to get the maximum length
         * of a GRE header contiguous */
         tempBuf = OvsAllocateMemoryWithTag(maxGreLen, OVS_GRE_POOL_TAG);
         if (!tempBuf) {
            status = NDIS_STATUS_RESOURCES;
            goto end;
         }
         RtlZeroMemory(tempBuf, maxGreLen);
         bufferStart = NdisGetDataBuffer(curNb, maxGreLen, tempBuf,
                                         1, 0);
         if (!bufferStart) {
            status = NDIS_STATUS_RESOURCES;
            goto end;
         }
    }

    ethHdr = (EthHdr *)bufferStart;
    headRoom += layers.l3Offset;

    ipHdr = (IPHdr *)(bufferStart + layers.l3Offset);
    tunKey->src.Ipv4.sin_addr.s_addr = ipHdr->saddr;
    tunKey->src.Ipv4.sin_family = AF_INET;
    tunKey->dst.Ipv4.sin_addr.s_addr = ipHdr->daddr;
    tunKey->dst.Ipv4.sin_family = AF_INET;

    tunKey->tos = ipHdr->tos;
    tunKey->ttl = ipHdr->ttl;
    tunKey->pad = 0;
    headRoom += sizeof *ipHdr;

    greHdr = (GREHdr *)(bufferStart + layers.l4Offset);
    /* ESPAN header has fixed 8-byte GRE header */
    ersHdr = (ERSPANHdr *)(bufferStart + layers.l4Offset + 8);
    OVS_LOG_INFO("Decap ERSPAN: version %u session id %u",
                  ersHdr->ver, ersHdr->session_id);

    headRoom += sizeof *greHdr;

    tunnelSize = GreTunHdrSizeFromLayers(greHdr->flags, &layers);

    /* Verify the packet length after looking at the GRE flags */
    if (packetLength <= tunnelSize) {
        status = NDIS_STATUS_INVALID_LENGTH;
        goto end;
    }

    /* Validate if ERSPAN header protocol type */
    if (greHdr->protocolType != htons(ETH_P_ERSPAN)) {
        OVS_LOG_ERROR("not erspan packet");
        status = STATUS_NDIS_INVALID_PACKET;
        goto end;
    }

    PCHAR currentOffset = (PCHAR)greHdr + sizeof *greHdr;
    if (greHdr->flags & GRE_KEY || greHdr->flags & GRE_CSUM) {
        OVS_LOG_ERROR("ERSPAN packet should not have GRE CSUM/KEY");
        status = STATUS_NDIS_INVALID_PACKET;
        goto end;
    }

    /*
     * Create a copy of the NBL so that we have all the headers in one MDL.
     */
    *newNbl = OvsPartialCopyNBL(switchContext, curNbl,
                                tunnelSize, 0,
                                TRUE /* copy NBL info */);
    if (*newNbl == NULL) {
        status = NDIS_STATUS_RESOURCES;
        goto end;
    }
    curNbl = *newNbl;
    curNb = NET_BUFFER_LIST_FIRST_NB(curNbl);

    OVS_LOG_INFO("set erspan to tunnelID %u", ntohl(ersHdr->session_id));
    tunKey->tunnelId = (UINT64)(ntohl(ersHdr->session_id) << 32);

    /* Clear out the receive flag for the inner packet. */
    NET_BUFFER_LIST_INFO(curNbl, TcpIpChecksumNetBufferListInfo) = 0;
    NdisAdvanceNetBufferDataStart(curNb, 16, FALSE,
                                  NULL);
end:
    if (tempBuf) {
        OvsFreeMemoryWithTag(tempBuf, OVS_ERSPAN_POOL_TAG);
        tempBuf = NULL;
    }
    return status;
}
