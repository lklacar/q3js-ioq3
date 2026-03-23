#ifndef NET_WT_H
#define NET_WT_H

#include "qcommon.h"

qboolean	NET_WT_GetCvars( void );
qboolean	NET_UseWebTransport( void );
void		NET_WT_Config( qboolean enableNetworking );
qboolean	NET_WT_StringToAdr( const char *s, netadr_t *a, netadrtype_t family );
qboolean	NET_WT_GetPacket( netadr_t *net_from, msg_t *net_message );
void		NET_WT_SendPacket( int length, const void *data, netadr_t to );
qboolean	NET_WT_CompareBaseAdrMask( netadr_t a, netadr_t b, int netmask );
qboolean	NET_WT_CompareAdr( netadr_t a, netadr_t b );
const char	*NET_WT_AdrToString( netadr_t a );
const char	*NET_WT_AdrToStringwPort( netadr_t a );
qboolean	NET_WT_IsLocalAddress( netadr_t adr );
qboolean	NET_WT_IsLANAddress( netadr_t adr );
qboolean	NET_WT_ShouldUseLiteralAddress( const char *s, netadrtype_t family );

#endif
