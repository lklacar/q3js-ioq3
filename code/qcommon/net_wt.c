/*
===========================================================================
Copyright (C) 1999-2005 Id Software, Inc.

This file is part of Quake III Arena source code.

Quake III Arena source code is free software; you can redistribute it
and/or modify it under the terms of the GNU General Public License as
published by the Free Software Foundation; either version 2 of the License,
or (at your option) any later version.

Quake III Arena source code is distributed in the hope that it will be
useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Quake III Arena source code; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
===========================================================================
*/

#include "../qcommon/q_shared.h"
#include "../qcommon/qcommon.h"
#include "../qcommon/net_wt.h"

#ifdef __EMSCRIPTEN__
#include <emscripten/emscripten.h>
#endif

#define WT_MAX_ENDPOINTS 1024
#define WT_MAX_LABEL     128
#define WT_MAX_URL       512
#define WT_DEFAULT_PATH  "/quake3"

typedef struct {
	qboolean	inuse;
	unsigned int	id;
	unsigned short	port;
	char		url[WT_MAX_URL];
	char		label[WT_MAX_LABEL];
} wt_endpoint_t;

static cvar_t *net_transport;
static cvar_t *cl_wt_path;
static cvar_t *cl_wt_cert_hash;
static cvar_t *sv_wt_cert_file;
static cvar_t *sv_wt_key_file;
static cvar_t *sv_wt_path;
static cvar_t *sv_wt_allowed_origins;

static qboolean wt_backendActive = qfalse;
static wt_endpoint_t wt_endpoints[WT_MAX_ENDPOINTS];
static unsigned int wt_nextEndpointId = 1;
static char wt_stringBuffer[NET_ADDRSTRMAXLEN];

static unsigned int NET_WT_GetEndpointId( netadr_t a )
{
	return ((unsigned int)a.ip[0]) |
		((unsigned int)a.ip[1] << 8) |
		((unsigned int)a.ip[2] << 16) |
		((unsigned int)a.ip[3] << 24);
}

static void NET_WT_SetAddress( netadr_t *a, unsigned int id, unsigned short port )
{
	Com_Memset( a, 0, sizeof( *a ) );
	a->type = NA_WEBTRANSPORT;
	a->ip[0] = id & 0xff;
	a->ip[1] = ( id >> 8 ) & 0xff;
	a->ip[2] = ( id >> 16 ) & 0xff;
	a->ip[3] = ( id >> 24 ) & 0xff;
	a->port = BigShort( (short) port );
}

static wt_endpoint_t *NET_WT_FindEndpointById( unsigned int id )
{
	int i;

	for( i = 0; i < WT_MAX_ENDPOINTS; i++ )
	{
		if( wt_endpoints[i].inuse && wt_endpoints[i].id == id )
			return &wt_endpoints[i];
	}

	return NULL;
}

static wt_endpoint_t *NET_WT_FindEndpointByUrl( const char *url )
{
	int i;

	if( !url || !*url )
		return NULL;

	for( i = 0; i < WT_MAX_ENDPOINTS; i++ )
	{
		if( wt_endpoints[i].inuse && !Q_stricmp( wt_endpoints[i].url, url ) )
			return &wt_endpoints[i];
	}

	return NULL;
}

static wt_endpoint_t *NET_WT_AllocEndpoint( void )
{
	int i;

	for( i = 0; i < WT_MAX_ENDPOINTS; i++ )
	{
		if( !wt_endpoints[i].inuse )
		{
			Com_Memset( &wt_endpoints[i], 0, sizeof( wt_endpoints[i] ) );
			wt_endpoints[i].inuse = qtrue;
			return &wt_endpoints[i];
		}
	}

	return NULL;
}

static wt_endpoint_t *NET_WT_EnsureEndpoint( unsigned int id )
{
	wt_endpoint_t *endpoint;

	endpoint = NET_WT_FindEndpointById( id );
	if( endpoint )
		return endpoint;

	endpoint = NET_WT_AllocEndpoint();
	if( endpoint )
		endpoint->id = id;

	return endpoint;
}

static void NET_WT_UpdateEndpoint( unsigned int id, unsigned short port,
	const char *url, const char *label )
{
	wt_endpoint_t *endpoint = NET_WT_EnsureEndpoint( id );

	if( !endpoint )
		return;

	endpoint->port = port;

	if( url && *url )
		Q_strncpyz( endpoint->url, url, sizeof( endpoint->url ) );

	if( label && *label )
		Q_strncpyz( endpoint->label, label, sizeof( endpoint->label ) );
	else if( url && *url )
		Q_strncpyz( endpoint->label, url, sizeof( endpoint->label ) );
}

static wt_endpoint_t *NET_WT_AllocClientRoute( const char *url, const char *label,
	unsigned short port )
{
	wt_endpoint_t *endpoint = NET_WT_FindEndpointByUrl( url );

	if( endpoint )
	{
		NET_WT_UpdateEndpoint( endpoint->id, port, url, label );
		return endpoint;
	}

	endpoint = NET_WT_AllocEndpoint();
	if( !endpoint )
		return NULL;

	endpoint->id = wt_nextEndpointId++;
	NET_WT_UpdateEndpoint( endpoint->id, port, url, label );

	return endpoint;
}

static const char *NET_WT_DescribeEndpoint( netadr_t a )
{
	wt_endpoint_t *endpoint = NET_WT_FindEndpointById( NET_WT_GetEndpointId( a ) );

	if( endpoint )
	{
		if( endpoint->label[0] )
			return endpoint->label;
		if( endpoint->url[0] )
			return endpoint->url;
	}

	Com_sprintf( wt_stringBuffer, sizeof( wt_stringBuffer ), "peer-%u",
		NET_WT_GetEndpointId( a ) );
	return wt_stringBuffer;
}

#ifdef __EMSCRIPTEN__
EM_JS( int, NET_WT_JS_IsSupported, (void), {
	return Module.__ioq3WebTransport &&
		Module.__ioq3WebTransport.isSupported() ? 1 : 0;
} );

EM_JS( int, NET_WT_JS_NormalizeAddress,
	( const char *address, const char *default_path, char *url_out, int url_out_size,
	  char *label_out, int label_out_size, int *port_out ), {
	const state = Module.__ioq3WebTransport;
	if (!state) {
		return 0;
	}

	const result = state.normalizeAddress(
		UTF8ToString(address),
		UTF8ToString(default_path)
	);
	if (!result) {
		return 0;
	}

	stringToUTF8(result.url, url_out, url_out_size);
	stringToUTF8(result.label, label_out, label_out_size);
	HEAP32[port_out >> 2] = result.port | 0;
	return 1;
} );

EM_JS( void, NET_WT_JS_RegisterClientRoute,
	( int route_id, const char *url, const char *label, int port,
	  const char *cert_hashes ), {
	const state = Module.__ioq3WebTransport;
	if (!state) {
		return;
	}

	state.registerClientRoute(
		route_id,
		UTF8ToString(url),
		UTF8ToString(label),
		port,
		UTF8ToString(cert_hashes)
	);
} );

EM_JS( void, NET_WT_JS_StartServer,
	( int port, const char *host, const char *path, const char *cert_file,
	  const char *key_file, const char *allowed_origins ), {
	const state = Module.__ioq3WebTransport;
	if (!state) {
		return;
	}

	state.startServer({
		port,
		host: UTF8ToString(host),
		path: UTF8ToString(path),
		certFile: UTF8ToString(cert_file),
		keyFile: UTF8ToString(key_file),
		allowedOrigins: UTF8ToString(allowed_origins)
	});
} );

EM_JS( void, NET_WT_JS_Stop, (void), {
	if (Module.__ioq3WebTransport) {
		Module.__ioq3WebTransport.stop();
	}
} );

EM_JS( int, NET_WT_JS_SendPacket, ( int peer_id, const void *data, int length ), {
	const state = Module.__ioq3WebTransport;
	if (!state) {
		return 0;
	}

	return state.sendPacket(peer_id, HEAPU8.slice(data, data + length)) ? 1 : 0;
} );

EM_JS( int, NET_WT_JS_DequeuePacket,
	( void *data, int max_len, int *peer_id_out, int *port_out,
	  char *label_out, int label_out_size ), {
	const state = Module.__ioq3WebTransport;
	if (!state) {
		return 0;
	}

	const packet = state.dequeuePacket(max_len);
	if (!packet) {
		return 0;
	}

	HEAP32[peer_id_out >> 2] = packet.peerId | 0;
	HEAP32[port_out >> 2] = packet.port | 0;

	if (label_out_size > 0) {
		stringToUTF8(packet.label || "", label_out, label_out_size);
	}

	if (packet.length > max_len) {
		return -packet.length;
	}

	HEAPU8.set(packet.data, data);
	return packet.length;
} );
#endif

qboolean NET_WT_GetCvars( void )
{
	int modified = 0;

#ifdef __EMSCRIPTEN__
	net_transport = Cvar_Get( "net_transport", "webtransport", CVAR_LATCH | CVAR_ARCHIVE );
	modified += net_transport->modified;
	net_transport->modified = qfalse;

	cl_wt_path = Cvar_Get( "cl_wt_path", WT_DEFAULT_PATH, CVAR_ARCHIVE );
	modified += cl_wt_path->modified;
	cl_wt_path->modified = qfalse;

	cl_wt_cert_hash = Cvar_Get( "cl_wt_cert_hash", "", CVAR_ARCHIVE );
	modified += cl_wt_cert_hash->modified;
	cl_wt_cert_hash->modified = qfalse;

	sv_wt_cert_file = Cvar_Get( "sv_wt_cert_file", "", CVAR_LATCH );
	modified += sv_wt_cert_file->modified;
	sv_wt_cert_file->modified = qfalse;

	sv_wt_key_file = Cvar_Get( "sv_wt_key_file", "", CVAR_LATCH );
	modified += sv_wt_key_file->modified;
	sv_wt_key_file->modified = qfalse;

	sv_wt_path = Cvar_Get( "sv_wt_path", WT_DEFAULT_PATH, CVAR_LATCH | CVAR_ARCHIVE );
	modified += sv_wt_path->modified;
	sv_wt_path->modified = qfalse;

	sv_wt_allowed_origins = Cvar_Get( "sv_wt_allowed_origins", "", CVAR_LATCH | CVAR_ARCHIVE );
	modified += sv_wt_allowed_origins->modified;
	sv_wt_allowed_origins->modified = qfalse;
#else
	(void)net_transport;
#endif

	return modified ? qtrue : qfalse;
}

qboolean NET_UseWebTransport( void )
{
#ifdef __EMSCRIPTEN__
	return net_transport && !Q_stricmp( net_transport->string, "webtransport" );
#else
	return qfalse;
#endif
}

void NET_WT_Config( qboolean enableNetworking )
{
#ifdef __EMSCRIPTEN__
	NET_WT_JS_Stop();
	wt_backendActive = qfalse;

	if( !NET_UseWebTransport() || !enableNetworking )
		return;

	if( !NET_WT_JS_IsSupported() )
	{
		Com_Printf( "NET_WT: WebTransport is not available in this runtime.\n" );
		return;
	}

	wt_backendActive = qtrue;

	if( com_dedicated && com_dedicated->integer == 2 )
	{
		const char *path = ( sv_wt_path && sv_wt_path->string[0] ) ?
			sv_wt_path->string : WT_DEFAULT_PATH;

		if( !sv_wt_cert_file || !sv_wt_cert_file->string[0] ||
			!sv_wt_key_file || !sv_wt_key_file->string[0] )
		{
			Com_Printf( "NET_WT: sv_wt_cert_file and sv_wt_key_file must be set.\n" );
			wt_backendActive = qfalse;
			return;
		}

		NET_WT_JS_StartServer(
			Cvar_VariableIntegerValue( "net_port" ),
			Cvar_VariableString( "net_ip" ),
			path,
			sv_wt_cert_file->string,
			sv_wt_key_file->string,
			sv_wt_allowed_origins ? sv_wt_allowed_origins->string : "" );
	}
#else
	(void)enableNetworking;
#endif
}

qboolean NET_WT_StringToAdr( const char *s, netadr_t *a, netadrtype_t family )
{
#ifdef __EMSCRIPTEN__
	char url[WT_MAX_URL];
	char label[WT_MAX_LABEL];
	int port = PORT_SERVER;
	wt_endpoint_t *endpoint;

	if( !NET_UseWebTransport() || family != NA_UNSPEC )
		return qfalse;

	if( !NET_WT_JS_NormalizeAddress( s,
		( cl_wt_path && cl_wt_path->string[0] ) ? cl_wt_path->string : WT_DEFAULT_PATH,
		url, sizeof( url ), label, sizeof( label ), &port ) )
	{
		return qfalse;
	}

	endpoint = NET_WT_AllocClientRoute( url, label, (unsigned short) port );
	if( !endpoint )
		return qfalse;

	NET_WT_SetAddress( a, endpoint->id, endpoint->port );
	return qtrue;
#else
	(void)s;
	(void)a;
	(void)family;
	return qfalse;
#endif
}

qboolean NET_WT_GetPacket( netadr_t *net_from, msg_t *net_message )
{
#ifdef __EMSCRIPTEN__
	int length;
	int peerId;
	int port;
	char label[WT_MAX_LABEL];

	if( !wt_backendActive )
		return qfalse;

	for( ;; )
	{
		label[0] = '\0';
		peerId = 0;
		port = 0;

		length = NET_WT_JS_DequeuePacket( net_message->data, net_message->maxsize,
			&peerId, &port, label, sizeof( label ) );
		if( length == 0 )
			return qfalse;

		NET_WT_UpdateEndpoint( (unsigned int) peerId, (unsigned short) port, NULL, label );
		NET_WT_SetAddress( net_from, (unsigned int) peerId, (unsigned short) port );

		if( length < 0 )
		{
			Com_Printf( "Oversize packet from %s\n", NET_WT_AdrToString( *net_from ) );
			continue;
		}

		net_message->readcount = 0;
		net_message->cursize = length;
		return qtrue;
	}
#else
	(void)net_from;
	(void)net_message;
	return qfalse;
#endif
}

void NET_WT_SendPacket( int length, const void *data, netadr_t to )
{
#ifdef __EMSCRIPTEN__
	wt_endpoint_t *endpoint;

	if( !wt_backendActive || to.type != NA_WEBTRANSPORT )
		return;

	endpoint = NET_WT_FindEndpointById( NET_WT_GetEndpointId( to ) );
	if( !endpoint )
		return;

	if( endpoint->url[0] )
	{
		NET_WT_JS_RegisterClientRoute( endpoint->id, endpoint->url,
			endpoint->label, endpoint->port,
			cl_wt_cert_hash ? cl_wt_cert_hash->string : "" );
	}

	if( !NET_WT_JS_SendPacket( endpoint->id, data, length ) )
	{
		Com_Printf( "NET_WT: failed to send packet to %s (%d bytes)\n",
			NET_WT_AdrToString( to ), length );
	}
#else
	(void)length;
	(void)data;
	(void)to;
#endif
}

qboolean NET_WT_CompareBaseAdrMask( netadr_t a, netadr_t b, int netmask )
{
	(void)netmask;

	if( a.type != NA_WEBTRANSPORT || b.type != NA_WEBTRANSPORT )
		return qfalse;

	return NET_WT_GetEndpointId( a ) == NET_WT_GetEndpointId( b );
}

qboolean NET_WT_CompareAdr( netadr_t a, netadr_t b )
{
	if( !NET_WT_CompareBaseAdrMask( a, b, -1 ) )
		return qfalse;

	return a.port == b.port;
}

const char *NET_WT_AdrToString( netadr_t a )
{
	char description[NET_ADDRSTRMAXLEN];

	Q_strncpyz( description, NET_WT_DescribeEndpoint( a ), sizeof( description ) );
	Com_sprintf( wt_stringBuffer, sizeof( wt_stringBuffer ), "wt:%s", description );
	return wt_stringBuffer;
}

const char *NET_WT_AdrToStringwPort( netadr_t a )
{
	return NET_WT_AdrToString( a );
}

qboolean NET_WT_IsLocalAddress( netadr_t adr )
{
	(void)adr;
	return qfalse;
}

qboolean NET_WT_IsLANAddress( netadr_t adr )
{
	(void)adr;
	return qfalse;
}

qboolean NET_WT_ShouldUseLiteralAddress( const char *s, netadrtype_t family )
{
	(void)s;
	return NET_UseWebTransport() && family == NA_UNSPEC;
}
