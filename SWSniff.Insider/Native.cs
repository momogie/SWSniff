using System;
using System.Runtime.InteropServices;

namespace SWSniff.Insider
{
    internal static class Native
    {
        [DllImport("ws2_32.dll")]
        public static extern int recvfrom(IntPtr Socket, IntPtr buf, int len, int flags, ref SockAddr from, IntPtr fromlen);
        
        [DllImport("Ws2_32.dll")]
        static extern int recv(
            IntPtr socketHandle,
            IntPtr buf,
            int count,
            int socketFlags
        );


        [UnmanagedFunctionPointer(CallingConvention.StdCall,
            CharSet = CharSet.Unicode,
            SetLastError = true)]


        delegate int Drecv(
            IntPtr socketHandle,
            IntPtr buf,
            int count,
            int socketFlags
        );
    }
    
    
    [StructLayout(LayoutKind.Explicit, Size = 24)]
    internal struct SockAddr
    {
        [FieldOffset(0)] internal ADDRESS_FAMILIES_INT sa_family;

        [FieldOffset(2)] internal byte[] sa_data;
    }
    
    internal enum ADDRESS_FAMILIES_INT : ushort
    {
        /// <summary>
        /// Unspecified [value = 0].
        /// </summary>
        AF_UNSPEC = 0,
        /// <summary>
        /// Local to host (pipes, portals) [value = 1].
        /// </summary>
        AF_UNIX = 1,
        /// <summary>
        /// Internetwork: UDP, TCP, etc [value = 2].
        /// </summary>
        AF_INET = 2,
        /// <summary>
        /// Arpanet imp addresses [value = 3].
        /// </summary>
        AF_IMPLINK = 3,
        /// <summary>
        /// Pup protocols: e.g. BSP [value = 4].
        /// </summary>
        AF_PUP = 4,
        /// <summary>
        /// Mit CHAOS protocols [value = 5].
        /// </summary>
        AF_CHAOS = 5,
        /// <summary>
        /// XEROX NS protocols [value = 6].
        /// </summary>
        AF_NS = 6,
        /// <summary>
        /// IPX protocols: IPX, SPX, etc [value = 6].
        /// </summary>
        AF_IPX = 6,
        /// <summary>
        /// ISO protocols [value = 7].
        /// </summary>
        AF_ISO = 7,
        /// <summary>
        /// OSI is ISO [value = 7].
        /// </summary>
        AF_OSI = 7,
        /// <summary>
        /// european computer manufacturers [value = 8].
        /// </summary>
        AF_ECMA = 8,
        /// <summary>
        /// datakit protocols [value = 9].
        /// </summary>
        AF_DATAKIT = 9,
        /// <summary>
        /// CCITT protocols, X.25 etc [value = 10].
        /// </summary>
        AF_CCITT = 10,
        /// <summary>
        /// IBM SNA [value = 11].
        /// </summary>
        AF_SNA = 11,
        /// <summary>
        /// DECnet [value = 12].
        /// </summary>
        AF_DECnet = 12,
        /// <summary>
        /// Direct data link interface [value = 13].
        /// </summary>
        AF_DLI = 13,
        /// <summary>
        /// LAT [value = 14].
        /// </summary>
        AF_LAT = 14,
        /// <summary>
        /// NSC Hyperchannel [value = 15].
        /// </summary>
        AF_HYLINK = 15,
        /// <summary>
        /// AppleTalk [value = 16].
        /// </summary>
        AF_APPLETALK = 16,
        /// <summary>
        /// NetBios-style addresses [value = 17].
        /// </summary>
        AF_NETBIOS = 17,
        /// <summary>
        /// VoiceView [value = 18].
        /// </summary>
        AF_VOICEVIEW = 18,
        /// <summary>
        /// Protocols from Firefox [value = 19].
        /// </summary>
        AF_FIREFOX = 19,
        /// <summary>
        /// Somebody is using this! [value = 20].
        /// </summary>
        AF_UNKNOWN1 = 20,
        /// <summary>
        /// Banyan [value = 21].
        /// </summary>
        AF_BAN = 21,
        /// <summary>
        /// Native ATM Services [value = 22].
        /// </summary>
        AF_ATM = 22,
        /// <summary>
        /// Internetwork Version 6 [value = 23].
        /// </summary>
        AF_INET6 = 23,
        /// <summary>
        /// Microsoft Wolfpack [value = 24].
        /// </summary>
        AF_CLUSTER = 24,
        /// <summary>
        /// IEEE 1284.4 WG AF [value = 25].
        /// </summary>
        AF_12844 = 25,
        /// <summary>
        /// IrDA [value = 26].
        /// </summary>
        AF_IRDA = 26,
        /// <summary>
        /// Network Designers OSI &amp; gateway enabled protocols [value = 28].
        /// </summary>
        AF_NETDES = 28,
        /// <summary>
        /// [value = 29].
        /// </summary>
        AF_TCNPROCESS = 29,
        /// <summary>
        /// [value = 30].
        /// </summary>
        AF_TCNMESSAGE = 30,
        /// <summary>
        /// [value = 31].
        /// </summary>
        AF_ICLFXBM = 31
    }
}