using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using System.Text;
using System.Xml;
using System.IO;
using System.Security;
using System.Linq;

public class StartUp
{
    static void Main(string[] argv)
    {
        string Host = "127.0.0.1";
        Int16 Port = 7686;

        if (argv.Length >= 1)
        {
            Host = argv[0];
        }
        if (argv.Length >= 2)
        {
            Port = Int16.Parse(argv[1]);
        }
        CancellationTokenSource cancellation = new CancellationTokenSource();
        NBFSNetService service = new NBFSNetService(Host, Port);
        var task = service.ListenForConnection(cancellation.Token);
        Console.ReadKey(true);
        cancellation.Cancel();
        task.Wait();
        service.StopService();
        Console.ReadKey(true);
    }
}

public class NBFSNetService
{
    private static Int32 DATA_LENGTH = 1024;
    private TcpListener listener;
    private WcfBinaryCodec codec;

    public NBFSNetService(string host, Int16 port)
    {
        IPAddress localAddr = IPAddress.Parse(host);
        listener = new TcpListener(localAddr, port);
        listener.Start();
        Console.WriteLine("Listener started on {0}:{1}.", host, port);
        codec = new WcfBinaryCodec();
    }

    public void StopService()
    {
        listener.Stop();
        Console.WriteLine("Listener stopped.");
    }

    public async Task ListenForConnection(CancellationToken cancellation)
    {
        try
        {
            while (!cancellation.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync().ConfigureAwait(false);
                await handleReading(client, cancellation).ConfigureAwait(false);
            }
        } catch (Exception e)
        {
            Console.WriteLine(e.Message);
            Console.WriteLine(e.StackTrace);
        }
    }

    private async Task handleReading(TcpClient client, CancellationToken cancellation)
    {
        byte[] buffer = new byte[DATA_LENGTH];
        MemoryStream stream = new MemoryStream();
        var networkStream = client.GetStream();
        int bytes_read;
        try
        {
            while (networkStream.DataAvailable)
            {
                bytes_read = await networkStream.ReadAsync(buffer, 0, buffer.Length, cancellation).ConfigureAwait(false);
                await stream.WriteAsync(buffer, 0, bytes_read, cancellation).ConfigureAwait(false);
            }
            await Respond(client, stream.ToArray(), cancellation).ConfigureAwait(false);
            
        } catch(Exception e)
        {
            Console.WriteLine(e.Message);
            Console.WriteLine(e.StackTrace);
        }
        client.GetStream().Dispose();
        client.Close();
    }

    private async Task Respond(TcpClient client, byte[] data, CancellationToken cancellation)
    {
        byte[] response;
        if (data[0] == (byte)0)
        {
            response = await codec.DecodeBinaryXML(new ArraySegment<byte>(data, 1, data.Length - 1).ToArray(), false).ConfigureAwait(false);
        }
        else if (data[0] == (byte)1)
        {
            response = await codec.EncodeBinaryXML(new ArraySegment<byte>(data, 1, data.Length - 1).ToArray()).ConfigureAwait(false);
        } else
        {
            response = new byte[0];
        }
        try
        {
            await client.GetStream().WriteAsync(response, 0, response.Length, cancellation).ConfigureAwait(false);
            await client.GetStream().FlushAsync().ConfigureAwait(false);
        } catch(Exception e)
        {
            Console.WriteLine(e.Message);
            Console.WriteLine(e.StackTrace);
        }
    }
}

public class WcfBinaryCodec
{
    private Encoding m_encoding = Encoding.UTF8;

    public WcfBinaryCodec() { }

    public WcfBinaryCodec(Encoding encoding)
    {
        m_encoding = encoding;
    }

    /// <summary>
    /// Decode a bytestream that was encoded by WCF's BinaryEncodingBindingElement.  Will throw if the bytestream does
    /// not decode properly or the result is not valid XML.  I/O streams are flushed but not closed.
    /// </summary>        
    /// <param name="explodeNewlines">if true, the returned string will be nicely indented according to 
    /// element depth, and each attribute will be placed on its own line</param>
    /// <returns></returns>
    public async Task DecodeBinaryXML(Stream binaryInput, Stream xmlOutput, bool? explodeNewlines)
    {
        // defaults
        var explode = explodeNewlines ?? false;

        // parse bytestream into the XML DOM
        var doc = new XmlDocument();
        // do not resolve external resources
        doc.XmlResolver = null;
        try
        {
            using (var binaryReader = XmlDictionaryReader.CreateBinaryReader(binaryInput, WcfDictionaryBuilder.Dict, XmlDictionaryReaderQuotas.Max))
            {
                doc.Load(binaryReader);
            }
        }
        catch (Exception e)
        {
            Console.WriteLine(e.Message);
            Console.WriteLine(e.StackTrace);
        }
        // write document to the output stream with customized settings
        var settings = new XmlWriterSettings()
        {
            CheckCharacters = false,
            CloseOutput = false,
            ConformanceLevel = ConformanceLevel.Auto,
            Encoding = m_encoding,
            Indent = explode,
            IndentChars = "\t",
            NewLineChars = Environment.NewLine,
            NewLineHandling = explode ? NewLineHandling.Replace : NewLineHandling.None,
            NewLineOnAttributes = explode,
            Async = true
            // QuoteChar = '"'
        };
        try
        {
            using (var writer = XmlWriter.Create(xmlOutput, settings))
            {
                doc.Save(writer);
                writer.Flush();
                await xmlOutput.FlushAsync().ConfigureAwait(false);
            }
        }
        catch (Exception e)
        {
            Console.WriteLine(e.Message);
            Console.WriteLine(e.StackTrace);
        }
    }

    public async Task<byte[]> DecodeBinaryXML(byte[] binaryInput, bool? explodeNewLines)
    {
        var input = new MemoryStream(binaryInput);
        var output = new MemoryStream();
        await DecodeBinaryXML(input, output, explodeNewLines).ConfigureAwait(false);
        return output.ToArray();
    }

    /// <summary>
    /// Encode a text stream into a binary XML stream compatible with WCF's BinaryEncodingBindingElement.  Will throw if 
    /// the input stream cannot be parsed into an XML document.  I/O streams are flushed but not closed.
    /// </summary>
    /// <param name="xmlInput"></param>
    /// <param name="binaryOutput"></param>
    public async Task EncodeBinaryXML(Stream xmlInput, Stream binaryOutput)
    {
        // parse string into the XML DOM
        var doc = new XmlDocument();
        // do not resolve external resources
        doc.XmlResolver = null;
        try
        {
            doc.Load(xmlInput);
        } catch (Exception e)
        {
            Console.WriteLine(e.Message);
            Console.WriteLine(e.StackTrace);
        }

        // write bytestream
        try
        {
            using (var binaryWriter = XmlDictionaryWriter.CreateBinaryWriter(binaryOutput, WcfDictionaryBuilder.Dict, null, false))
            {
                doc.Save(binaryWriter);
                binaryWriter.Flush();
                await binaryOutput.FlushAsync().ConfigureAwait(false);
            }
        }
        catch (Exception e)
        {
            Console.WriteLine(e.Message);
            Console.WriteLine(e.StackTrace);
        }
    }

    public async Task<byte[]> EncodeBinaryXML(byte[] xmlInput)
    {
        var input = new MemoryStream(xmlInput);
        var output = new MemoryStream();
        await EncodeBinaryXML(input, output).ConfigureAwait(false);
        return output.ToArray();
    }
}

public static class WcfDictionaryBuilder
{
    private static XmlDictionary dict;

    public static XmlDictionary Dict
    {
        get { return dict; }
    }

    static WcfDictionaryBuilder()
    {
        dict = new XmlDictionary();
        dict.Add("mustUnderstand");
        dict.Add("Envelope");
        dict.Add("http://www.w3.org/2003/05/soap-envelope");
        dict.Add("http://www.w3.org/2005/08/addressing");
        dict.Add("Header");
        dict.Add("Action");
        dict.Add("To");
        dict.Add("Body");
        dict.Add("Algorithm");
        dict.Add("RelatesTo");
        dict.Add("http://www.w3.org/2005/08/addressing/anonymous");
        dict.Add("URI");
        dict.Add("Reference");
        dict.Add("MessageID");
        dict.Add("Id");
        dict.Add("Identifier");
        dict.Add("http://schemas.xmlsoap.org/ws/2005/02/rm");
        dict.Add("Transforms");
        dict.Add("Transform");
        dict.Add("DigestMethod");
        dict.Add("DigestValue");
        dict.Add("Address");
        dict.Add("ReplyTo");
        dict.Add("SequenceAcknowledgement");
        dict.Add("AcknowledgementRange");
        dict.Add("Upper");
        dict.Add("Lower");
        dict.Add("BufferRemaining");
        dict.Add("http://schemas.microsoft.com/ws/2006/05/rm");
        dict.Add("http://schemas.xmlsoap.org/ws/2005/02/rm/SequenceAcknowledgement");
        dict.Add("SecurityTokenReference");
        dict.Add("Sequence");
        dict.Add("MessageNumber");
        dict.Add("http://www.w3.org/2000/09/xmldsig#");
        dict.Add("http://www.w3.org/2000/09/xmldsig#enveloped-signature");
        dict.Add("KeyInfo");
        dict.Add("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
        dict.Add("http://www.w3.org/2001/04/xmlenc#");
        dict.Add("http://schemas.xmlsoap.org/ws/2005/02/sc");
        dict.Add("DerivedKeyToken");
        dict.Add("Nonce");
        dict.Add("Signature");
        dict.Add("SignedInfo");
        dict.Add("CanonicalizationMethod");
        dict.Add("SignatureMethod");
        dict.Add("SignatureValue");
        dict.Add("DataReference");
        dict.Add("EncryptedData");
        dict.Add("EncryptionMethod");
        dict.Add("CipherData");
        dict.Add("CipherValue");
        dict.Add("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
        dict.Add("Security");
        dict.Add("Timestamp");
        dict.Add("Created");
        dict.Add("Expires");
        dict.Add("Length");
        dict.Add("ReferenceList");
        dict.Add("ValueType");
        dict.Add("Type");
        dict.Add("EncryptedHeader");
        dict.Add("http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd");
        dict.Add("RequestSecurityTokenResponseCollection");
        dict.Add("http://schemas.xmlsoap.org/ws/2005/02/trust");
        dict.Add("http://schemas.xmlsoap.org/ws/2005/02/trust#BinarySecret");
        dict.Add("http://schemas.microsoft.com/ws/2006/02/transactions");
        dict.Add("s");
        dict.Add("Fault");
        dict.Add("MustUnderstand");
        dict.Add("role");
        dict.Add("relay");
        dict.Add("Code");
        dict.Add("Reason");
        dict.Add("Text");
        dict.Add("Node");
        dict.Add("Role");
        dict.Add("Detail");
        dict.Add("Value");
        dict.Add("Subcode");
        dict.Add("NotUnderstood");
        dict.Add("qname");
        dict.Add("");
        dict.Add("From");
        dict.Add("FaultTo");
        dict.Add("EndpointReference");
        dict.Add("PortType");
        dict.Add("ServiceName");
        dict.Add("PortName");
        dict.Add("ReferenceProperties");
        dict.Add("RelationshipType");
        dict.Add("Reply");
        dict.Add("a");
        dict.Add("http://schemas.xmlsoap.org/ws/2006/02/addressingidentity");
        dict.Add("Identity");
        dict.Add("Spn");
        dict.Add("Upn");
        dict.Add("Rsa");
        dict.Add("Dns");
        dict.Add("X509v3Certificate");
        dict.Add("http://www.w3.org/2005/08/addressing/fault");
        dict.Add("ReferenceParameters");
        dict.Add("IsReferenceParameter");
        dict.Add("http://www.w3.org/2005/08/addressing/reply");
        dict.Add("http://www.w3.org/2005/08/addressing/none");
        dict.Add("Metadata");
        dict.Add("http://schemas.xmlsoap.org/ws/2004/08/addressing");
        dict.Add("http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous");
        dict.Add("http://schemas.xmlsoap.org/ws/2004/08/addressing/fault");
        dict.Add("http://schemas.xmlsoap.org/ws/2004/06/addressingex");
        dict.Add("RedirectTo");
        dict.Add("Via");
        dict.Add("http://www.w3.org/2001/10/xml-exc-c14n#");
        dict.Add("PrefixList");
        dict.Add("InclusiveNamespaces");
        dict.Add("ec");
        dict.Add("SecurityContextToken");
        dict.Add("Generation");
        dict.Add("Label");
        dict.Add("Offset");
        dict.Add("Properties");
        dict.Add("Cookie");
        dict.Add("wsc");
        dict.Add("http://schemas.xmlsoap.org/ws/2004/04/sc");
        dict.Add("http://schemas.xmlsoap.org/ws/2004/04/security/sc/dk");
        dict.Add("http://schemas.xmlsoap.org/ws/2004/04/security/sc/sct");
        dict.Add("http://schemas.xmlsoap.org/ws/2004/04/security/trust/RST/SCT");
        dict.Add("http://schemas.xmlsoap.org/ws/2004/04/security/trust/RSTR/SCT");
        dict.Add("RenewNeeded");
        dict.Add("BadContextToken");
        dict.Add("c");
        dict.Add("http://schemas.xmlsoap.org/ws/2005/02/sc/dk");
        dict.Add("http://schemas.xmlsoap.org/ws/2005/02/sc/sct");
        dict.Add("http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT");
        dict.Add("http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/SCT");
        dict.Add("http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT/Renew");
        dict.Add("http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/SCT/Renew");
        dict.Add("http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT/Cancel");
        dict.Add("http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/SCT/Cancel");
        dict.Add("http://www.w3.org/2001/04/xmlenc#aes128-cbc");
        dict.Add("http://www.w3.org/2001/04/xmlenc#kw-aes128");
        dict.Add("http://www.w3.org/2001/04/xmlenc#aes192-cbc");
        dict.Add("http://www.w3.org/2001/04/xmlenc#kw-aes192");
        dict.Add("http://www.w3.org/2001/04/xmlenc#aes256-cbc");
        dict.Add("http://www.w3.org/2001/04/xmlenc#kw-aes256");
        dict.Add("http://www.w3.org/2001/04/xmlenc#des-cbc");
        dict.Add("http://www.w3.org/2000/09/xmldsig#dsa-sha1");
        dict.Add("http://www.w3.org/2001/10/xml-exc-c14n#WithComments");
        dict.Add("http://www.w3.org/2000/09/xmldsig#hmac-sha1");
        dict.Add("http://www.w3.org/2001/04/xmldsig-more#hmac-sha256");
        dict.Add("http://schemas.xmlsoap.org/ws/2005/02/sc/dk/p_sha1");
        dict.Add("http://www.w3.org/2001/04/xmlenc#ripemd160");
        dict.Add("http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p");
        dict.Add("http://www.w3.org/2000/09/xmldsig#rsa-sha1");
        dict.Add("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        dict.Add("http://www.w3.org/2001/04/xmlenc#rsa-1_5");
        dict.Add("http://www.w3.org/2000/09/xmldsig#sha1");
        dict.Add("http://www.w3.org/2001/04/xmlenc#sha256");
        dict.Add("http://www.w3.org/2001/04/xmlenc#sha512");
        dict.Add("http://www.w3.org/2001/04/xmlenc#tripledes-cbc");
        dict.Add("http://www.w3.org/2001/04/xmlenc#kw-tripledes");
        dict.Add("http://schemas.xmlsoap.org/2005/02/trust/tlsnego#TLS_Wrap");
        dict.Add("http://schemas.xmlsoap.org/2005/02/trust/spnego#GSS_Wrap");
        dict.Add("http://schemas.microsoft.com/ws/2006/05/security");
        dict.Add("dnse");
        dict.Add("o");
        dict.Add("Password");
        dict.Add("PasswordText");
        dict.Add("Username");
        dict.Add("UsernameToken");
        dict.Add("BinarySecurityToken");
        dict.Add("EncodingType");
        dict.Add("KeyIdentifier");
        dict.Add("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
        dict.Add("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#HexBinary");
        dict.Add("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Text");
        dict.Add("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier");
        dict.Add("http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#GSS_Kerberosv5_AP_REQ");
        dict.Add("http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#GSS_Kerberosv5_AP_REQ1510");
        dict.Add("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID");
        dict.Add("Assertion");
        dict.Add("urn:oasis:names:tc:SAML:1.0:assertion");
        dict.Add("http://docs.oasis-open.org/wss/oasis-wss-rel-token-profile-1.0.pdf#license");
        dict.Add("FailedAuthentication");
        dict.Add("InvalidSecurityToken");
        dict.Add("InvalidSecurity");
        dict.Add("k");
        dict.Add("SignatureConfirmation");
        dict.Add("TokenType");
        dict.Add("http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1");
        dict.Add("http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKey");
        dict.Add("http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKeySHA1");
        dict.Add("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1");
        dict.Add("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0");
        dict.Add("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID");
        dict.Add("AUTH-HASH");
        dict.Add("RequestSecurityTokenResponse");
        dict.Add("KeySize");
        dict.Add("RequestedTokenReference");
        dict.Add("AppliesTo");
        dict.Add("Authenticator");
        dict.Add("CombinedHash");
        dict.Add("BinaryExchange");
        dict.Add("Lifetime");
        dict.Add("RequestedSecurityToken");
        dict.Add("Entropy");
        dict.Add("RequestedProofToken");
        dict.Add("ComputedKey");
        dict.Add("RequestSecurityToken");
        dict.Add("RequestType");
        dict.Add("Context");
        dict.Add("BinarySecret");
        dict.Add("http://schemas.xmlsoap.org/ws/2005/02/trust/spnego");
        dict.Add("http://schemas.xmlsoap.org/ws/2005/02/trust/tlsnego");
        dict.Add("wst");
        dict.Add("http://schemas.xmlsoap.org/ws/2004/04/trust");
        dict.Add("http://schemas.xmlsoap.org/ws/2004/04/security/trust/RST/Issue");
        dict.Add("http://schemas.xmlsoap.org/ws/2004/04/security/trust/RSTR/Issue");
        dict.Add("http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue");
        dict.Add("http://schemas.xmlsoap.org/ws/2004/04/security/trust/CK/PSHA1");
        dict.Add("http://schemas.xmlsoap.org/ws/2004/04/security/trust/SymmetricKey");
        dict.Add("http://schemas.xmlsoap.org/ws/2004/04/security/trust/Nonce");
        dict.Add("KeyType");
        dict.Add("http://schemas.xmlsoap.org/ws/2004/04/trust/SymmetricKey");
        dict.Add("http://schemas.xmlsoap.org/ws/2004/04/trust/PublicKey");
        dict.Add("Claims");
        dict.Add("InvalidRequest");
        dict.Add("RequestFailed");
        dict.Add("SignWith");
        dict.Add("EncryptWith");
        dict.Add("EncryptionAlgorithm");
        dict.Add("CanonicalizationAlgorithm");
        dict.Add("ComputedKeyAlgorithm");
        dict.Add("UseKey");
        dict.Add("http://schemas.microsoft.com/net/2004/07/secext/WS-SPNego");
        dict.Add("http://schemas.microsoft.com/net/2004/07/secext/TLSNego");
        dict.Add("t");
        dict.Add("http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue");
        dict.Add("http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/Issue");
        dict.Add("http://schemas.xmlsoap.org/ws/2005/02/trust/Issue");
        dict.Add("http://schemas.xmlsoap.org/ws/2005/02/trust/SymmetricKey");
        dict.Add("http://schemas.xmlsoap.org/ws/2005/02/trust/CK/PSHA1");
        dict.Add("http://schemas.xmlsoap.org/ws/2005/02/trust/Nonce");
        dict.Add("RenewTarget");
        dict.Add("CancelTarget");
        dict.Add("RequestedTokenCancelled");
        dict.Add("RequestedAttachedReference");
        dict.Add("RequestedUnattachedReference");
        dict.Add("IssuedTokens");
        dict.Add("http://schemas.xmlsoap.org/ws/2005/02/trust/Renew");
        dict.Add("http://schemas.xmlsoap.org/ws/2005/02/trust/Cancel");
        dict.Add("http://schemas.xmlsoap.org/ws/2005/02/trust/PublicKey");
        dict.Add("Access");
        dict.Add("AccessDecision");
        dict.Add("Advice");
        dict.Add("AssertionID");
        dict.Add("AssertionIDReference");
        dict.Add("Attribute");
        dict.Add("AttributeName");
        dict.Add("AttributeNamespace");
        dict.Add("AttributeStatement");
        dict.Add("AttributeValue");
        dict.Add("Audience");
        dict.Add("AudienceRestrictionCondition");
        dict.Add("AuthenticationInstant");
        dict.Add("AuthenticationMethod");
        dict.Add("AuthenticationStatement");
        dict.Add("AuthorityBinding");
        dict.Add("AuthorityKind");
        dict.Add("AuthorizationDecisionStatement");
        dict.Add("Binding");
        dict.Add("Condition");
        dict.Add("Conditions");
        dict.Add("Decision");
        dict.Add("DoNotCacheCondition");
        dict.Add("Evidence");
        dict.Add("IssueInstant");
        dict.Add("Issuer");
        dict.Add("Location");
        dict.Add("MajorVersion");
        dict.Add("MinorVersion");
        dict.Add("NameIdentifier");
        dict.Add("Format");
        dict.Add("NameQualifier");
        dict.Add("Namespace");
        dict.Add("NotBefore");
        dict.Add("NotOnOrAfter");
        dict.Add("saml");
        dict.Add("Statement");
        dict.Add("Subject");
        dict.Add("SubjectConfirmation");
        dict.Add("SubjectConfirmationData");
        dict.Add("ConfirmationMethod");
        dict.Add("urn:oasis:names:tc:SAML:1.0:cm:holder-of-key");
        dict.Add("urn:oasis:names:tc:SAML:1.0:cm:sender-vouches");
        dict.Add("SubjectLocality");
        dict.Add("DNSAddress");
        dict.Add("IPAddress");
        dict.Add("SubjectStatement");
        dict.Add("urn:oasis:names:tc:SAML:1.0:am:unspecified");
        dict.Add("xmlns");
        dict.Add("Resource");
        dict.Add("UserName");
        dict.Add("urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName");
        dict.Add("EmailName");
        dict.Add("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
        dict.Add("u");
        dict.Add("ChannelInstance");
        dict.Add("http://schemas.microsoft.com/ws/2005/02/duplex");
        dict.Add("Encoding");
        dict.Add("MimeType");
        dict.Add("CarriedKeyName");
        dict.Add("Recipient");
        dict.Add("EncryptedKey");
        dict.Add("KeyReference");
        dict.Add("e");
        dict.Add("http://www.w3.org/2001/04/xmlenc#Element");
        dict.Add("http://www.w3.org/2001/04/xmlenc#Content");
        dict.Add("KeyName");
        dict.Add("MgmtData");
        dict.Add("KeyValue");
        dict.Add("RSAKeyValue");
        dict.Add("Modulus");
        dict.Add("Exponent");
        dict.Add("X509Data");
        dict.Add("X509IssuerSerial");
        dict.Add("X509IssuerName");
        dict.Add("X509SerialNumber");
        dict.Add("X509Certificate");
        dict.Add("AckRequested");
        dict.Add("http://schemas.xmlsoap.org/ws/2005/02/rm/AckRequested");
        dict.Add("AcksTo");
        dict.Add("Accept");
        dict.Add("CreateSequence");
        dict.Add("http://schemas.xmlsoap.org/ws/2005/02/rm/CreateSequence");
        dict.Add("CreateSequenceRefused");
        dict.Add("CreateSequenceResponse");
        dict.Add("http://schemas.xmlsoap.org/ws/2005/02/rm/CreateSequenceResponse");
        dict.Add("FaultCode");
        dict.Add("InvalidAcknowledgement");
        dict.Add("LastMessage");
        dict.Add("http://schemas.xmlsoap.org/ws/2005/02/rm/LastMessage");
        dict.Add("LastMessageNumberExceeded");
        dict.Add("MessageNumberRollover");
        dict.Add("Nack");
        dict.Add("netrm");
        dict.Add("Offer");
        dict.Add("r");
        dict.Add("SequenceFault");
        dict.Add("SequenceTerminated");
        dict.Add("TerminateSequence");
        dict.Add("http://schemas.xmlsoap.org/ws/2005/02/rm/TerminateSequence");
        dict.Add("UnknownSequence");
        dict.Add("http://schemas.microsoft.com/ws/2006/02/tx/oletx");
        dict.Add("oletx");
        dict.Add("OleTxTransaction");
        dict.Add("PropagationToken");
        dict.Add("http://schemas.xmlsoap.org/ws/2004/10/wscoor");
        dict.Add("wscoor");
        dict.Add("CreateCoordinationContext");
        dict.Add("CreateCoordinationContextResponse");
        dict.Add("CoordinationContext");
        dict.Add("CurrentContext");
        dict.Add("CoordinationType");
        dict.Add("RegistrationService");
        dict.Add("Register");
        dict.Add("RegisterResponse");
        dict.Add("ProtocolIdentifier");
        dict.Add("CoordinatorProtocolService");
        dict.Add("ParticipantProtocolService");
        dict.Add("http://schemas.xmlsoap.org/ws/2004/10/wscoor/CreateCoordinationContext");
        dict.Add("http://schemas.xmlsoap.org/ws/2004/10/wscoor/CreateCoordinationContextResponse");
        dict.Add("http://schemas.xmlsoap.org/ws/2004/10/wscoor/Register");
        dict.Add("http://schemas.xmlsoap.org/ws/2004/10/wscoor/RegisterResponse");
        dict.Add("http://schemas.xmlsoap.org/ws/2004/10/wscoor/fault");
        dict.Add("ActivationCoordinatorPortType");
        dict.Add("RegistrationCoordinatorPortType");
        dict.Add("InvalidState");
        dict.Add("InvalidProtocol");
        dict.Add("InvalidParameters");
        dict.Add("NoActivity");
        dict.Add("ContextRefused");
        dict.Add("AlreadyRegistered");
        dict.Add("http://schemas.xmlsoap.org/ws/2004/10/wsat");
        dict.Add("wsat");
        dict.Add("http://schemas.xmlsoap.org/ws/2004/10/wsat/Completion");
        dict.Add("http://schemas.xmlsoap.org/ws/2004/10/wsat/Durable2PC");
        dict.Add("http://schemas.xmlsoap.org/ws/2004/10/wsat/Volatile2PC");
        dict.Add("Prepare");
        dict.Add("Prepared");
        dict.Add("ReadOnly");
        dict.Add("Commit");
        dict.Add("Rollback");
        dict.Add("Committed");
        dict.Add("Aborted");
        dict.Add("Replay");
        dict.Add("http://schemas.xmlsoap.org/ws/2004/10/wsat/Commit");
        dict.Add("http://schemas.xmlsoap.org/ws/2004/10/wsat/Rollback");
        dict.Add("http://schemas.xmlsoap.org/ws/2004/10/wsat/Committed");
        dict.Add("http://schemas.xmlsoap.org/ws/2004/10/wsat/Aborted");
        dict.Add("http://schemas.xmlsoap.org/ws/2004/10/wsat/Prepare");
        dict.Add("http://schemas.xmlsoap.org/ws/2004/10/wsat/Prepared");
        dict.Add("http://schemas.xmlsoap.org/ws/2004/10/wsat/ReadOnly");
        dict.Add("http://schemas.xmlsoap.org/ws/2004/10/wsat/Replay");
        dict.Add("http://schemas.xmlsoap.org/ws/2004/10/wsat/fault");
        dict.Add("CompletionCoordinatorPortType");
        dict.Add("CompletionParticipantPortType");
        dict.Add("CoordinatorPortType");
        dict.Add("ParticipantPortType");
        dict.Add("InconsistentInternalState");
        dict.Add("mstx");
        dict.Add("Enlistment");
        dict.Add("protocol");
        dict.Add("LocalTransactionId");
        dict.Add("IsolationLevel");
        dict.Add("IsolationFlags");
        dict.Add("Description");
        dict.Add("Loopback");
        dict.Add("RegisterInfo");
        dict.Add("ContextId");
        dict.Add("TokenId");
        dict.Add("AccessDenied");
        dict.Add("InvalidPolicy");
        dict.Add("CoordinatorRegistrationFailed");
        dict.Add("TooManyEnlistments");
        dict.Add("Disabled");
        dict.Add("ActivityId");
        dict.Add("http://schemas.microsoft.com/2004/09/ServiceModel/Diagnostics");
        dict.Add("http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#Kerberosv5APREQSHA1");
        dict.Add("http://schemas.xmlsoap.org/ws/2002/12/policy");
        dict.Add("FloodMessage");
        dict.Add("LinkUtility");
        dict.Add("Hops");
        dict.Add("http://schemas.microsoft.com/net/2006/05/peer/HopCount");
        dict.Add("PeerVia");
        dict.Add("http://schemas.microsoft.com/net/2006/05/peer");
        dict.Add("PeerFlooder");
        dict.Add("PeerTo");
        dict.Add("http://schemas.microsoft.com/ws/2005/05/routing");
        dict.Add("PacketRoutable");
        dict.Add("http://schemas.microsoft.com/ws/2005/05/addressing/none");
        dict.Add("http://schemas.microsoft.com/ws/2005/05/envelope/none");
        dict.Add("http://www.w3.org/2001/XMLSchema-instance");
        dict.Add("http://www.w3.org/2001/XMLSchema");
        dict.Add("nil");
        dict.Add("type");
        dict.Add("char");
        dict.Add("boolean");
        dict.Add("byte");
        dict.Add("unsignedByte");
        dict.Add("short");
        dict.Add("unsignedShort");
        dict.Add("int");
        dict.Add("unsignedInt");
        dict.Add("long");
        dict.Add("unsignedLong");
        dict.Add("float");
        dict.Add("double");
        dict.Add("decimal");
        dict.Add("dateTime");
        dict.Add("string");
        dict.Add("base64Binary");
        dict.Add("anyType");
        dict.Add("duration");
        dict.Add("guid");
        dict.Add("anyURI");
        dict.Add("QName");
        dict.Add("time");
        dict.Add("date");
        dict.Add("hexBinary");
        dict.Add("gYearMonth");
        dict.Add("gYear");
        dict.Add("gMonthDay");
        dict.Add("gDay");
        dict.Add("gMonth");
        dict.Add("integer");
        dict.Add("positiveInteger");
        dict.Add("negativeInteger");
        dict.Add("nonPositiveInteger");
        dict.Add("nonNegativeInteger");
        dict.Add("normalizedString");
        dict.Add("ConnectionLimitReached");
        dict.Add("http://schemas.xmlsoap.org/soap/envelope/");
        dict.Add("Actor");
        dict.Add("Faultcode");
        dict.Add("Faultstring");
        dict.Add("Faultactor");
        dict.Add("Detail");
    }
}

