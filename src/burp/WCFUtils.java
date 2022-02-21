/*
 * Copyright (c) John Murray, 2015.
 *
 *   This program is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU Affero General Public License as
 *     published by the Free Software Foundation, either version 3 of the
 *     License, or (at your option) any later version.
 *
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU Affero General Public License for more details.
 *
 *     You should have received a copy of the GNU Affero General Public License
 *     along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package burp;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Future;

public class WCFUtils {
    public static String WCFHeader = "msbin";
    public static String SERIALIZEHEADER = "Via:WCFSERIALIZED-GOODNESS";
    public static PrintWriter out;
    public static PrintWriter err;

	public static byte[] toXML(byte[] message, IExtensionHelpers helpers)
    {
		try {

            List<String> headers = helpers.analyzeRequest(message).getHeaders();
            int bodyOffset = helpers.analyzeRequest(message).getBodyOffset();
            byte[] body = new byte[message.length - bodyOffset];

            //copy it and convert it to XML
            System.arraycopy(message, bodyOffset, body, 0, body.length);

            String xml = encodeDecodeWcf(true, helpers.bytesToString(body), helpers);
            byte[] decoded = helpers.base64Decode(xml);

            return helpers.buildHttpMessage(headers, decoded);

		} catch (Exception e) {
			return e.getLocalizedMessage().getBytes();
		}
	}

	public static byte[] fromXML(byte[] xml, IExtensionHelpers helpers)
    {
		try {
            return helpers.base64Decode(encodeDecodeWcf(false, helpers.bytesToString(xml), helpers));
		} catch (Exception ex) {
            return ex.getLocalizedMessage().getBytes();
		}
	}

    public static String encodeDecodeWcf(boolean isBinary, String content, IExtensionHelpers helpers)
    {
        try
        {
            Socket socket = new Socket("127.0.0.1", 7686);
            InputStream inStream = new BufferedInputStream(socket.getInputStream());
            OutputStream outStream = new BufferedOutputStream(socket.getOutputStream());

            byte[] data = helpers.stringToBytes(content);
            byte[] message = new byte[data.length + 1];

            System.arraycopy(data, 0, message, 1, data.length);
            if(isBinary)
            {
                message[0] = (byte) 0;
			} else
            {
                message[0] = (byte) 1;
			}

            outStream.write(message);
            outStream.flush();

            byte[] response = new byte[1024];
            int bytes_read;
            ByteArrayOutputStream buffer = new ByteArrayOutputStream(4096);
            do {
                bytes_read = inStream.read(response, 0, response.length);
                buffer.write(response, 0, bytes_read);
            } while(inStream.available() > 0);
            outStream.close();
            inStream.close();
            socket.close();
            buffer.flush();

            return helpers.base64Encode(buffer.toByteArray());
        }
        catch (Exception e)
        {
            err.println(e.getLocalizedMessage());
            return helpers.base64Encode(e.getMessage());
        }
    }

    public static boolean isWCF(byte[] content, IExtensionHelpers helpers)
    {
        return (helpers.indexOf(content, helpers.stringToBytes(WCFUtils.WCFHeader), false, 0, content.length) > -1);
    }

    public static boolean hasMagicHeader(byte[] content, IExtensionHelpers helpers)
    {
        return helpers.indexOf(content, helpers.stringToBytes(WCFUtils.SERIALIZEHEADER), false, 0, content.length) > -1;
    }

}
