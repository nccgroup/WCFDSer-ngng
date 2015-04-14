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

import java.util.List;

public class WCFHttpListener implements IHttpListener {

    private IExtensionHelpers helpers;
    public WCFHttpListener(IExtensionHelpers helpers)
    {
        this.helpers = helpers;
    }
	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
    {
        if (toolFlag == IBurpExtenderCallbacks.TOOL_SCANNER || toolFlag == IBurpExtenderCallbacks.TOOL_INTRUDER || toolFlag == IBurpExtenderCallbacks.TOOL_PROXY)
        {

            //if it is a request, check to see if it has the magic header
            if (messageIsRequest && messageInfo != null && WCFUtils.hasMagicHeader(messageInfo.getRequest(), helpers)) {

                //if the request has the custom header, remove it
                List<String> headers = helpers.analyzeRequest(messageInfo.getRequest()).getHeaders();
                headers.remove(WCFUtils.SERIALIZEHEADER);

                //extract the body
                int bodyOffset = helpers.analyzeRequest(messageInfo.getRequest()).getBodyOffset();
                byte[] request = messageInfo.getRequest();
                int bodyLength = request.length - bodyOffset;

                byte[] body = new byte[bodyLength];
                System.arraycopy(request, bodyOffset, body, 0, bodyLength);

                //convert it back to a serialized object and create an http message (without the magic header)
                byte[] newHTTPMessage = helpers.buildHttpMessage(headers, WCFUtils.fromXML(body, helpers));
                //System.out.println(helpers.bytesToString(newHTTPMessage));

                //update the current message to this one
                messageInfo.setRequest(newHTTPMessage);
            }

            //if it is a response, and looks like java, and comes from the scanner convert it to XML so that stack traces and error messages, etc. can be picked up on)
            else if (toolFlag == IBurpExtenderCallbacks.TOOL_SCANNER && WCFUtils.isWCF(messageInfo.getResponse(), helpers))
            {
                try {
                    byte[] XML = WCFUtils.toXML(messageInfo.getResponse(), helpers);
                    List<String> headers = helpers.analyzeRequest(messageInfo.getResponse()).getHeaders();

                    //set the request body here so burp actually sees it
                    messageInfo.setResponse(helpers.buildHttpMessage(headers, XML));

                } catch (Exception ex) {
                    System.out.println("Error deserializing standard (intruder/scanner) response " + ex.getMessage());
                }
            }
        }
	}
}