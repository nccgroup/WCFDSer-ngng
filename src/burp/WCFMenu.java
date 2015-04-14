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

import javax.swing.*;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.util.ArrayList;
import java.util.List;

public class WCFMenu implements IContextMenuFactory {
	private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

	public WCFMenu(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
		this.callbacks = callbacks;
        this.helpers = helpers;
	}

	@Override
	public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
		JMenuItem sendWCFToIntruderMenu = new JMenuItem("Send Deserialized WCF to Intruder");
		sendWCFToIntruderMenu.addMouseListener(new MouseListener() {
			@Override
			public void mouseClicked(MouseEvent arg0) {

			}

			@Override
			public void mouseEntered(MouseEvent arg0) {
			}

			@Override
			public void mouseExited(MouseEvent arg0) {
			}

			@Override
			public void mousePressed(MouseEvent arg0) {
				IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();
				for (IHttpRequestResponse iReqResp : selectedMessages) {
					IHttpService httpService = iReqResp.getHttpService();

					//append our custom header and send to intruder
					List<String> headers = helpers.analyzeRequest(iReqResp.getRequest()).getHeaders();
					headers.add(WCFUtils.SERIALIZEHEADER);

					byte[] message = iReqResp.getRequest();

					int bodyOffset = helpers.analyzeRequest(message).getBodyOffset();
					byte[] body = new byte[message.length - bodyOffset];

					//copy it and convert it to XML
					System.arraycopy(message, bodyOffset, body, 0, message.length - bodyOffset);

					callbacks.sendToIntruder(httpService.getHost(), httpService.getPort(), (httpService.getProtocol().equals("https") ? true : false),
							WCFUtils.toXML(helpers.buildHttpMessage(headers, body), helpers));
				}
			}

			@Override
			public void mouseReleased(MouseEvent arg0) {
			}
		});

		List<JMenuItem> menus = new ArrayList();
		menus.add(sendWCFToIntruderMenu);
		return menus;
	}

}
