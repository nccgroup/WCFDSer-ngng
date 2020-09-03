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


import java.awt.print.Printable;
import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory
{
    private IBurpExtenderCallbacks m_callbacks;
    private IExtensionHelpers m_helpers;

    //
    // implement IBurpExtender
    //
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {

        // keep a reference to our callbacks object
        this.m_callbacks = callbacks;
        
        // obtain an extension helpers object
        m_helpers = callbacks.getHelpers();
        
        // set our extension name
        callbacks.setExtensionName("WCF Deserializer");
        
        // register ourselves as a message editor tab factory
        WCFTabFactory factory = new WCFTabFactory(m_callbacks, m_helpers);

        callbacks.registerMessageEditorTabFactory(factory);
        
        callbacks.registerContextMenuFactory(new WCFMenu(callbacks, m_helpers));
        
        callbacks.registerHttpListener(new WCFHttpListener(m_helpers, m_callbacks));

        WCFUtils.out = new PrintWriter(callbacks.getStdout());
        WCFUtils.err = new PrintWriter(callbacks.getStderr());
    }

    //
    // implement IMessageEditorTabFactory
    //
    
    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable)
    {
        // create a new instance of our custom editor tab
        return new WCFDeserializerTab(controller, editable, m_callbacks, m_helpers);
    }

   
}
