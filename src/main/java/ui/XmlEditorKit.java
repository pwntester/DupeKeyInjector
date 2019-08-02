package ui;

import javax.swing.text.StyledEditorKit;
import javax.swing.text.ViewFactory;

// From: https://www.boplicity.nl/knowledgebase/Java/Xml+syntax+highlighting+in+Swing+JTextPane.html

public class XmlEditorKit extends StyledEditorKit {

    private static final long serialVersionUID = 2969169649596107757L;
    private ViewFactory xmlViewFactory;

    public XmlEditorKit() {
        xmlViewFactory = new XmlViewFactory();
    }

    @Override
    public ViewFactory getViewFactory() {
        return xmlViewFactory;
    }

    @Override
    public String getContentType() {
        return "text/xml";
    }
}
