package ui;

import javax.swing.text.*;

// From: https://www.boplicity.nl/knowledgebase/Java/Xml+syntax+highlighting+in+Swing+JTextPane.html

public class XmlViewFactory extends Object implements ViewFactory {

    public View create(Element elem) {
        return new XmlView(elem);
    }

}
