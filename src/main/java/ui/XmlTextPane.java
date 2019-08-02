package ui;

import javax.swing.*;
import java.awt.*;

// From: https://www.boplicity.nl/knowledgebase/Java/Xml+syntax+highlighting+in+Swing+JTextPane.html

public class XmlTextPane extends JTextPane {

    private static final long serialVersionUID = 6270183148379328084L;

    public XmlTextPane() {

        Font font = new Font("Dialog", Font.PLAIN, 20);
        this.setFont(font);
        this.setEditorKitForContentType("text/xml", new XmlEditorKit());
        this.setContentType("text/xml");
        this.setText("");
        this.setBackground(new Color(255,255,255));


    }

}
