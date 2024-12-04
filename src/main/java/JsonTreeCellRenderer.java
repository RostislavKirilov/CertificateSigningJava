import com.fasterxml.jackson.databind.JsonNode;

import javax.swing.*;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import java.awt.*;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

class JsonTreeCellRenderer extends DefaultTreeCellRenderer {
    private static final int MAX_VALUE_LENGTH = 50; // Максимална дължина на показваната стойност
    private static final Set<String> FIELDS_TO_TRUNCATE = new HashSet<>(Arrays.asList(
            "userSignatureBase64", "fileContentBase64", "base64EncodedPkcs7"
    ));

    @Override
    public Component getTreeCellRendererComponent( JTree tree, Object value,
                                                   boolean sel, boolean expanded, boolean leaf, int row, boolean hasFocus) {

        Component c = super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, hasFocus);

        DefaultMutableTreeNode node = (DefaultMutableTreeNode) value;
        Object userObject = node.getUserObject();

        if (userObject instanceof JsonTreeNodeData) {
            JsonTreeNodeData data = (JsonTreeNodeData) userObject;
            JsonNode jsonValue = data.getValue();

            String text;
            if (jsonValue.isObject() || jsonValue.isArray()) {
                text = data.getKey();
            } else {
                String valueText = jsonValue.asText();
                if (FIELDS_TO_TRUNCATE.contains(data.getKey()) && !data.isExpanded()) {
                    valueText = "(скрито, двойно кликване за показване)";
                } else if (!data.isExpanded() && valueText.length() > MAX_VALUE_LENGTH) {
                    valueText = valueText.substring(0, MAX_VALUE_LENGTH) + "... (двойно кликване за повече)";
                }
                text = data.getKey() + ": " + valueText;
            }
            setText(text);
        } else {
            setText(value.toString());
        }

        return c;
    }
}
