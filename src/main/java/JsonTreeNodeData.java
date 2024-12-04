import com.fasterxml.jackson.databind.JsonNode;

class JsonTreeNodeData {
    private String key;
    private JsonNode value;
    private boolean expanded = false;

    public JsonTreeNodeData(String key, JsonNode value) {
        this.key = key;
        this.value = value;
    }

    public String getKey() {
        return key;
    }

    public JsonNode getValue() {
        return value;
    }

    public boolean isExpanded() {
        return expanded;
    }

    public void toggleExpanded() {
        this.expanded = !this.expanded;
    }
}
