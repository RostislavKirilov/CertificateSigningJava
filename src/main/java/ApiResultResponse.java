import java.util.List;

public class ApiResultResponse {
    private String entryNumber;
    private String entryDate;
    private Long documentId;
    private String processingStatus;
    private List<String> errors;
    private List<String> warnings;
    private String base64HtmlResult;
    private String base64FullHtmlResultInfo;
    private String base64Result;

    // Гетъри и сетъри за всички полета

    public String getEntryNumber() {
        return entryNumber;
    }

    public void setEntryNumber(String entryNumber) {
        this.entryNumber = entryNumber;
    }

    public String getEntryDate() {
        return entryDate;
    }

    public void setEntryDate(String entryDate) {
        this.entryDate = entryDate;
    }

    public Long getDocumentId() {
        return documentId;
    }

    public void setDocumentId(Long documentId) {
        this.documentId = documentId;
    }

    public String getProcessingStatus() {
        return processingStatus;
    }

    public void setProcessingStatus(String processingStatus) {
        this.processingStatus = processingStatus;
    }

    public List<String> getErrors() {
        return errors;
    }

    public void setErrors(List<String> errors) {
        this.errors = errors;
    }

    public List<String> getWarnings() {
        return warnings;
    }

    public void setWarnings(List<String> warnings) {
        this.warnings = warnings;
    }

    public String getBase64HtmlResult() {
        return base64HtmlResult;
    }

    public void setBase64HtmlResult(String base64HtmlResult) {
        this.base64HtmlResult = base64HtmlResult;
    }

    public String getBase64FullHtmlResultInfo() {
        return base64FullHtmlResultInfo;
    }

    public void setBase64FullHtmlResultInfo(String base64FullHtmlResultInfo) {
        this.base64FullHtmlResultInfo = base64FullHtmlResultInfo;
    }

    public String getBase64Result() {
        return base64Result;
    }

    public void setBase64Result(String base64Result) {
        this.base64Result = base64Result;
    }
}
