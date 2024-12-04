import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.formdev.flatlaf.FlatLightLaf;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import com.fasterxml.jackson.databind.ObjectMapper;

import javax.swing.*;
import javax.swing.plaf.FontUIResource;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreeModel;
import javax.swing.tree.TreePath;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;
import java.util.Base64;

public class DigitalSignatureApp extends JFrame {
    private JButton uploadSingleButton;
    private JButton uploadMultipleButton;
    private JButton signAndSendButton;

    private JButton checkDocumentButton;


    private List<File> selectedFiles = new ArrayList<>();
    private JTextArea logArea;
    private PrivateKey privateKey;
    private X509Certificate certificate;
    private Provider pkcs11Provider;

    private String jsonRequest; // Променлива за съхранение на JSON заявката

    public DigitalSignatureApp() {
        setTitle("Приложение за електронен подпис");
        setSize(1000, 700);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        // Настройка на FlatLaf тема
        try {
            UIManager.setLookAndFeel(new FlatLightLaf());
        } catch (Exception ex) {
            System.err.println("Не успях да заредя FlatLaf тема");
        }

        // Персонализиране на шрифтовете
        FontUIResource fontUIResource = new FontUIResource("Segoe UI", Font.PLAIN, 14);
        Enumeration<Object> keys = UIManager.getDefaults().keys();
        while (keys.hasMoreElements()) {
            Object key = keys.nextElement();
            Object value = UIManager.get(key);
            if (value instanceof FontUIResource) {
                UIManager.put(key, fontUIResource);
            }
        }

        // Създаване на лента с менюта
        JMenuBar menuBar = new JMenuBar();
        JMenu fileMenu = new JMenu("Файл");
        JMenuItem exitMenuItem = new JMenuItem("Изход");
        exitMenuItem.addActionListener(e -> System.exit(0));
        fileMenu.add(exitMenuItem);
        menuBar.add(fileMenu);
        setJMenuBar(menuBar);

        // Премахване на иконите
        // Зареждането на иконите е премахнато

        // Създаване на бутоните без икони
        uploadSingleButton = new JButton("Качи файл");
        uploadMultipleButton = new JButton("Качи файлове");
        signAndSendButton = new JButton("Подпиши и изпрати");
        checkDocumentButton = new JButton("Проверка на документ");

        // Настройка на бутоните
        uploadSingleButton.setFocusPainted(false);
        uploadMultipleButton.setFocusPainted(false);
        signAndSendButton.setFocusPainted(false);
        checkDocumentButton.setFocusPainted(false);

        // Добавяне на слушатели за бутоните
        uploadSingleButton.addActionListener(new UploadSingleAction());
        uploadMultipleButton.addActionListener(new UploadMultipleAction());
        signAndSendButton.addActionListener(new SignAndSendAction());
        checkDocumentButton.addActionListener(new CheckDocumentAction());

        // Създаване на текстовото поле за логове
        logArea = new JTextArea();
        logArea.setEditable(false);
        JScrollPane logScrollPane = new JScrollPane(logArea);

        // Създаване на панела за подписване
        JPanel signPanel = new JPanel(new BorderLayout(10, 10));
        signPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel signButtonPanel = new JPanel(new GridLayout(3, 1, 10, 10));
        signButtonPanel.add(uploadSingleButton);
        signButtonPanel.add(uploadMultipleButton);
        signButtonPanel.add(signAndSendButton);

        signPanel.add(signButtonPanel, BorderLayout.WEST);
        signPanel.add(logScrollPane, BorderLayout.CENTER);

        // Създаване на панела за проверка
        JPanel checkPanel = new JPanel(new BorderLayout(10, 10));
        checkPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JButton performCheckButton = new JButton("Извърши проверка");
        performCheckButton.setFocusPainted(false);
        performCheckButton.addActionListener(new CheckDocumentAction());

        JTextArea checkLogArea = new JTextArea();
        checkLogArea.setEditable(false);
        JScrollPane checkLogScrollPane = new JScrollPane(checkLogArea);

        checkPanel.add(performCheckButton, BorderLayout.NORTH);
        checkPanel.add(checkLogScrollPane, BorderLayout.CENTER);

        // Създаване на табове
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.addTab("Подписване и изпращане", signPanel);
        tabbedPane.addTab("Проверка на документ", checkPanel);

        // Главен панел
        add(tabbedPane, BorderLayout.CENTER);
    }

    private void showHtmlResultDialog(String htmlContent) {
        JDialog dialog = new JDialog(this, "Резултат от обработката", true);
        dialog.setSize(600, 400);
        dialog.setLocationRelativeTo(this);

        JEditorPane editorPane = new JEditorPane();
        editorPane.setContentType("text/html");
        editorPane.setEditable(false);
        editorPane.setText(htmlContent);

        JScrollPane scrollPane = new JScrollPane(editorPane);

        JButton closeButton = new JButton("Затвори");
        closeButton.addActionListener(e -> dialog.dispose());

        JPanel buttonPanel = new JPanel();
        buttonPanel.add(closeButton);

        dialog.setLayout(new BorderLayout());
        dialog.add(scrollPane, BorderLayout.CENTER);
        dialog.add(buttonPanel, BorderLayout.SOUTH);

        dialog.setVisible(true);
    }


    private class UploadSingleAction implements ActionListener {
        @Override
        public void actionPerformed ( ActionEvent e ) {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("Изберете файл за подписване");
            int option = fileChooser.showOpenDialog(DigitalSignatureApp.this);
            if (option == JFileChooser.APPROVE_OPTION) {
                selectedFiles.clear();
                selectedFiles.add(fileChooser.getSelectedFile());
                log("Избран файл за подписване: " + fileChooser.getSelectedFile().getAbsolutePath());
            }
        }
    }

    private class UploadMultipleAction implements ActionListener {
        @Override
        public void actionPerformed ( ActionEvent e ) {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("Изберете файлове за подписване");
            fileChooser.setMultiSelectionEnabled(true);
            int option = fileChooser.showOpenDialog(DigitalSignatureApp.this);
            if (option == JFileChooser.APPROVE_OPTION) {
                selectedFiles = Arrays.asList(fileChooser.getSelectedFiles());
                log("Файлове за подписване:");
                for (File file : selectedFiles) {
                    log(" - " + file.getAbsolutePath());
                }
            }
        }
    }

    private class SignAndSendAction implements ActionListener {
        @Override
        public void actionPerformed ( ActionEvent e ) {
            if (selectedFiles.isEmpty()) {
                JOptionPane.showMessageDialog(DigitalSignatureApp.this, "Моля, изберете файлове за подписване.");
                return;
            }

            JPasswordField passwordField = new JPasswordField();
            Object[] message = {
                    "Въведете PIN за електронния подпис:", passwordField
            };
            final char defaultEchoChar = passwordField.getEchoChar();

            passwordField.addMouseListener(new MouseAdapter() {
                @Override
                public void mousePressed ( MouseEvent e ) {
                    passwordField.setEchoChar((char) 0);
                }

                @Override
                public void mouseReleased ( MouseEvent e ) {
                    passwordField.setEchoChar(defaultEchoChar);
                }
            });

            int option = JOptionPane.showConfirmDialog(DigitalSignatureApp.this, message, "PIN", JOptionPane.OK_CANCEL_OPTION);
            String pin = null;
            if (option == JOptionPane.OK_OPTION) {
                pin = new String(passwordField.getPassword());
                if (pin.isEmpty()) {
                    log("PIN не е въведен.");
                    return;
                }
            } else {
                log("PIN не е въведен.");
                return;
            }

            try {
                KeyStore keyStore = loadKeyStore(pin);
                if (keyStore != null) {
                    Enumeration<String> aliases = keyStore.aliases();
                    if (aliases.hasMoreElements()) {
                        String alias = aliases.nextElement();
                        log("Електронният подпис е намерен.");
                        log("Алиас на сертификата: " + alias);

                        certificate = (X509Certificate) keyStore.getCertificate(alias);
                        privateKey = (PrivateKey) keyStore.getKey(alias, pin.toCharArray());

                        List<File> signedFiles = signFiles();
                        sendToAPI(signedFiles);
                    } else {
                        log("Не са намерени сертификати на устройството.");
                    }
                }
            } catch (Exception ex) {
                log("Грешка при подписването и изпращането на файловете: " + ex.getMessage());
                ex.printStackTrace();
            }
        }


    }

    private KeyStore loadKeyStore ( String pin ) throws Exception {
        String libraryPath = getPKCS11LibraryPath();
        if (libraryPath == null) {
            throw new Exception("Не може да бъде намерена PKCS#11 библиотеката.");
        }

        String pkcs11Config = "--name=SmartCard\nlibrary=" + libraryPath;

        Provider pkcs11Provider = getSunPKCS11Provider(pkcs11Config);
        Security.addProvider(pkcs11Provider);
        this.pkcs11Provider = pkcs11Provider;

        KeyStore keyStore = KeyStore.getInstance("PKCS11", pkcs11Provider);
        keyStore.load(null, pin.toCharArray());
        return keyStore;
    }

    private Provider getSunPKCS11Provider ( String pkcs11Config ) throws Exception {
        Provider provider;
        Provider sunPKCS11 = Security.getProvider("SunPKCS11");
        if (sunPKCS11 == null) {
            throw new Exception("SunPKCS11 provider не е наличен.");
        }
        provider = sunPKCS11.configure(pkcs11Config);
        return provider;
    }

    private String getPKCS11LibraryPath () {
        String osName = System.getProperty("os.name").toLowerCase();
        List<String> possiblePaths = new ArrayList<>();
        if (osName.contains("win")) {
            possiblePaths.add("C:\\Windows\\System32\\eTPKCS11.dll");
            possiblePaths.add("C:\\Windows\\System32\\btCryptoki.dll");
        } else if (osName.contains("linux")) {
            possiblePaths.add("/usr/lib/libeTPkcs11.so");
            possiblePaths.add("/usr/lib/libbtcryptoki.so");
        } else if (osName.contains("mac")) {
            possiblePaths.add("/usr/local/lib/libeTPkcs11.dylib");
        }

        for (String path : possiblePaths) {
            File libFile = new File(path);
            if (libFile.exists()) {
                log("Намерена PKCS#11 библиотека: " + path);
                return path;
            }
        }

        log("Не може да бъде намерена PKCS#11 библиотека в обичайните локации.");
        return null;
    }

    private class CheckDocumentAction implements ActionListener {
        @Override
        public void actionPerformed ( ActionEvent e ) {
            JTextField egnField = new JTextField();
            JTextField documentIdField = new JTextField();
            JTextField entryNumberField = new JTextField();
            JTextField entryDateField = new JTextField();

            Object[] message = {
                    "Въведете ЕГН:", egnField,
                    "Въведете ИД на документа (или оставете празно, ако ще ползвате входящ номер и дата):", documentIdField,
                    "Въведете входящ номер (ако няма ИД на документа):", entryNumberField,
                    "Въведете дата (в формат yyyy-MM-dd HH:mm:ss):", entryDateField
            };

            int option = JOptionPane.showConfirmDialog(DigitalSignatureApp.this, message, "Проверка на документа", JOptionPane.OK_CANCEL_OPTION);

            if (option == JOptionPane.OK_OPTION) {
                String egn = egnField.getText().trim();
                String documentIdStr = documentIdField.getText().trim();
                String entryNumber = entryNumberField.getText().trim();
                String entryDate = entryDateField.getText().trim();

                if (egn.isEmpty()) {
                    log("ЕГН не е въведен.");
                    return;
                }

                Map<String, Object> jsonMap = new HashMap<>();
                jsonMap.put("taxpayerPin", egn);
                jsonMap.put("taxpayerPinType", "IND_EGN");
                jsonMap.put("userPin", egn);
                jsonMap.put("userPinType", "IND_EGN");

                // Include userSignatureBase64
                try {
                    if (certificate == null) {
                        // Load the certificate again
                        String pin = promptForPin();
                        if (pin == null) return;
                        KeyStore keyStore = loadKeyStore(pin);
                        if (keyStore != null) {
                            Enumeration<String> aliases = keyStore.aliases();
                            if (aliases.hasMoreElements()) {
                                String alias = aliases.nextElement();
                                certificate = (X509Certificate) keyStore.getCertificate(alias);
                            } else {
                                log("Не са намерени сертификати на устройството.");
                                return;
                            }
                        }
                    }
                    jsonMap.put("userSignatureBase64", getCertificateBase64());
                } catch (Exception ex) {
                    log("Грешка при получаване на сертификата: " + ex.getMessage());
                    return;
                }

                if (!documentIdStr.isEmpty()) {
                    try {
                        long documentId = Long.parseLong(documentIdStr);
                        jsonMap.put("documentId", documentId);
                    } catch (NumberFormatException ex) {
                        log("Невалиден ИД на документа.");
                        return;
                    }
                } else if (!entryNumber.isEmpty() && !entryDate.isEmpty()) {
                    jsonMap.put("entryNumber", entryNumber);
                    jsonMap.put("entryDate", entryDate);
                } else {
                    log("Трябва да въведете ИД на документа или входящ номер и дата.");
                    return;
                }

                try {
                    sendCheckRequest(jsonMap);
                } catch (Exception ex) {
                    log("Грешка при изпращане на заявката за проверка: " + ex.getMessage());
                    ex.printStackTrace();
                }
            } else {
                log("Проверката на документа е отменена.");
            }
        }
    }

    private String promptForPin () {
        JPasswordField passwordField = new JPasswordField();
        Object[] message = {
                "Въведете PIN за електронния подпис:", passwordField
        };
        final char defaultEchoChar = passwordField.getEchoChar();

        passwordField.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed ( MouseEvent e ) {
                passwordField.setEchoChar((char) 0);
            }

            @Override
            public void mouseReleased ( MouseEvent e ) {
                passwordField.setEchoChar(defaultEchoChar);
            }
        });

        int option = JOptionPane.showConfirmDialog(DigitalSignatureApp.this, message, "PIN", JOptionPane.OK_CANCEL_OPTION);
        if (option == JOptionPane.OK_OPTION) {
            String pin = new String(passwordField.getPassword());
            if (pin.isEmpty()) {
                log("PIN не е въведен.");
                return null;
            }
            return pin;
        } else {
            log("PIN не е въведен.");
            return null;
        }
    }


    private void sendCheckRequest ( Map<String, Object> jsonMap ) {
        String apiUrl = "https://public-api.nra.bg/declaration/api-declarations-test/result";
        ObjectMapper objectMapper = new ObjectMapper();
        String json;
        try {
            json = objectMapper.writeValueAsString(jsonMap);
        } catch (JsonProcessingException e) {
            log("Грешка при сериализиране на JSON: " + e.getMessage());
            return;
        }
        log("JSON заявка за проверка: " + json);

        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpPost httpPost = new HttpPost(apiUrl);
        httpPost.setHeader("Content-Type", "application/json");
        httpPost.setEntity(new StringEntity(json, StandardCharsets.UTF_8));

        // Заменете с вашия действителен Authorization токен
        httpPost.setHeader("Authorization", "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleS1pZCJ9.eyJzY29wZSI6WyJlcy1hcGktZXh0ZXJuYWw6c3VibWl0LWRlY2xhcmF0aW9uLXRlc3QiLCJlcy1hcGktZXh0ZXJuYWw6YXBpLWV4dGVybmFsIl0sImV4cCI6MTc2NDE2Mjg5NywianRpIjoiNDMwNmMwOWQtNWU1Yy00NzFiLTg3NzYtMjNhODkzNTkxYWJjIiwiY2xpZW50X2lkIjoiYzY5OGExNjItMDcxZS00YjQ2LWI2NDgtODI4ZTY5YWVmYWM3In0.NkA4ZgFGB7UvTlRMH5pASePAgNVuN-3jMEb2vfMuxKeS5II9g0IgXd-dJ65smRko1JQM3HrwEMYNhUEEo0UMICJSGgr766tGOIkFX5a7qmcnD8vdxBHU7fk3j5EOEtNrxAisG21PtY--HuDROokLwbFuJfoQRXVQ-H8NfNoTT_oSujxhKhQx6IDRb1pPznKyOskUimTGz8UCbA20d8oP9nhVIf67vdOFqjqRqn7I6d2Opwt9hWZh6S5rKvkINSi98DAzpW19Lvcwhry1YEIHSu00zszKLKQOScYGLgX_0ff00wuTUu-xdBKVvcUAWX1n-39u-Y3LXRQr6ipkiYLYYQ");

        try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
            int statusCode = response.getStatusLine().getStatusCode();
            String responseBody = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
            log("API статус: " + statusCode);
            log("Отговор от API: " + responseBody);

            if (statusCode == 200) {
                ObjectMapper responseMapper = new ObjectMapper();
                ApiResultResponse apiResultResponse = responseMapper.readValue(responseBody, ApiResultResponse.class);

                showApiResultDialog(apiResultResponse);
            } else {
                // Обработка на грешка
                log("Грешка при изпращане към API-то. Статус код: " + statusCode);
                log("Отговор от API: " + responseBody);

                // Можете да десериализирате грешката в обект, ако желаете
                // ErrorResponse errorResponse = responseMapper.readValue(responseBody, ErrorResponse.class);

                JOptionPane.showMessageDialog(this, "Грешка при изпращане към API-то. Статус код: " + statusCode);
            }
        } catch (IOException ex) {
            log("Грешка при изпращане на заявката: " + ex.getMessage());
            ex.printStackTrace();
        }
    }


    private List<File> signFiles () throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        List<File> signedFiles = new ArrayList<>();

        for (File file : selectedFiles) {
            File signedFile = signFile(file);
            signedFiles.add(signedFile);
            log("Подписан файл: " + signedFile.getName());
        }

        return signedFiles;
    }

    private File signFile ( File inputFile ) throws Exception {
        byte[] fileData = Files.readAllBytes(inputFile.toPath());

        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        ContentSigner signer = createP11ContentSigner("SHA256withRSA", privateKey, pkcs11Provider);

        generator.addSignerInfoGenerator(new SignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().build())
                .build(signer, new JcaX509CertificateHolder(certificate)));
        generator.addCertificate(new JcaX509CertificateHolder(certificate));

        CMSProcessableByteArray cmsData = new CMSProcessableByteArray(fileData);
        CMSSignedData signedData = generator.generate(cmsData, false);

        byte[] signatureBytes = signedData.getEncoded();
        File signedFile = new File(inputFile.getParent(), inputFile.getName() + ".p7s");
        try (FileOutputStream fos = new FileOutputStream(signedFile)) {
            fos.write(signatureBytes);
        }

        return signedFile;
    }

    private void showApiResultDialog(ApiResultResponse apiResultResponse) {
        StringBuilder sb = new StringBuilder();
        sb.append("Резултат от обработката на документа:\n");
        sb.append("Входящ номер: ").append(apiResultResponse.getEntryNumber()).append("\n");
        sb.append("Дата на входиране: ").append(apiResultResponse.getEntryDate()).append("\n");
        if (apiResultResponse.getProcessingStatus() != null) {
            sb.append("Статус на обработката: ").append(apiResultResponse.getProcessingStatus()).append("\n");
        }
        if (apiResultResponse.getErrors() != null && !apiResultResponse.getErrors().isEmpty()) {
            sb.append("Грешки:\n");
            for (String error : apiResultResponse.getErrors()) {
                sb.append(" - ").append(error).append("\n");
            }
        }
        if (apiResultResponse.getWarnings() != null && !apiResultResponse.getWarnings().isEmpty()) {
            sb.append("Предупреждения:\n");
            for (String warning : apiResultResponse.getWarnings()) {
                sb.append(" - ").append(warning).append("\n");
            }
        }

        // Показване на основната информация в диалогов прозорец
        JOptionPane.showMessageDialog(this, sb.toString(), "Резултат от обработката", JOptionPane.INFORMATION_MESSAGE);

        // Тук добавете кода за обработка на base64HtmlResult
        String base64HtmlResult = apiResultResponse.getBase64HtmlResult();
        if (base64HtmlResult != null && !base64HtmlResult.isEmpty()) {
            byte[] decodedBytes = Base64.getDecoder().decode(base64HtmlResult);
            String htmlResult = new String(decodedBytes, StandardCharsets.UTF_8);
            // Показване на HTML резултата в нов диалогов прозорец
            showHtmlResultDialog(htmlResult);
        }

        // Ако искате да обработите и base64FullHtmlResultInfo
        String base64FullHtmlResultInfo = apiResultResponse.getBase64FullHtmlResultInfo();
        if (base64FullHtmlResultInfo != null && !base64FullHtmlResultInfo.isEmpty()) {
            byte[] decodedBytes = Base64.getDecoder().decode(base64FullHtmlResultInfo);
            String htmlFullResult = new String(decodedBytes, StandardCharsets.UTF_8);
            // Можете да решите дали да покажете пълния HTML резултат
            // showHtmlResultDialog(htmlFullResult);
        }
    }




    private ContentSigner createP11ContentSigner ( String algorithm, PrivateKey privateKey, Provider provider ) throws OperatorCreationException {
        try {
            Signature signature = Signature.getInstance(algorithm, provider);
            signature.initSign(privateKey);

            return new ContentSigner() {
                private ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                private AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(algorithm);
                // Не се използва digAlgId, може да бъде премахнато
                // private AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

                @Override
                public AlgorithmIdentifier getAlgorithmIdentifier () {
                    return sigAlgId;
                }

                @Override
                public OutputStream getOutputStream () {
                    return outputStream;
                }

                @Override
                public byte[] getSignature () {
                    try {
                        signature.update(outputStream.toByteArray());
                        return signature.sign();
                    } catch (Exception e) {
                        throw new RuntimeException("Грешка при създаване на подпис: " + e.getMessage(), e);
                    }
                }
            };
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new OperatorCreationException("Неуспешно създаване на ContentSigner: " + e.getMessage(), e);
        }
    }

    private void sendToAPI ( List<File> signedFiles ) throws Exception {
        String apiUrl = "https://public-api.nra.bg/declaration/api-declarations-test/";

        String taxpayerPin = JOptionPane.showInputDialog(this, "Въведете ЕГН (тъй като сте физическо лице):");
        if (taxpayerPin == null || taxpayerPin.trim().isEmpty()) {
            log("ЕГН не е въведен.");
            return;
        }

        String egn = taxpayerPin;

        Map<String, Object> jsonMap = new HashMap<>();
        jsonMap.put("taxpayerPin", taxpayerPin);
        jsonMap.put("taxpayerPinType", "IND_EGN");
        jsonMap.put("userPin", egn);
        jsonMap.put("userPinType", "IND_EGN");
        jsonMap.put("serviceDocumentType", "DEC_1_6");
        jsonMap.put("userSignatureBase64", getCertificateBase64());
        jsonMap.put("taxPeriodFrom", "03");
        jsonMap.put("taxPeriodTo", "03");
        jsonMap.put("year", "2023");
        jsonMap.put("insuranceFund", 0);

        List<Map<String, Object>> filesList = new ArrayList<>();
        for (File file : signedFiles) {
            File originalFile = new File(file.getParent(), file.getName().replace(".p7s", ""));

            // Определяне на типа документ и новото име на файла въз основа на размера
            long fileSize = originalFile.length();
            String fileDocumentType;
            String newFileName;

            if (fileSize >= 1024) { // Файлове по-големи или равни на 1 KB
                fileDocumentType = "DEC_1";
                newFileName = "D1";
            } else { // Файлове по-малки от 1 KB
                fileDocumentType = "DEC_6";
                newFileName = "D6";
            }

            Map<String, Object> fileMap = new HashMap<>();
            fileMap.put("fileName", newFileName);
            fileMap.put("fileType", getFileType(originalFile.getName()));
            fileMap.put("fileSize", originalFile.length());
            fileMap.put("fileContentBase64", getFileContentBase64(originalFile));
            fileMap.put("base64EncodedPkcs7", getSignatureBase64(file));
            fileMap.put("fileDocumentType", fileDocumentType);
            fileMap.put("numRecords", getNumRecords(originalFile));
            filesList.add(fileMap);
        }

        if (filesList.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Няма налични файлове за изпращане към API. Уверете се, че всички файлове имат валиден тип документ.");
            log("Не са добавени файлове към заявката поради липса на валиден тип документ.");
            return;
        }

        jsonMap.put("files", filesList);

        ObjectMapper objectMapper = new ObjectMapper();
        String json = objectMapper.writeValueAsString(jsonMap);
        log("JSON заявка: " + json);

        // Съхраняваме JSON заявката за по-късно използване
        this.jsonRequest = json;

        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpPost httpPost = new HttpPost(apiUrl);
        httpPost.setHeader("Content-Type", "application/json");
        httpPost.setEntity(new StringEntity(json, "UTF-8"));

        httpPost.setHeader("Authorization", "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleS1pZCJ9.eyJzY29wZSI6WyJlcy1hcGktZXh0ZXJuYWw6c3VibWl0LWRlY2xhcmF0aW9uLXRlc3QiLCJlcy1hcGktZXh0ZXJuYWw6YXBpLWV4dGVybmFsIl0sImV4cCI6MTc2NDE2Mjg5NywianRpIjoiNDMwNmMwOWQtNWU1Yy00NzFiLTg3NzYtMjNhODkzNTkxYWJjIiwiY2xpZW50X2lkIjoiYzY5OGExNjItMDcxZS00YjQ2LWI2NDgtODI4ZTY5YWVmYWM3In0.NkA4ZgFGB7UvTlRMH5pASePAgNVuN-3jMEb2vfMuxKeS5II9g0IgXd-dJ65smRko1JQM3HrwEMYNhUEEo0UMICJSGgr766tGOIkFX5a7qmcnD8vdxBHU7fk3j5EOEtNrxAisG21PtY--HuDROokLwbFuJfoQRXVQ-H8NfNoTT_oSujxhKhQx6IDRb1pPznKyOskUimTGz8UCbA20d8oP9nhVIf67vdOFqjqRqn7I6d2Opwt9hWZh6S5rKvkINSi98DAzpW19Lvcwhry1YEIHSu00zszKLKQOScYGLgX_0ff00wuTUu-xdBKVvcUAWX1n-39u-Y3LXRQr6ipkiYLYYQ\n");

        try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
            int statusCode = response.getStatusLine().getStatusCode();
            String responseBody = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
            log("API статус: " + statusCode);
            log("Отговор от API: " + responseBody);

            if (statusCode == 200) {
                // Парсиране на JSON отговора
                ApiResponse apiResponse = objectMapper.readValue(responseBody, ApiResponse.class);

                // Форматиране на изхода
                String formattedResponse = String.format(
                        "Документите са изпратени успешно.\n" +
                                "Входящ номер: %s\n" +
                                "Дата на входиране: %s\n" +
                                "ID на документ: %d",
                        apiResponse.getEntryNumber(),
                        apiResponse.getEntryDate(),
                        apiResponse.getDocumentId()
                );

                // Показваме персонализирания диалогов прозорец
                showResponseDialog(formattedResponse);

                logToFile("Успешно изпращане към API: " + formattedResponse);
            } else {
                log("Грешка при изпращане към API-то. Статус код: " + statusCode);
                JOptionPane.showMessageDialog(this, "Грешка при изпращане към API-то. Статус код: " + statusCode);
                logToFile("Неуспешно изпращане към API. Статус код: " + statusCode + ", Отговор: " + responseBody);
            }
        }
    }

    private void showResponseDialog ( String formattedResponse ) {
        // Създаваме JDialog
        JDialog dialog = new JDialog(this, "Резултат", true);
        dialog.setSize(400, 300);
        dialog.setLocationRelativeTo(this);

        // Създаваме JTextArea за показване на форматирания отговор
        JTextArea responseArea = new JTextArea(formattedResponse);
        responseArea.setEditable(false);
        responseArea.setLineWrap(true);
        responseArea.setWrapStyleWord(true);
        JScrollPane scrollPane = new JScrollPane(responseArea);

        // Създаваме бутон "Разглеждане на заявката"
        JButton viewRequestButton = new JButton("Разглеждане на заявката");
        viewRequestButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed ( ActionEvent e ) {
                // Показваме JSON заявката в нов диалогов прозорец
                showJsonRequestDialog();
            }
        });

        // Създаваме бутон "Затвори"
        JButton closeButton = new JButton("Затвори");
        closeButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed ( ActionEvent e ) {
                dialog.dispose();
            }
        });

        // Подреждаме компонентите в диалоговия прозорец
        JPanel buttonPanel = new JPanel();
        buttonPanel.add(viewRequestButton);
        buttonPanel.add(closeButton);

        dialog.setLayout(new BorderLayout());
        dialog.add(scrollPane, BorderLayout.CENTER);
        dialog.add(buttonPanel, BorderLayout.SOUTH);

        dialog.setVisible(true);
    }

    private void showJsonRequestDialog () {
        // Създаваме JDialog
        JDialog jsonDialog = new JDialog(this, "JSON Заявка", true);
        jsonDialog.setSize(600, 400);
        jsonDialog.setLocationRelativeTo(this);

        try {
            // Парсираме JSON заявката в обект
            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode jsonNode = objectMapper.readTree(jsonRequest);

            // Преобразуваме JSON обекта в TreeModel
            TreeModel treeModel = createTreeModel(jsonNode);

            // Създаваме JTree с персонализиран TreeCellRenderer
            JTree tree = new JTree(treeModel);
            tree.setCellRenderer(new JsonTreeCellRenderer());
            tree.setRootVisible(true);
            tree.setShowsRootHandles(true);

            // Добавяме слушател за двойно кликване върху възлите
            tree.addMouseListener(new MouseAdapter() {
                public void mouseClicked ( MouseEvent me ) {
                    TreePath tp = tree.getPathForLocation(me.getX(), me.getY());
                    if (tp != null) {
                        if (me.getClickCount() == 2) {
                            DefaultMutableTreeNode node = (DefaultMutableTreeNode) tp.getLastPathComponent();
                            if (node.getUserObject() instanceof JsonTreeNodeData) {
                                JsonTreeNodeData data = (JsonTreeNodeData) node.getUserObject();
                                data.toggleExpanded();
                                ((DefaultTreeModel) tree.getModel()).nodeChanged(node);
                            }
                        }
                    }
                }
            });

            JScrollPane scrollPane = new JScrollPane(tree);

            // Създаваме бутон "Затвори"
            JButton closeButton = new JButton("Затвори");
            closeButton.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed ( ActionEvent e ) {
                    jsonDialog.dispose();
                }
            });

            // Подреждаме компонентите в диалоговия прозорец
            JPanel buttonPanel = new JPanel();
            buttonPanel.add(closeButton);

            jsonDialog.setLayout(new BorderLayout());
            jsonDialog.add(scrollPane, BorderLayout.CENTER);
            jsonDialog.add(buttonPanel, BorderLayout.SOUTH);

            jsonDialog.setVisible(true);
        } catch (IOException e) {
            // Обработка на грешка при парсиране на JSON
            JOptionPane.showMessageDialog(this, "Грешка при форматирането на JSON заявката: " + e.getMessage());
        }
    }


    private void logToFile ( String message ) {
        try {
            File logDir = new File("Logs");
            if (!logDir.exists()) {
                logDir.mkdir();
            }
            File logFile = new File(logDir, "logs.txt");
            try (FileWriter fw = new FileWriter(logFile, true);
                 BufferedWriter bw = new BufferedWriter(fw);
                 PrintWriter out = new PrintWriter(bw)) {
                String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
                out.println(timestamp + " - " + message);
            }
        } catch (IOException e) {
            log("Грешка при записването в лог файла: " + e.getMessage());
        }
    }

    private String getFileType ( String fileName ) {
        int lastDot = fileName.lastIndexOf('.');
        if (lastDot == -1) {
            return "txt";
        }
        return fileName.substring(lastDot + 1).toLowerCase();
    }

    private String getCertificateBase64 () throws CertificateEncodingException {
        byte[] certBytes = certificate.getEncoded();
        return Base64.getEncoder().encodeToString(certBytes);
    }

    private String getFileContentBase64 ( File file ) throws IOException {
        byte[] fileBytes = Files.readAllBytes(file.toPath());
        return Base64.getEncoder().encodeToString(fileBytes);
    }

    private String getSignatureBase64 ( File signedFile ) throws IOException {
        byte[] signatureBytes = Files.readAllBytes(signedFile.toPath());
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    private String getFileDocumentType ( String fileName ) {
        String upperFileName = fileName.toUpperCase(Locale.ENGLISH);
        if (upperFileName.contains("DEC1")) {
            return "DEC_1";
        } else if (upperFileName.contains("DEC6")) {
            return "DEC_6";
        } else if (upperFileName.contains("D1")) {
            return "DEC_1";
        } else if (upperFileName.contains("D6")) {
            return "DEC_6";
        } else if (upperFileName.contains("NOTICE_62_5")) {
            return "DEC_NOTICE_62_5";
        } else if (upperFileName.contains("NOTICE_123_1")) {
            return "DEC_NOTICE_123_1";
        } else if (upperFileName.contains("FISC_RISK_EU_BG")) {
            return "DEC_FISC_RISK_EU_BG";
        } else if (upperFileName.contains("FISC_RISK_BG_EU")) {
            return "DEC_FISC_RISK_BG_EU";
        } else if (upperFileName.contains("FISC_RISK_ANNUL")) {
            return "DEC_FISC_RISK_ANNUL";
        } else if (upperFileName.contains("FISC_RISK_CONFIRM")) {
            return "DEC_FISC_RISK_CONFIRM";
        } else if (upperFileName.contains("FISC_RISK_BG_BG")) {
            return "DEC_FISC_RISK_BG_BG";
        } else if (upperFileName.contains("FISC_RISK_IMPORT")) {
            return "DEC_FISC_RISK_IMPORT";
        } else {
            log("Не може да се определи типът на файла: " + fileName + ". Файлът няма да бъде добавен към заявката.");
            return "DEC_UNKNOWN";
        }
    }

    private int getNumRecords ( File file ) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            int lines = 0;
            while (reader.readLine() != null) lines++;
            return lines;
        }
    }

    private void log ( String message ) {
        logArea.append(message + "\n");
    }

    private TreeModel createTreeModel ( JsonNode jsonNode ) {
        DefaultMutableTreeNode root = new DefaultMutableTreeNode("JSON Заявка");
        buildTree(jsonNode, root);
        return new DefaultTreeModel(root);
    }

    private void buildTree ( JsonNode jsonNode, DefaultMutableTreeNode parent ) {
        if (jsonNode.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = jsonNode.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> entry = fields.next();
                String key = entry.getKey();
                JsonNode value = entry.getValue();

                DefaultMutableTreeNode child = new DefaultMutableTreeNode(new JsonTreeNodeData(key, value));
                parent.add(child);
                buildTree(value, child);
            }
        } else if (jsonNode.isArray()) {
            int index = 0;
            for (JsonNode item : jsonNode) {
                DefaultMutableTreeNode child = new DefaultMutableTreeNode(new JsonTreeNodeData("[" + index + "]", item));
                parent.add(child);
                buildTree(item, child);
                index++;
            }
        }
    }


    public static void main ( String[] args ) {
        SwingUtilities.invokeLater(() -> {
            DigitalSignatureApp app = new DigitalSignatureApp();
            app.setVisible(true);
        });
    }
}