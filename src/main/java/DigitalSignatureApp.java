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
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import com.fasterxml.jackson.databind.ObjectMapper;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;
import java.util.Base64;

import static java.rmi.server.LogStream.log;

public class DigitalSignatureApp extends JFrame {
    private JButton uploadSingleButton;
    private JButton uploadMultipleButton;
    private JButton signAndSendButton;

    private List<File> selectedFiles = new ArrayList<>();
    private JTextArea logArea;
    private PrivateKey privateKey;
    private X509Certificate certificate;
    private Provider pkcs11Provider;

    public DigitalSignatureApp () {
        setTitle("Digital Signature Application");
        setSize(800, 600);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        uploadSingleButton = new JButton("Качи файл за подписване");
        uploadMultipleButton = new JButton("Качи файлове за подписване");
        signAndSendButton = new JButton("Подпиши и изпрати към API");

        logArea = new JTextArea();
        logArea.setEditable(false);
        JScrollPane logScrollPane = new JScrollPane(logArea);

        uploadSingleButton.addActionListener(new UploadSingleAction());
        uploadMultipleButton.addActionListener(new UploadMultipleAction());
        signAndSendButton.addActionListener(new SignAndSendAction());

        JPanel buttonPanel = new JPanel(new GridLayout(1, 3, 10, 10));
        buttonPanel.add(uploadSingleButton);
        buttonPanel.add(uploadMultipleButton);
        buttonPanel.add(signAndSendButton);

        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        mainPanel.add(buttonPanel, BorderLayout.NORTH);
        mainPanel.add(logScrollPane, BorderLayout.CENTER);

        add(mainPanel);
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

    private ContentSigner createP11ContentSigner ( String algorithm, PrivateKey privateKey, Provider provider ) throws OperatorCreationException {
        try {
            Signature signature = Signature.getInstance(algorithm, provider);
            signature.initSign(privateKey);

            return new ContentSigner() {
                private ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                private AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(algorithm);
                private AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

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
            String fileDocumentType = getFileDocumentType(originalFile.getName());
            if (fileDocumentType.equals("DEC_UNKNOWN")) {
                log("Типът на файла не е разпознат и файлът няма да бъде добавен към заявката: " + originalFile.getName());
                continue; // Пропускане на този файл
            }

            Map<String, Object> fileMap = new HashMap<>();
            fileMap.put("fileName", originalFile.getName());
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

        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpPost httpPost = new HttpPost(apiUrl);
        httpPost.setHeader("Content-Type", "application/json");
        httpPost.setEntity(new StringEntity(json, "UTF-8"));

        httpPost.setHeader("Authorization", "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleS1pZCJ9.eyJzY29wZSI6WyJlcy1hcGktZXh0ZXJuYWw6c3VibWl0LWRlY2xhcmF0aW9uLXRlc3QiLCJlcy1hcGktZXh0ZXJuYWw6YXBpLWV4dGVybmFsIl0sImV4cCI6MTc2NDE2Mjg5NywianRpIjoiNDMwNmMwOWQtNWU1Yy00NzFiLTg3NzYtMjNhODkzNTkxYWJjIiwiY2xpZW50X2lkIjoiYzY5OGExNjItMDcxZS00YjQ2LWI2NDgtODI4ZTY5YWVmYWM3In0.NkA4ZgFGB7UvTlRMH5pASePAgNVuN-3jMEb2vfMuxKeS5II9g0IgXd-dJ65smRko1JQM3HrwEMYNhUEEo0UMICJSGgr766tGOIkFX5a7qmcnD8vdxBHU7fk3j5EOEtNrxAisG21PtY--HuDROokLwbFuJfoQRXVQ-H8NfNoTT_oSujxhKhQx6IDRb1pPznKyOskUimTGz8UCbA20d8oP9nhVIf67vdOFqjqRqn7I6d2Opwt9hWZh6S5rKvkINSi98DAzpW19Lvcwhry1YEIHSu00zszKLKQOScYGLgX_0ff00wuTUu-xdBKVvcUAWX1n-39u-Y3LXRQr6ipkiYLYYQ\n");

        try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
            int statusCode = response.getStatusLine().getStatusCode();
            String responseBody = EntityUtils.toString(response.getEntity());
            log("API статус: " + statusCode);
            log("Отговор от API: " + responseBody);

            if (statusCode == 200) {
                JOptionPane.showMessageDialog(this, "Документите са изпратени успешно.");
                logToFile("Успешно изпращане към API: " + responseBody);
            } else {
                log("Грешка при изпращане към API-то. Статус код: " + statusCode);
                JOptionPane.showMessageDialog(this, "Грешка при изпращане към API-то. Статус код: " + statusCode);
                logToFile("Неуспешно изпращане към API. Статус код: " + statusCode + ", Отговор: " + responseBody);
            }
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

    public static void main ( String[] args ) {
        SwingUtilities.invokeLater(() -> {
            DigitalSignatureApp app = new DigitalSignatureApp();
            app.setVisible(true);
        });
    }
}
