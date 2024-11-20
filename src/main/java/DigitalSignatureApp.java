import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.entity.mime.content.FileBody;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import javax.swing.JPasswordField;


import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.List;

public class DigitalSignatureApp extends JFrame {
    private JButton uploadSingleButton;
    private JButton uploadMultipleButton;
    private JButton signAndSendButton;

    private List<File> selectedFiles = new ArrayList<>();
    private JTextArea logArea;
    private PrivateKey privateKey;
    private X509Certificate certificate;

    public DigitalSignatureApp() {
        setTitle("Digital Signature Application");
        setSize(700, 500);
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
        public void actionPerformed(ActionEvent e) {
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
        public void actionPerformed(ActionEvent e) {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("Изберете файлове за подписване");
            fileChooser.setMultiSelectionEnabled(true);
            int option = fileChooser.showOpenDialog(DigitalSignatureApp.this);
            if (option == JFileChooser.APPROVE_OPTION) {
                selectedFiles = Arrays.asList(fileChooser.getSelectedFiles());
                log("Файлове за подписване: ");
                for (File file : selectedFiles) {
                    log(" - " + file.getAbsolutePath());
                }
            }
        }
    }

    @SuppressWarnings("SpellCheckingInspection")
    private class SignAndSendAction implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
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
                public void mouseEntered(MouseEvent e) {
                    passwordField.setEchoChar((char) 0);
                }

                @Override
                public void mouseExited(MouseEvent e) {
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
                    // Get aliases
                    Enumeration<String> aliases = keyStore.aliases();
                    if (aliases.hasMoreElements()) {
                        String alias = aliases.nextElement();
                        log("Електронният подпис е намерен.");
                        log("Алиас на сертификата: " + alias);

                        certificate = (X509Certificate) keyStore.getCertificate(alias);
                        privateKey = (PrivateKey) keyStore.getKey(alias, pin.toCharArray());

                        // Sign and send files
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


    private KeyStore loadKeyStore(String pin) throws Exception {
        String libraryPath = getPKCS11LibraryPath();
        if (libraryPath == null) {
            throw new Exception("Не може да бъде намерена PKCS#11 библиотеката.");
        }

        String pkcs11Config = "--name=SmartCard\nlibrary=" + libraryPath;

        Provider pkcs11Provider = getSunPKCS11Provider(pkcs11Config);

        Security.addProvider(pkcs11Provider);

        KeyStore keyStore = KeyStore.getInstance("PKCS11", pkcs11Provider);
        keyStore.load(null, pin.toCharArray());

        return keyStore;
    }

    private Provider getSunPKCS11Provider(String pkcs11Config) throws Exception {
        Provider provider;

        Provider sunPKCS11 = Security.getProvider("SunPKCS11");
        if (sunPKCS11 == null) {
            throw new Exception("SunPKCS11 provider не е наличен.");
        }
        provider = sunPKCS11.configure(pkcs11Config);

        return provider;
    }

    private String getPKCS11LibraryPath() {
        String osName = System.getProperty("os.name").toLowerCase();
        List<String> possiblePaths = new ArrayList<>();

        if (osName.contains("win")) {
            // Windows possible paths
            possiblePaths.add("C:\\Windows\\System32\\eTPKCS11.dll"); // SafeNet
            possiblePaths.add("C:\\Windows\\System32\\btCryptoki.dll"); // Borica (b-trust)
        } else if (osName.contains("linux")) {
            // Linux possible paths
            possiblePaths.add("/usr/lib/libeTPkcs11.so"); // SafeNet
            possiblePaths.add("/usr/lib/libeToken.so"); // SafeNet
            possiblePaths.add("/usr/lib/libbtcryptoki.so"); // Borica
        } else if (osName.contains("mac")) {
            // macOS possible paths
            possiblePaths.add("/usr/local/lib/libeTPkcs11.dylib"); // SafeNet
            possiblePaths.add("/usr/local/lib/libbtcryptoki.dylib"); // Borica
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

    private List<File> signFiles() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        List<File> signedFiles = new ArrayList<>();

        for (File file : selectedFiles) {
            File signedFile = signFile(file);
            signedFiles.add(signedFile);
            log("Подписан файл: " + signedFile.getName());
        }

        return signedFiles;
    }

    private File signFile(File inputFile) throws Exception {
        byte[] fileData = Files.readAllBytes(inputFile.toPath());

        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

        String signatureAlgorithm = certificate.getSigAlgName();
        if (signatureAlgorithm == null || signatureAlgorithm.isEmpty()) {
            signatureAlgorithm = "SHA256withRSA";
        }

        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
                .setProvider("SunPKCS11-SmartCard")
                .build(privateKey);

        generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                .build(signer, certificate));
        generator.addCertificate(new JcaX509CertificateHolder(certificate));

        CMSProcessableByteArray cmsData = new CMSProcessableByteArray(fileData);
        CMSSignedData signedData = generator.generate(cmsData, true);

        File signedFile = new File(inputFile.getParent(), inputFile.getName() + ".p7s");
        try (FileOutputStream fos = new FileOutputStream(signedFile)) {
            fos.write(signedData.getEncoded());
        }

        return signedFile;
    }

    private void sendToAPI(List<File> files) throws Exception {
        String apiUrl = "https://teststess.free.beeceptor.com";
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpPost uploadFile = new HttpPost(apiUrl);
            MultipartEntityBuilder builder = MultipartEntityBuilder.create();
            for (File file : files) {
                builder.addPart("files", new FileBody(file));
            }
            HttpEntity multipart = builder.build();
            uploadFile.setEntity(multipart);

            try (CloseableHttpResponse response = httpClient.execute(uploadFile)) {
                int statusCode = response.getStatusLine().getStatusCode();
                log("API статус: " + statusCode);
                JOptionPane.showMessageDialog(this, "Документите са изпратени успешно. Статус код: " + statusCode);
            }
        }
    }

    private void log(String message) {
        logArea.append(message + "\n");
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            DigitalSignatureApp app = new DigitalSignatureApp();
            app.setVisible(true);
        });
    }
}
