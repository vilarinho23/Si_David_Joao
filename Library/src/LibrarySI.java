import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.json.JSONObject;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Scanner;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * A classe LibrarySI representa uma biblioteca de segurança para gestão de licenças.
 * Inclui métodos para a validação de licenças, registo e apresentação das mesmas.
 * A classe utiliza a biblioteca Bouncy Castle para operações criptográficas e interage com um smart card para gestão de chaves do cartão de cidadão.
 *
 * @author David e João
 * @version 1.0.0
 * @since SIDavidJoao 1.0.0
 */
public class LibrarySI {
    private static final Scanner scanner = new Scanner(System.in);
    private static String appName;
    private static String appVersion;
    private static LibKeyGen libKeyGen;
    private static CardReader cardReader;
    private static JSONObject licenceData;

    /**
     * Construtor da class LibrarySI.
     * Inicializa a biblioteca com um nome de aplicação e versão padrão.
     */
    public LibrarySI(){
        init("SIDavidJoao", "1.0.0");
    }

    /**
     * Inicializa a biblioteca com o nome e a versão da aplicação especificados.
     *
     * @param appName    O nome da aplicação.
     * @param appVersion A versão da aplicação.
     */
    private void init(String appName, String appVersion) {
        LibrarySI.appName = appName;
        LibrarySI.appVersion = appVersion;
        libKeyGen = new LibKeyGen();
        cardReader= new CardReader();
    }


    /**
     * Apresenta informações sobre a licença, incluindo detalhes do utilizador, informação do sistema e validade da licença.
     */
    public void showLicenseInfo() {
        String name = licenceData.getString("name");
        String email = licenceData.getString("email");
        String nic = licenceData.getString("nic");
        String certificate = licenceData.getString("certificate");
        String cpu = licenceData.getString("cpu");
        String cpuArch = licenceData.getString("cpuarch");
        String mbSerial = licenceData.getString("mbserial");
        String storage = licenceData.getString("storage");
        String appName = licenceData.getString("appname");
        String version = licenceData.getString("version");
        String startDate = licenceData.getString("startdate");
        String endDate = licenceData.getString("finaldate");

        LocalDate sDate = LocalDate.parse(startDate, DateTimeFormatter.ISO_DATE);
        LocalDate eDate = LocalDate.parse(endDate, DateTimeFormatter.ISO_DATE);

        long daysBetween = java.time.temporal.ChronoUnit.DAYS.between(sDate, eDate);


        System.out.println("\n\nLICENÇA");
        System.out.println("\nNome: " + name);
        System.out.println("Email: " + email);
        System.out.println("NIC: " + nic);
        System.out.println("Certificado: " + certificate);
        System.out.println("\nNº de CPUs: " + cpu);
        System.out.println("Arquitetura do CPU: " + cpuArch);
        System.out.println("Número de Série da MotherBoard: " + mbSerial);
        System.out.println("Disco: " + storage);
        System.out.println("\nNome da Aplicação: " + appName);
        System.out.println("Versão: " + version);
        System.out.println("Validade: " + endDate + "(" + daysBetween + " dias)");
    }


    /**
     * Verifica se a aplicação está registada, validando a assinatura e o conteúdo da licença.
     *
     * @return True se a aplicação estiver registada, falso caso contrário.
     */
    public Boolean isRegistered() {
        try {
            String zipFilePath = "license.zip";

            File file = new File(zipFilePath);
            if (!file.exists()){
                System.out.println ("\n\nA aplicação não se encontra registada.");
                return false;
            }

            if (verifySignatureInZip(zipFilePath)) {
                String decryptedContent = decryptLicense(zipFilePath, libKeyGen);
                if (verifyLicenceContent(new JSONObject(decryptedContent))) {
                    licenceData = new JSONObject(decryptedContent);
                    return true;
                }
                return false;
            }
        } catch (Exception e) {
            System.out.println("Erro durante validação de licença: " + e.getMessage());
        }
        return false;
    }

    private static boolean verifyLicenceContent(JSONObject decryptedContent) {
        String certificate = decryptedContent.getString("certificate");
        String cpu = decryptedContent.getString("cpu");
        String cpuArch = decryptedContent.getString("cpuarch");
        String mbSerial = decryptedContent.getString("mbserial");
        String storage = decryptedContent.getString("storage");
        String name = decryptedContent.getString("appname");
        String version = decryptedContent.getString("version");
        String endDate = decryptedContent.getString("finaldate");


        byte[] decodedBytes = Base64.getDecoder().decode(certificate);
        Certificate licenseCertificate = null;
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            licenseCertificate = certificateFactory.generateCertificate(new ByteArrayInputStream(decodedBytes));
        } catch (CertificateException e) {
            System.out.println("Erro com o certificado: " + e);
        }
        String[] actualSystemInfo = getSystemIdentifier();

        Certificate actualCertificate = cardReader.certificate;
        String actualCpu = actualSystemInfo[0];
        String actualCpuArch = actualSystemInfo[1];
        String actualMbSerial = actualSystemInfo[2];
        String actualStorage = actualSystemInfo[3];
        String actualAppName = appName;
        String actualVersion = appVersion;
        String actualEndDate = LocalDate.now().format(DateTimeFormatter.ISO_DATE);


        if (actualCertificate.equals(licenseCertificate) &&
                actualCpu.equals(cpu) &&
                actualCpuArch.equals(cpuArch) &&
                actualMbSerial.equals(mbSerial) &&
                actualStorage.equals(storage) &&
                actualAppName.equals(name) &&
                actualVersion.equals(version) &&
                LocalDate.parse(actualEndDate).isBefore(LocalDate.parse(endDate))) {
            return true;
        } else {
            if (!actualCertificate.equals(licenseCertificate)) {
                System.out.println("\nIncompatibilidade do Certificado");
            }
            if (!actualCpu.equals(cpu)) {
                System.out.println("\nIncompatibilidade da CPU");
            }
            if (!actualCpuArch.equals(cpuArch)) {
                System.out.println("\nIncompatibilidade da arquitetura da CPU");
            }
            if (!actualMbSerial.equals(mbSerial)) {
                System.out.println("\nIncompatibilidade do número de série da motherboard");
            }
            if (!actualStorage.equals(storage)) {
                System.out.println("\nIncompatibilidade do armazenamento");
            }
            if (!actualAppName.equals(name)) {
                System.out.println("\nIncompatibilidade do nome da aplicação");
            }
            if (!actualVersion.equals(version)) {
                System.out.println("\nIncompatibilidade da versão da aplicação");
            }
            if (!LocalDate.parse(actualEndDate).isBefore(LocalDate.parse(endDate))) {
                System.out.println("\nIncompatibilidade da data de expiração da licença");
            }
            return false;
        }
    }

    private static boolean verifySignatureInZip(String zipFilePath) {
        try {
            byte[] signatureBytes = readZipEntry(zipFilePath, "signature.pem");

            PublicKey publicKey = readPublicKey();

            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);

            byte[] licenseBytes = readZipEntry(zipFilePath, "license.json");

            assert licenseBytes != null;
            signature.update(licenseBytes);
            return signature.verify(signatureBytes);
        } catch (Exception e) {
            System.out.println("Erro durante validação da assinatura: " + e.getMessage());
        }
        return false;
    }

    private static String decryptLicense(String zipFilePath, LibKeyGen libKeyGen) {
        try {
            PrivateKey privateKey = libKeyGen.getPrivateKey();
            byte[] encryptedLicenseBytes = readZipEntry(zipFilePath, "license.json");

            String encryptedContent = new String(encryptedLicenseBytes);

            String[] parts = encryptedContent.split("::");
            String encryptedSymmetricKey = parts[0];
            String encryptedData = parts[1];

            byte[] decryptedSymmetricKey = decryptRSA(Base64.getDecoder().decode(encryptedSymmetricKey), privateKey);

            Cipher aesCipher = Cipher.getInstance("AES");
            SecretKey secretKey = new SecretKeySpec(decryptedSymmetricKey, "AES");
            aesCipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decryptedData = aesCipher.doFinal(Base64.getDecoder().decode(encryptedData));

            return new String(decryptedData, StandardCharsets.UTF_8);

        } catch (Exception e) {
            System.out.println("Erro ao decifrar licença: " + e.getMessage());
        }
        return null;
    }

    private static byte[] decryptRSA(byte[] encryptedData, PrivateKey privateKey) throws Exception {
        javax.crypto.Cipher rsaCipher = javax.crypto.Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(javax.crypto.Cipher.DECRYPT_MODE, privateKey);
        return rsaCipher.doFinal(encryptedData);
    }

    private static byte[] readZipEntry(String zipFilePath, String entryName) {
        try (ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFilePath))) {
            ZipEntry zipEntry = zis.getNextEntry();
            while (zipEntry != null) {
                if (zipEntry.getName().equals(entryName)) {
                    ByteArrayOutputStream bos = new ByteArrayOutputStream();
                    byte[] buffer = new byte[1024];
                    int bytesRead;
                    while ((bytesRead = zis.read(buffer)) != -1) {
                        bos.write(buffer, 0, bytesRead);
                    }
                    return bos.toByteArray();
                }
                zis.closeEntry();
                zipEntry = zis.getNextEntry();
            }
        } catch (IOException e) {
            System.out.println("Erro ao ler zip entry: " + e.getMessage());
        }
        return null;
    }


    /**
     * Inicia o processo de registo para obter uma licença.
     * Recolhe informações do utilizador, gera um pedido de registo e guarda-o num ficheiro zip.
     */
    public void startRegistration() {
        System.out.println("\nPedido de Registo de Licença!\n");

        String nome;
        String email;
        String numeroCivil;

        try {
            do {
                System.out.print("Nome: ");
                nome = scanner.nextLine();
            } while (!nome.matches("[a-zA-Z]+"));

            do {
                System.out.print("Email: ");
                email = scanner.nextLine();
            } while (!email.matches("^[_A-Za-z0-9-]+(\\.[_A-Za-z0-9-]+)*@[A-Za-z0-9]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$"));

            do {
                System.out.print("Número de identificação civil: ");
                numeroCivil = scanner.nextLine();
            } while (!numeroCivil.matches("\\d{8}"));

            System.out.print("\nA gerar pedido de registo...");

            RSAPublicKey publicKey = readPublicKey();

            JSONObject userInfo = new JSONObject();

            userInfo.put("name", nome);
            userInfo.put("email", email);
            userInfo.put("nic", numeroCivil);

            Certificate userCertificate = cardReader.readCertificate();
            String encodedCertificate = Base64.getEncoder().encodeToString(userCertificate.getEncoded());
            userInfo.put("certificate", encodedCertificate);

            String[] systemInfo = getSystemIdentifier();
            assert systemInfo != null;
            userInfo.put("cpu", systemInfo[0]);
            userInfo.put("cpuarch", systemInfo[1]);
            userInfo.put("mbserial", systemInfo[2]);
            userInfo.put("storage", systemInfo[3]);
            userInfo.put("appname", appName);
            userInfo.put("version", appVersion);
            String jsonString = userInfo.toString();

            String encryptedContent = encryptContent(jsonString, publicKey);
            String encryptedFile = "pedido_registo.json";
            saveToFile(Objects.requireNonNull(encryptedContent), encryptedFile);

            PrivateKey privateKey = cardReader.getCCPrivateKey();
            signFile(encryptedFile, privateKey, cardReader.prov);

            savePublicKeyToFile(cardReader.getCCPublicKey());

            try (ZipOutputStream zipOut = new ZipOutputStream(new FileOutputStream("pedido_registo.zip"))) {
                addFileToZip(encryptedFile, zipOut, "pedido_registo.json");
                addFileToZip("pk_user.pem", zipOut, "pk_user.pem");
                addFileToZip("signature.pem", zipOut, "signature.pem");
                addFileToZip("libPubKey.pem", zipOut, "libPubKey.pem");

                deleteFile(encryptedFile);
                deleteFile("pk_user.pem");
                deleteFile("signature.pem");
            } catch (IOException e) {
                System.out.println("Erro ao adicionar ficheiro ao zip: " + e.getMessage());
            }

            System.out.println("\n\nPedido de Registo Completo! ");

        } catch (Exception e) {
            System.out.println("Erro durante o registo: " + e.getMessage());
        }
    }

    private static RSAPublicKey readPublicKey() throws Exception {
        try (FileReader fileReader = new FileReader("autorPubKey.pem");
             PEMParser pemParser = new PEMParser(fileReader)) {

            Object object = pemParser.readObject();

            if (object instanceof SubjectPublicKeyInfo) {
                return (RSAPublicKey) new JcaPEMKeyConverter().getPublicKey((SubjectPublicKeyInfo) object);
            }
        }
        return null;
    }

    private static String encryptContent(String content, RSAPublicKey publicKey) {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            SecretKey secretKey = keyGen.generateKey();

            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedContent = cipher.doFinal(content.getBytes(StandardCharsets.UTF_8));

            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedSymmetricKey = rsaCipher.doFinal(secretKey.getEncoded());

            String result = Base64.getEncoder().encodeToString(encryptedSymmetricKey) + "::" +
                    Base64.getEncoder().encodeToString(encryptedContent);
            return result;
        } catch (Exception e) {
            System.out.println("Erro ao cifrar conteúdo: " + e.getMessage());
            return null;
        }
    }

    private static void saveToFile(String content, String filePath) {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(content.getBytes());
        } catch (IOException e) {
            System.out.println("Erro ao escrever para o ficheiro: " + e.getMessage());
        }
    }

    private static void savePublicKeyToFile(PublicKey publicKey) {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("pk_user.pem"))) {
            oos.writeObject(publicKey);
        } catch (IOException e) {
            System.out.println("Erro ao salvar chave pública: " + e.getMessage());
        }
    }

    private static void addFileToZip(String filePath, ZipOutputStream zipOut, String zipEntryName) throws IOException {
        try (FileInputStream fis = new FileInputStream(filePath)) {
            ZipEntry zipEntry = new ZipEntry(zipEntryName);
            zipOut.putNextEntry(zipEntry);
            byte[] bytes = new byte[1024];
            int length;
            while ((length = fis.read(bytes)) >= 0) {
                zipOut.write(bytes, 0, length);
            }
        }
    }

    private static void deleteFile(String filePath){
        try {
            File file = new File(filePath);
            file.delete();
        } catch (SecurityException e) {
            System.out.println("Erro de segurança ao excluir o ficheiro: " + e.getMessage());
        }
    }

    private static String[] getSystemIdentifier() {
        try {
            int numProcessors = Runtime.getRuntime().availableProcessors();
            String cpuArch = System.getProperty("os.arch");

            Process process = new ProcessBuilder().command("cmd", "/c", "wmic baseboard get serialnumber").start();
            List<String> outputLines = new BufferedReader(new InputStreamReader(process.getInputStream())).lines().toList();
            String mbSerial = outputLines.get(2).trim();

            process = new ProcessBuilder().command("cmd", "/c", "wmic diskdrive get model").start();
            outputLines = new BufferedReader(new InputStreamReader(process.getInputStream())).lines().toList();
            String storageSerial = outputLines.get(4).trim();

            return new String[]{String.valueOf(numProcessors), cpuArch, mbSerial, storageSerial};
        } catch (IOException e) {
            System.out.println("Ocorreu um erro ao obter informação do sistema: " + e.getMessage());
            return null;
        }
    }

    private static void signFile(String filePath, PrivateKey privateKey, Provider prov) {
        try (FileInputStream fis = new FileInputStream(filePath)) {
            Signature signature = Signature.getInstance("SHA256withRSA", prov);
            signature.initSign(privateKey);

            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                signature.update(buffer, 0, bytesRead);
            }

            byte[] signatureBytes = signature.sign();
            String signatureFilePath = "signature.pem";
            try (FileOutputStream fos = new FileOutputStream(signatureFilePath)) {
                fos.write(signatureBytes);
            } catch (IOException e) {
                System.out.println("Erro ao escrever assinatura para um ficheiro: " + e.getMessage());
            }
        } catch (Exception e) {
            System.out.println("Erro ao assinar o ficheiro: " + e.getMessage());
        }
    }

    /**
     * A classe CardReader representa um leitor de cartões, que é utilizada para interagir com o cartão de cidadão.
     * Inicializa o leitor de cartões e recupera as chaves pública e privada.
     */
    private static class CardReader {
        private final Provider prov;
        private PublicKey publicKey;
        private PrivateKey privateKey;
        private Certificate certificate;

        public CardReader() {
            System.out.print("A Ler Cartão de Cidadão...");
            this.prov = getProv();
            KeyStore keyStore = initializeKeyStore();
            retrieveKeys(keyStore);
        }

        private KeyStore initializeKeyStore() {
            try {
                KeyStore ks = KeyStore.getInstance("PKCS11", prov);
                ks.load(null, null);
                return ks;
            } catch (Exception e) {
                System.out.println("Erro ao iniciar SmartCard KeyStore: " + e.getMessage());
                return null;
            }
        }

        public static Provider getProv() {
            String configpath = "src/resource/pkcs11cc.cfg";
            System.out.println(configpath);

            Provider p = Security.getProvider("SunPKCS11");
            p = p.configure(configpath);
            if (Security.getProvider(p.getName()) == null) {
                Security.addProvider(p);
            }
            return p;
        }

        public PrivateKey getCCPrivateKey() {
            return privateKey;
        }

        public PublicKey getCCPublicKey() {
            return publicKey;
        }

        public Certificate readCertificate() {
            return certificate;
        }

        private void retrieveKeys(KeyStore ks) {
            String alias = "CITIZEN SIGNATURE CERTIFICATE";
            try {
                certificate = ks.getCertificate(alias);
                privateKey = (PrivateKey) ks.getKey(alias, null);
                publicKey = certificate.getPublicKey();
            }catch (Exception e){
                System.out.println("Erro ao obter par de chaves: " + e.getMessage());
            }
        }
    }


    /**
     * A classe LibKeyGen representa um gerador de um par de chaves RSA.
     * Inclui métodos para gerar, guardar e recuperar chaves de ficheiros utilizando uma password.
     */
    private static class LibKeyGen {

        private char[] storedPassword;

        static {
            Security.addProvider(new BouncyCastleProvider());
        }

        public LibKeyGen(){
            generateAndStorePassword();
        }

        private void generateAndStorePassword() {
            boolean correctPassword = false;

            while (!correctPassword) {
                try {
                    if (areFilesExist()) {
                        storedPassword = getPasswordFromUser();
                        getPrivateKey();
                    } else {
                        System.out.println("Primeiro Registo\n");
                        storedPassword = getPasswordFromUser();
                        KeyPair keyPair = generateKeyPair();
                        saveKeysToFile(keyPair, storedPassword);
                    }
                    correctPassword = true;
                } catch (Exception e) {
                    System.out.println("Password Incorreta. Tente Novamente.\n");
                }
            }
        }

        private boolean areFilesExist() {
            String publicKeyFilePath = "libPubKey.pem";
            String privateKeyFilePath = "libPrivKey.pem";
            return new File(privateKeyFilePath).exists() && new File(publicKeyFilePath).exists();
        }

        private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        }

        private void saveKeysToFile(KeyPair keyPair, char[] password) {
            try {
                savePrivateKeyToPemFile(keyPair.getPrivate(), password);
                savePublicKeyToFile(keyPair.getPublic());
            } catch (Exception e) {
                System.out.println("Erro ao guardar chaves em ficheiro: " + e.getMessage());
            }
        }

        private char[] getPasswordFromUser() {
            Scanner scanner = new Scanner(System.in);
            System.out.print("Digite a Password de Segurança: ");
            return scanner.nextLine().toCharArray();
        }

        private void savePrivateKeyToPemFile(PrivateKey privateKey, char[] password) throws Exception {
            JcePEMEncryptorBuilder encryptorBuilder = new JcePEMEncryptorBuilder("AES-256-CBC");
            encryptorBuilder.setSecureRandom(new SecureRandom());

            try (Writer writer = new FileWriter("libPrivKey.pem");
                 JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
                pemWriter.writeObject(privateKey, encryptorBuilder.build(password));
                pemWriter.flush();
            }
        }

        private void savePublicKeyToFile(PublicKey publicKey) throws Exception {
            try (Writer writer = new FileWriter("libPubKey.pem");
                 JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
                pemWriter.writeObject(publicKey);
                pemWriter.flush();
            }
        }

        private char[] getStoredPassword() {
            return storedPassword;
        }

        private PrivateKey getPrivateKey() throws Exception {
            KeyPair keyPair = decodePrivateKey();
            return keyPair.getPrivate();
        }

        private KeyPair decodePrivateKey() throws Exception {
            try (FileReader fileReader = new FileReader("libPrivKey.pem");
                 PEMParser pemParser = new PEMParser(fileReader)) {

                Object object = pemParser.readObject();

                if (object instanceof PEMEncryptedKeyPair encryptedKeyPair) {
                    PEMKeyPair pemKeyPair = encryptedKeyPair.decryptKeyPair(new JcePEMDecryptorProviderBuilder().build(getStoredPassword()));
                    return new JcaPEMKeyConverter().getKeyPair(pemKeyPair);
                }
            }
            return null;
        }
    }
}

