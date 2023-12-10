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
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;


/**
 * A classe Autor representa a geração de licenças para um software.
 * Utiliza criptografia assimétrica e simétrica e assinaturas digitais.
 * Esta classe inclui métodos para gerar e assinar licenças com base em pedidos de registo.
 *
 * @author David e João
 */
public class Autor {

    private static final Scanner scanner = new Scanner(System.in);


    /**
     * Método principal para a geração de licenças.
     *
     * @param args Argumentos da linha de comando (não utilizados).
     */
    public static void main(String[] args) {
        AutorKeyGen akg = new AutorKeyGen();
        System.out.println("Atribuição de Licença!");
        while (true) {
            System.out.print("\nInserir Pedido de Licença(Enter para terminar): ");
            String choice = scanner.nextLine().trim();

            if (choice.isEmpty()) {
                System.out.println("\nPrograma Terminado!");
                break;
            } else if (!choice.equals("pedido_registo.zip")) {
                System.out.println("Arquivo inválido. Tente novamente.");
            } else {
                if (!fileExists(choice)) {
                    System.out.println("O arquivo '" + choice + "' não existe. Tente novamente.");
                    continue;
                }
                if (verifySignature()) {
                    displayInfo(Objects.requireNonNull(readJsonContent(akg)));
                    String date = getLicenseDate();
                    genLicense(date, akg);
                } else {
                    System.out.println("Assinatura inválida!");
                    break;
                }
            }
        }
    }
    private static boolean fileExists(String filePath) {
        File file = new File(filePath);
        return file.exists() && file.isFile();
    }
    private static void genLicense(String date, AutorKeyGen akg) {
        try {
            JSONObject userInfo = readJsonContent(akg);

            userInfo.put("finaldate", date);

            LocalDate currentDate = LocalDate.now();
            System.out.println(currentDate);
            userInfo.put("startdate", currentDate);

            String jsonString = userInfo.toString();

            RSAPublicKey libPublicKey = (RSAPublicKey) readLibPublicKey();

            String encryptedContent = encryptContent(jsonString, libPublicKey);

            String licenseFilePath = "license.json";
            saveToFile(encryptedContent, licenseFilePath);

            PrivateKey autorPrivateKey = akg.getPrivateKey();
            signFile(licenseFilePath, autorPrivateKey);

            try (ZipOutputStream zipOut = new ZipOutputStream(new FileOutputStream("license.zip"))) {
                addFileToZip(licenseFilePath, zipOut, "license.json");
                addFileToZip("signature.pem", zipOut, "signature.pem");
                deleteFile("pedido_registo.zip");
                deleteFile("license.json");
                deleteFile("signature.pem");
            } catch (IOException e) {
                System.out.println("Erro ao adicionar ficheiro ao zip: " + e.getMessage());
            }

            System.out.println("\nLicença gerada com sucesso e assinada!");
        } catch (Exception e) {
            System.out.println("Erro ao gerar a licença: " + e.getMessage());
        }
    }
    private static void saveToFile(String content, String filePath) {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(content.getBytes());
        } catch (IOException e) {
            System.out.println("Erro ao escrever para o ficheiro: " + e.getMessage());
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

    private static void signFile(String filePath, PrivateKey privateKey) {
        try (FileInputStream fis = new FileInputStream(filePath)) {

            Signature signature = Signature.getInstance("SHA256withRSA");
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
                System.out.println("Erro ao passar assinatura para ficheiro: " + e.getMessage());
            }
        } catch (Exception e) {
            System.out.println("Erro ao assinar o ficheiro: " + e.getMessage());
        }
    }

    private static void deleteFile(String filePath) {
        File fileToDelete = new File(filePath);

        if (fileToDelete.exists()) {
            fileToDelete.delete();
        } else {
            System.out.println("Ficheiro não existe: " + filePath);
        }
    }

    private static JSONObject readJsonContent(AutorKeyGen akg) {
        try {
            String zipFilePath = "pedido_registo.zip";
            String jsonFileName = "pedido_registo.json";

            byte[] encryptedContent = readZipEntry(zipFilePath, jsonFileName);
            String decryptedContent = decryptContent(new String(encryptedContent), akg);
            return new JSONObject(decryptedContent);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static PublicKey readUserPublicKey() {
        try {
            String zipFilePath = "pedido_registo.zip";
            String publicKeyFileName = "pk_user.pem";

            try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(readZipEntry(zipFilePath, publicKeyFileName)))) {
                Object obj = ois.readObject();
                if (obj instanceof PublicKey) {
                    return (PublicKey) obj;
                } else {
                    return null;
                }
            }
        } catch (Exception e) {
            System.out.println("Erro ao ler chave publica: " + e.getMessage());
        }

        return null;
    }
    private static PublicKey readLibPublicKey() {
        try {
            String zipFilePath = "pedido_registo.zip";
            String publicKeyFileName = "libPubKey.pem";

            try (InputStream inputStream = new ByteArrayInputStream(readZipEntry(zipFilePath, publicKeyFileName));
                 Reader reader = new InputStreamReader(inputStream);
                 PEMParser pemParser = new PEMParser(reader)) {

                Object obj = pemParser.readObject();

                if (obj instanceof SubjectPublicKeyInfo) {
                    JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
                    return converter.getPublicKey((SubjectPublicKeyInfo) obj);
                } else {
                    return null;
                }
            }
        } catch (Exception e) {
            System.out.println("Erro ao ler chave publica: " + e.getMessage());
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

            return Base64.getEncoder().encodeToString(encryptedSymmetricKey) + "::" +
                    Base64.getEncoder().encodeToString(encryptedContent);
        } catch (Exception e) {
            System.out.println("Erro ao cifrar conteúdo: " + e.getMessage());
            return null;
        }
    }

    private static String decryptContent(String encryptedContent, AutorKeyGen akg) {
        try {
            RSAPrivateKey privateKey = (RSAPrivateKey) akg.getPrivateKey();

            String[] parts = encryptedContent.split("::");
            String encryptedSymmetricKey = parts[0];
            String encryptedData = parts[1];

            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedSymmetricKey = rsaCipher.doFinal(Base64.getDecoder().decode(encryptedSymmetricKey));

            Cipher aesCipher = Cipher.getInstance("AES");
            SecretKey secretKey = new SecretKeySpec(decryptedSymmetricKey, "AES");
            aesCipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decryptedData = aesCipher.doFinal(Base64.getDecoder().decode(encryptedData));

            return new String(decryptedData, StandardCharsets.UTF_8);
        } catch (Exception e) {
            System.out.println("Erro ao decifrar conteúdo: " + e.getMessage());
            return null;
        }
    }

    private static byte[] readZipEntry(String zipFilePath, String entryName) throws IOException {
        try (ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFilePath))) {
            ZipEntry zipEntry;
            while ((zipEntry = zis.getNextEntry()) != null) {
                if (zipEntry.getName().equals(entryName)) {
                    int size = (int) zipEntry.getSize();
                    if (size == -1) {
                        ByteArrayOutputStream bos = new ByteArrayOutputStream();
                        byte[] buffer = new byte[4096];
                        int bytesRead;
                        while ((bytesRead = zis.read(buffer)) != -1) {
                            bos.write(buffer, 0, bytesRead);
                        }
                        return bos.toByteArray();
                    } else {
                        byte[] entryBytes = new byte[size];
                        zis.read(entryBytes);
                        return entryBytes;
                    }
                }
                zis.closeEntry();
            }
            System.out.println("Erro: Entry '" + entryName + "' não encontrada no ficheiro zip.");
            return null;
        }
    }

    private static boolean verifySignature() {
        try {
            String zipFilePath = "pedido_registo.zip";
            String signatureFileName = "signature.pem";
            String jsonFileName = "pedido_registo.json";

            byte[] signatureBytes = readZipEntry(zipFilePath, signatureFileName);
            byte[] pedidoBytes = readZipEntry(zipFilePath, jsonFileName);

            if (signatureBytes == null || pedidoBytes == null) {
                return false;
            }
            PublicKey publicKey = readUserPublicKey();
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);
            signature.update(pedidoBytes);

            return signature.verify(signatureBytes);
        } catch (Exception e) {
            System.out.println("Erro ao verificar assinatura: " + e.getMessage());
        }
        return false;
    }
    private static String getLicenseDate(){
        try {
            DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd");

            while (true) {
                System.out.print("\nInsira Data de Conclusão da Licença (yyyy-MM-dd): ");
                String inputDate = scanner.nextLine();

                try {
                    LocalDate endDate = LocalDate.parse(inputDate, DATE_FORMATTER);
                    LocalDate currentDate = LocalDate.now();

                    if (endDate.isBefore(currentDate)) {
                        System.out.print("Data de conclusão inválida. A data deve ser futura.\n");
                    } else {
                        System.out.println("Data de conclusão validada!\n");
                        return inputDate;
                    }
                } catch (DateTimeParseException e) {
                    System.out.print("Formato de data inválido. Utilize o formato yyyy-MM-dd.\n");
                }
            }
        } catch (Exception e) {
            System.out.println("Ocorreu um erro ao analisar a data: " + e.getMessage());
        }
        return null;
    }

    private static void displayInfo(JSONObject jsonObject) {
        String name = jsonObject.getString("name");
        String email = jsonObject.getString("email");
        String nic = jsonObject.getString("nic");
        String certificate = jsonObject.getString("certificate");
        String cpu = jsonObject.getString("cpu");
        String cpuArch = jsonObject.getString("cpuarch");
        String mbSerial = jsonObject.getString("mbserial");
        String storage = jsonObject.getString("storage");
        String appName = jsonObject.getString("appname");
        String version = jsonObject.getString("version");

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
    }


    /**
     * A classe LibKeyGen representa um gerador de um par de chaves RSA.
     * Inclui métodos para gerar, guardar e recuperar chaves de ficheiros utilizando uma password.
     */
    public static class AutorKeyGen {

        private char[] storedPassword;

        static {
            Security.addProvider(new BouncyCastleProvider());
        }

        public AutorKeyGen() {
            generateAndStorePassword();
        }

        private void generateAndStorePassword() {
            boolean correctPassword = false;

            while (!correctPassword) {
                try {
                    if (areFilesExist()) {
                        storedPassword = getPasswordFromUser();
                        getPrivateKey();
                        correctPassword = true;
                    } else {
                        System.out.println("Primeiro Registo\n");
                        storedPassword = getPasswordFromUser();
                        KeyPair keyPair = generateKeyPair();
                        saveKeysToFile(keyPair, storedPassword);
                        correctPassword = true;
                    }
                } catch (Exception e) {
                    System.out.println("Password Incorreta. Tente Novamente.\n");
                }
            }
        }

        private boolean areFilesExist() {
            String privateKeyFilePath = "autorPrivKey.pem";
            return new File(privateKeyFilePath).exists();
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
                e.printStackTrace();
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

            try (Writer writer = new FileWriter("autorPrivKey.pem");
                 JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
                pemWriter.writeObject(privateKey, encryptorBuilder.build(password));
                pemWriter.flush();
            }
        }

        private void savePublicKeyToFile(PublicKey publicKey) throws Exception {
            try (Writer writer = new FileWriter("autorPubKey.pem");
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
            try (FileReader fileReader = new FileReader("autorPrivKey.pem");
                 PEMParser pemParser = new PEMParser(fileReader)) {

                Object object = pemParser.readObject();

                if (object instanceof PEMEncryptedKeyPair encryptedKeyPair) {
                    PEMKeyPair pemKeyPair = encryptedKeyPair.decryptKeyPair(new JcePEMDecryptorProviderBuilder().build(getStoredPassword()));
                    return new JcaPEMKeyConverter().getKeyPair(pemKeyPair);
                } else if (object instanceof PEMKeyPair) {
                    PEMKeyPair pemKeyPair = (PEMKeyPair) object;
                    return new JcaPEMKeyConverter().getKeyPair(pemKeyPair);
                } else {
                    throw new IllegalArgumentException("Objeto Inválido: " + object.getClass());
                }
            }
        }
    }
}
