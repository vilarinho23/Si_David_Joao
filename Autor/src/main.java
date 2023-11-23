import org.json.JSONObject;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Base64;
import java.util.Scanner;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

public class main {

    private static final Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) {

        System.out.println("Atribuição de Licença!");
        while (true) {
            System.out.print("\nInserir Pedido de Licença(Enter para terminar): ");
            String choice = scanner.nextLine();

            if (choice.equals("")) {
                System.out.println("\nPrograma Terminado!");
                break;
            } else {
                unzip(choice);
                if (verifySignature()){
                    displayInfo(readJsonContent());
                    String date = getLicenseDate();

                    genLicense(date);
                }else {
                    System.out.println("Assinatura inválida!");
                    break;
                };
            }
        }
    }
    private static void genLicense(String date) {
        try {
            JSONObject userInfo = readJsonContent();

            userInfo.put("finaldate", date);

            LocalDate currentDate = LocalDate.now();
            System.out.println(currentDate);
            userInfo.put("startdate", currentDate);

            String jsonString = userInfo.toString();

            RSAPublicKey userPublicKey = (RSAPublicKey) readPublicKey();

            String encryptedContent = encryptContent(jsonString, userPublicKey);

            String licenseFilePath = "license.json";
            saveToFile(encryptedContent, licenseFilePath);

            PrivateKey autorPrivateKey = readPrivateKey();
            signFile(licenseFilePath, autorPrivateKey);

            try (ZipOutputStream zipOut = new ZipOutputStream(new FileOutputStream("license.zip"))) {
                addFileToZip(licenseFilePath, zipOut, "license.json");
                addFileToZip("signature.pem", zipOut, "signature.pem");
                deleteFile("pedido_registo.json");
                deleteFile("license.json");
                deleteFile("signature.pem");
                deleteFile("pk_user.pem");
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
            System.out.println("Sucesso ao escrever em: " + filePath);
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
                System.out.println("Assinatura salva em: " + signatureFilePath);
            } catch (IOException e) {
                System.out.println("Erro ao passar assinatura para ficheiro: " + e.getMessage());
            }

            System.out.println("Sucesso ao assinar: " + filePath);
        } catch (Exception e) {
            System.out.println("Erro ao assinar o ficheiro: " + e.getMessage());
        }
    }

    private static void deleteFile(String filePath) {
        File fileToDelete = new File(filePath);

        if (fileToDelete.exists()) {
            if (fileToDelete.delete()) {
                System.out.println("Apagada com Sucesso: " + filePath);
            } else {
                System.err.println("Erro ao apagar: " + filePath);
            }
        } else {
            System.out.println("Ficheiro não existe: " + filePath);
        }
    }

    private static void unzip(String zipFilePath){
        try {
            byte[] buffer = new byte[1024];
            try (ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFilePath))) {
                ZipEntry zipEntry = zis.getNextEntry();
                while (zipEntry != null) {
                    String fileName = zipEntry.getName();
                    File newFile = new File(fileName);

                    try (FileOutputStream fos = new FileOutputStream(newFile)) {
                        int len;
                        while ((len = zis.read(buffer)) > 0) {
                            fos.write(buffer, 0, len);
                        }
                    }
                    zis.closeEntry();
                    zipEntry = zis.getNextEntry();
                }
            }
        }catch (IOException e) {
            throw new RuntimeException(e);
        }

        File zipFile = new File(zipFilePath);
        if (zipFile.exists()) {
            if (zipFile.delete()) {
                System.out.println("zip apagado com sucesso");
            } else {
                System.err.println("erro ao apagar zip");
            }
        }
    }

    private static JSONObject readJsonContent() {
        byte[] encryptedContent;
        try {
            encryptedContent = Files.readAllBytes(Paths.get("pedido_registo.json"));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        String decryptedContent = decryptContent(new String(encryptedContent));
        assert decryptedContent != null;
        return new JSONObject(decryptedContent);
    }

    private static PublicKey readPublicKey() {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream("pk_user.pem"))) {
            Object obj = ois.readObject();

            if (obj instanceof PublicKey) {
                return (PublicKey) obj;
            } else {
                return null;
            }
        } catch (Exception e) {
            System.out.println("Erro ao ler chave pública: " + e.getMessage());
            return null;
        }
    }

    private static RSAPrivateKey readPrivateKey() {
        try {
            byte[] privateKeyBytes = Files.readAllBytes(Path.of("privk_autor.pem"));
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            System.out.println("Erro ao ler chave privada: " + e.getMessage());
            return null;
        }
    }

    private static String encryptContent(String content, RSAPublicKey publicKey) {
        try {
            // Gerar uma chave simétrica
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            SecretKey secretKey = keyGen.generateKey();

            // Cifrar com chave simétrica
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedContent = cipher.doFinal(content.getBytes(StandardCharsets.UTF_8));

            // Cifrar chave simétrica com chave assimétrica
            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedSymmetricKey = rsaCipher.doFinal(secretKey.getEncoded());

            // Combinar ambas as partes
            String result = Base64.getEncoder().encodeToString(encryptedSymmetricKey) + "::" +
                    Base64.getEncoder().encodeToString(encryptedContent);
            System.out.println("Sucesso ao cifrar!");
            return result;
        } catch (Exception e) {
            System.out.println("Erro ao cifrar conteúdo: " + e.getMessage());
            return null;
        }
    }

    private static String decryptContent(String encryptedContent) {
        try {
            // Separar a chave simétrica cifrada do conteúdo cifrado
            RSAPrivateKey privateKey = readPrivateKey();

            String[] parts = encryptedContent.split("::");
            String encryptedSymmetricKey = parts[0];
            String encryptedData = parts[1];

            // Decifrar a chave simétrica com a chave privada
            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedSymmetricKey = rsaCipher.doFinal(Base64.getDecoder().decode(encryptedSymmetricKey));

            // Decifrar o conteúdo simétrico
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

    private static boolean verifySignature(){
        try {
            byte[] signatureBytes = Files.readAllBytes(Path.of("signature.pem"));

            PublicKey publicKey = readPublicKey();

            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);

            byte[] pedidoBytes = Files.readAllBytes(Path.of("pedido_registo.json"));

            signature.update(pedidoBytes);

            if (signature.verify(signatureBytes)) {
                return true;
            } else {
                return false;
            }
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
}
