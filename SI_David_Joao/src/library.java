import org.json.JSONObject;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class library {
    private static final Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) {
        try {
            startRegistration("ProteçãoSI", "1.0.0");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Método principal para iniciar o registo
    public static void startRegistration(String nomeAPP, String versaoAPP) {
        System.out.println("Pedido de Registo de Licença!\n");

        String nome;
        String email;
        String numeroCivil;

        try {
            // Obter e validar o nome
            do {
                System.out.print("Nome: ");
                nome = scanner.nextLine();
            } while (!nome.matches("[a-zA-Z]+"));

            // Obter e validar o email
            do {
                System.out.print("Email: ");
                email = scanner.nextLine();
            } while (!email.matches("^[_A-Za-z0-9-]+(\\.[_A-Za-z0-9-]+)*@[A-Za-z0-9]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$"));

            // Obter e validar o número de identificação civil
            do {
                System.out.print("Número de identificação civil: ");
                numeroCivil = scanner.nextLine();
            } while (!numeroCivil.matches("\\d{8}"));

            System.out.print("\nA gerar pedido de registo...");

            // Ler a chave pública do ficheiro
            String publicKeyFilePath = "pubk_autor.pem";
            RSAPublicKey publicKey = readPublicKey(publicKeyFilePath);

            CardReader cardReader = new CardReader();

            JSONObject userInfo = new JSONObject();

            // Preencher informações do utilizador
            userInfo.put("name", nome);
            userInfo.put("email", email);
            userInfo.put("nic", numeroCivil);

            // Ler o certificado do cartão do cidadão
            Certificate userCertificate = cardReader.readCertificate();
            String encodedCertificate = Base64.getEncoder().encodeToString(userCertificate.getEncoded());
            String truncatedCertificate = encodedCertificate.substring(0, Math.min(encodedCertificate.length(), 50));
            userInfo.put("certificate", truncatedCertificate);

            // Obter informações do sistema
            String[] systemInfo = getSystemIdentifier();
            assert systemInfo != null;
            userInfo.put("cpu", systemInfo[0]);
            userInfo.put("cpuarch", systemInfo[1]);
            userInfo.put("mbserial", systemInfo[2]);
            userInfo.put("storage", systemInfo[3]);
            userInfo.put("appname", nomeAPP);
            userInfo.put("version", versaoAPP);
            String jsonString = userInfo.toString();

            // Cifrar conteúdo
            String encryptedContent = encryptContent(jsonString, publicKey);
            String encryptedFile = "pedido_registo.json";
            saveToFile(Objects.requireNonNull(encryptedContent), encryptedFile);

            // Assinar o ficheiro
            PrivateKey privateKey = cardReader.getPrivateKey();
            signFile(encryptedFile, privateKey, cardReader.prov);



            // Salvar a chave pública do utilizador num ficheiro
            savePublicKeyToFile(cardReader.getPublicKey());

            // Criar um arquivo zip com os ficheiros criados
            try (ZipOutputStream zipOut = new ZipOutputStream(new FileOutputStream("pedido_registo.zip"))) {
                addFileToZip(encryptedFile, zipOut, "pedido_registo.json");
                addFileToZip("pk_user.pem", zipOut, "pk_user.pem");
                addFileToZip("signature.pem", zipOut, "signature.pem");
            } catch (IOException e) {
                System.out.println("Erro ao adicionar ficheiro ao zip: " + e.getMessage());
            }

            System.out.println("\n\nPedido de Registo Completo! ");

        } catch (Exception e) {
            System.out.println("Erro durante o registo: " + e.getMessage());
        }
    }

    // Método para ler a chave pública do autor do ficheiro
    private static RSAPublicKey readPublicKey(String filePath) {
        try {
            byte[] publicKeyBytes = Files.readAllBytes(Paths.get(filePath));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            System.out.println("Sucesso ao Ler chave publica!");
            return (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
        } catch (Exception e) {
            System.out.println("Erro a ler chave pública: " + e.getMessage());
            return null;
        }
    }

    // Método para cifrar o conteúdo usando criptografia assimétrica e simétrica
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

    // Método para salvar conteúdo num ficheiro
    private static void saveToFile(String content, String filePath) {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(content.getBytes());
            System.out.println("Sucesso ao escrever em: " + filePath);
        } catch (IOException e) {
            System.out.println("Erro ao escrever para o ficheiro: " + e.getMessage());
        }
    }

    // Método para salvar chave pública do utilizador num ficheiro
    private static void savePublicKeyToFile(PublicKey publicKey) {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("pk_user.pem"))) {
            oos.writeObject(publicKey);
            System.out.println("Sucesso ao escrever chave pública em: " + "pk_user.pem");
        } catch (IOException e) {
            System.out.println("Erro ao salvar chave pública: " + e.getMessage());
        }
    }

    // Método para adicionar um ficheiro a um zip
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
        // Eliminar o ficheiro após adicionar ao zip
        try {
            File file = new File(filePath);
            if (file.delete()) {
                System.out.println("Ficheiro excluído com sucesso: " + filePath);
            } else {
                System.out.println("Erro ao excluir o ficheiro: " + filePath);
            }
        } catch (SecurityException e) {
            System.out.println("Erro de segurança ao excluir o ficheiro: " + e.getMessage());
        }
    }

    // Método para obter informações do sistema
    public static String[] getSystemIdentifier() {
        try {
            // Informações sobre a CPU
            int numProcessors = Runtime.getRuntime().availableProcessors();
            String cpuArch = System.getProperty("os.arch");

            // Informações sobre a Motherboard
            Process process = new ProcessBuilder().command("cmd", "/c", "wmic baseboard get serialnumber").start();
            List<String> outputLines = new BufferedReader(new InputStreamReader(process.getInputStream())).lines().toList();
            String mbSerial = outputLines.get(2).trim();

            // Informações sobre o armazenamento
            process = new ProcessBuilder().command("cmd", "/c", "wmic diskdrive get model").start();
            outputLines = new BufferedReader(new InputStreamReader(process.getInputStream())).lines().toList();
            String storageSerial = outputLines.get(4).trim();

            // Combinar informações
            return new String[]{String.valueOf(numProcessors), cpuArch, mbSerial, storageSerial};
        } catch (IOException e) {
            System.out.println("Ocorreu um erro ao obter informação do sistema: " + e.getMessage());
            return null;
        }
    }

    // Método para assinar um ficheiro
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
                System.out.println("Signature saved successfully to: " + signatureFilePath);
            } catch (IOException e) {
                System.out.println("Error writing signature to the file: " + e.getMessage());
            }


            System.out.println("Sucesso ao assinar: " + filePath);
        } catch (Exception e) {
            System.out.println("Erro ao assinar o ficheiro: " + e.getMessage());
        }
    }

    // Classe interna para lidar com o leitor de cartões
    public static class CardReader {
        private final KeyStore keyStore;
        private final Provider prov;

        public CardReader() {
            this.prov = getProv();
            this.keyStore = initializeKeyStore();
        }

        // Inicializar o KeyStore do Cartão de Cidadão
        private KeyStore initializeKeyStore() {
            try {
                KeyStore ks = KeyStore.getInstance("PKCS11", prov);
                ks.load(null, null);
                return ks;
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException("Erro ao inicializar KeyStore do Cartão de Cidadão.", e);
            }
        }

        // Obter o provider de segurança
        public static Provider getProv() {
            String configName = "src/resources/pkcs11cc.cfg";
            Provider p = Security.getProvider("SunPKCS11");
            p = p.configure(configName);
            if (Security.getProvider(p.getName()) == null) {
                Security.addProvider(p);
            }
            return p;
        }

        // Obter a chave privada do cartão
        public PrivateKey getPrivateKey() {
            try {
                String alias = getAliasFromKeyStore(keyStore);
                Key key = keyStore.getKey(alias, null);
                if (key instanceof PrivateKey) {
                    return (PrivateKey) key;
                } else {
                    throw new InvalidKeyException("A chave privada não é do tipo desejado.");
                }
            } catch (Exception e) {
                throw new RuntimeException("Erro ao obter a chave privada.", e);
            }
        }

        // Obter a chave pública do cartão
        public PublicKey getPublicKey() {
            try {
                String alias = getAliasFromKeyStore(keyStore);
                Certificate cert = keyStore.getCertificate(alias);
                return cert.getPublicKey();
            } catch (Exception e) {
                throw new RuntimeException("Erro ao obter a chave pública.", e);
            }
        }

        // Ler o certificado do cartão
        public Certificate readCertificate() {
            try {
                String alias = getAliasFromKeyStore(keyStore);
                return keyStore.getCertificate(alias);
            } catch (Exception e) {
                throw new RuntimeException("Erro ao ler o certificado.", e);
            }
        }

        // Obter o alias apropriado do KeyStore
        private String getAliasFromKeyStore(KeyStore keyStore) {
            try {
                Enumeration<String> aliases = keyStore.aliases();
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    if (keyStore.isKeyEntry(alias)) {
                        return alias;
                    }
                }
                throw new KeyStoreException("Nenhuma chave privada encontrada no KeyStore.");
            } catch (Exception e) {
                throw new RuntimeException("Erro ao obter o alias do KeyStore.", e);
            }
        }
    }
}

