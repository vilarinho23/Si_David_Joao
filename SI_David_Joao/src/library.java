import java.io.*;
import java.net.NetworkInterface;
import java.security.*;
import java.security.cert.Certificate;
import java.util.*;
import java.nio.file.Paths;
import org.json.JSONObject;

public class library {
    private static final Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) {
        try {
            startRegistration("ProteçãoSI", "1.0.0");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    public static void startRegistration(String nomeAPP, String versaoAPP) {
        System.out.println("Pedido de Registo de Licença!\n");

        String nome;
        String email;
        String numeroCivil;
        do {
            System.out.print("Nome: ");
            nome = scanner.nextLine();
        } while (!nome.matches("[a-zA-Z]+"));

        do {
            System.out.print("Email: ");
            email = scanner.nextLine();
        }while(!email.matches("^[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@[A-Za-z0-9]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$"));

        do {
            System.out.print("Número de identificação civil: ");
            numeroCivil = scanner.nextLine();
        }while (!numeroCivil.matches("\\d{8}"));

        System.out.println("A ler cartão...");

        try {
            CardReader cardReader = new CardReader();

            JSONObject userInfo = new JSONObject();
            userInfo.put("Nome", nome);
            userInfo.put("Email", email);
            userInfo.put("Número de Identificação Civil", numeroCivil);

            Certificate userCertificate = cardReader.readCertificate();
            userInfo.put("Certificate", Base64.getEncoder().encodeToString(userCertificate.getEncoded()));

            String systemInfo = getSystemIdentifier();
            userInfo.put("Informação do Sistema", systemInfo);

            userInfo.put("Nome da Aplicação", nomeAPP);
            userInfo.put("Versão", versaoAPP);

            String jsonString = userInfo.toString();
            String desktopPath = System.getProperty("user.home") + "/Desktop";
            String fileName = "pedido_registo.json";
            String jsonFilePath = Paths.get(desktopPath, fileName).toString();
            try (FileOutputStream fos = new FileOutputStream(jsonFilePath)) {
                fos.write(jsonString.getBytes());
            } catch (IOException e) {
                System.out.println("Ocorreu um erro durante o registo: " + e.getMessage());
            }

            PrivateKey privateKey = cardReader.getPrivateKey();
            signFile(jsonFilePath, privateKey, cardReader.prov);

            System.out.println("Pedido de Registo Completo! ");

        } catch (Exception e) {
            System.out.println("Ocorreu um erro durante o registo: " + e.getMessage());
        }
    }

    public static String getSystemIdentifier() {
        try {
            //CPU INFO
            int numProcessors = Runtime.getRuntime().availableProcessors();
            String cpuArch = System.getProperty("os.arch");

            //MAC INFO
            StringBuilder macAddresses = new StringBuilder();
            Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
            while (networkInterfaces.hasMoreElements()) {
                NetworkInterface networkInterface = networkInterfaces.nextElement();
                byte[] mac = networkInterface.getHardwareAddress();
                if (mac != null) {
                    macAddresses.append(Arrays.toString(mac));
                }
            }

            //Motherboard INFO
            Process process = new ProcessBuilder().command("cmd", "/c", "wmic baseboard get serialnumber").start();
            List<String> outputLines = new BufferedReader(new InputStreamReader(process.getInputStream())).lines().toList();
            String mbSerial = outputLines.get(2).trim();

            //Storage INFO
            process = new ProcessBuilder().command("cmd", "/c", "wmic diskdrive get model").start();
            outputLines = new BufferedReader(new InputStreamReader(process.getInputStream())).lines().toList();
            String StorageSerial = outputLines.get(4).trim();

            //Combinar INFO
            return numProcessors + "/" + cpuArch + "/" + mbSerial + "/" + StorageSerial + "/" + macAddresses;
        } catch (IOException e) {
            System.out.println("Ocorreu um erro ao obter informação do sistema: " + e.getMessage());
            return null;
        }
    }

    private static void signFile(String filePath, PrivateKey privateKey, Provider prov) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA", prov);
        signature.initSign(privateKey);

        try (FileInputStream fis = new FileInputStream(filePath)) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                signature.update(buffer, 0, bytesRead);
            }
        }
    }

    public static class CardReader {
        private final KeyStore keyStore;
        private final Provider prov;

        public CardReader() {
            this.prov = getProv();
            this.keyStore = initializeKeyStore();
        }

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
        public static Provider getProv() {
            String configName = "src/resources/pkcs11cc.cfg";
            Provider p = Security.getProvider("SunPKCS11");
            p = p.configure(configName);
            if (Security.getProvider(p.getName()) == null) {
                Security.addProvider(p);
            }
            return p;
        }

        public PrivateKey getPrivateKey() throws Exception {
            String alias = getAliasFromKeyStore(keyStore);
            Key key = keyStore.getKey(alias, null);

            if (key instanceof PrivateKey) {
                return (PrivateKey) key;
            } else {
                throw new InvalidKeyException("A chave privada não é do tipo desejado.");
            }
        }

        public Certificate readCertificate() throws Exception {
            String alias = getAliasFromKeyStore(keyStore);
            return keyStore.getCertificate(alias);
        }

        private String getAliasFromKeyStore(KeyStore keyStore) throws KeyStoreException {
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (keyStore.isKeyEntry(alias)) {
                    return alias;
                }
            }
            throw new KeyStoreException("Nenhuma chave privada encontrada no KeyStore.");
        }

    }


}
