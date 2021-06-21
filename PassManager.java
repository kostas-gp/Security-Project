public class Main {

    //The Frame of the app
    private JFrame gui;

    //Name of Files
    private final File users_dir = new File("UserData");
    private final File authHashes_file = new File("authHashes.txt");
    private final String entries_foldername = "Entries";

    //Username and sKey 
    private String user;
    private Key sKey;

    //LoginFrame
    public Main () {
        gui = new LoginFrame(this, "Username", "Password");
        gui.setVisible(true);
    }

    //The register of the users
    public void register (String name, String surname, String username, char[] password, String email) {

        //Check if there is already a user
        if (usernameExists(username)) {
            JOptionPane.showMessageDialog(gui, "Username already exists.", "Fail", JOptionPane.WARNING_MESSAGE);
        } else {
            try {
                //Initially a pair of public and private RSA keys with size 2048 is created
                KeyPair keys = Keys.generateRSAKeyPair();
                RSAPrivateKey priv = (RSAPrivateKey) keys.getPrivate();
                RSAPublicKey pub = (RSAPublicKey) keys.getPublic();

                //Certification Request with the element of the user
                PKCS10CertificationRequest CSRequest = Certificates.generateRequest(
                        keys,
                        name,
                        surname,
                        username,
                        email,
                        Certificates.getCAcert(),
                        Certificates.getCAprivateKey());

                //Create a user file
                if (users_dir.exists() == false) {
                    users_dir.mkdir();
                }
                // file of the specific user
                File user_home = new File(users_dir.getPath() + "/" + username);
                user_home.mkdir();

                //The Certification Request is  verified by a VerifierProvider made for the programe with the public key
                ContentVerifierProvider CA_verifier = new JcaContentVerifierProviderBuilder().setProvider("BC").build(Certificates.getCAcert().getPublicKey());
                if (CSRequest.isSignatureValid(CA_verifier)) {
                    System.out.println("SHA1withRSA" + ": PKCS#10 request verified.");

                    //PassManager CA issues the user certificate based on the user data
                    X509Certificate cert = Certificates.getCertificate(CSRequest, Certificates.getCAcert(), Certificates.getCAprivateKey());

                    // Keys and certificate are written through the Bouncy Castle PemWriter class archived in his folder
                    PemFile.write("X.509 CERTIFICATE", cert.getEncoded(), user_home.getPath() + "/cert.crt");
                    PemFile.write("RSA PRIVATE KEY", priv.getEncoded(), user_home.getPath() + "/private.pem");
                    PemFile.write("RSA PUBLIC KEY", pub.getEncoded(), user_home.getPath() + "/public.pem");

                    //The creation of sKey and authHash for the user following the PBKDF2 standard (DK format = PBKDF2 (P, S, c, dkLen))
                    SecretKey sKey = Keys.generatePBKDF2Key(password, username.getBytes(), 2000, 16);
                    SecretKey authHash = Keys.generatePBKDF2Key(toChars(sKey.getEncoded()), toBytes(password), 1000, 16);

                    //AuthHash and AuthHashes of the user are writen to the folder
                    storeAuthHash(username, authHash.getEncoded());

                    // Display appropriate message
                    JOptionPane.showMessageDialog(gui, "Your registration completed successfully.\n"
                                                  + "Exported files paths:\n"
                                                  + "Certificate: " + user_home.getPath() + "\\cert.crt\n"
                                                  + "Private Key: " + user_home.getPath() + "\\private.pem\n"
                                                  + "Public Key: " + user_home.getPath() + "\\public.pem\n",
                                                  "Success", JOptionPane.INFORMATION_MESSAGE);
                } else {
                    System.out.println("SHA1withRSA" + ": Failed verify check.");
                    JOptionPane.showMessageDialog(gui, "Certification Request Failed Verification.", "Error", JOptionPane.ERROR_MESSAGE);
                }

            } catch (NoSuchAlgorithmException | NoSuchProviderException | OperatorCreationException | IOException | InvalidKeySpecException |
                     CertificateException | KeyStoreException | UnrecoverableKeyException | PKCSException ex) {
                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            } catch (Exception ex) {
                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    //The process of user authentication
    public void login (String username, char[] password) {
        try {

            //Create sKey and authHash for the user following the PBKDF2 standard (DK format = PBKDF2 (P, S, c, dkLen))
            SecretKey sKey = Keys.generatePBKDF2Key(password, username.getBytes(), 2000, 16);
            SecretKey authHash = Keys.generatePBKDF2Key(toChars(sKey.getEncoded()), toBytes(password), 1000, 16);

            //Comparison of the authHash bytes created with the data provided by the user
            if (Arrays.equals(getAuthHash(username), authHash.getEncoded())) {

                //Find the user folder
                File user_home = new File(users_dir.getPath() + "/" + username);

                //Uploading the user certificate and confirming its validity (date basis) and its authenticity, ie that it was issued by PassManager CA
                X509Certificate userCert = PemFile.loadCertificate(user_home.getPath() + "/cert.crt");

                userCert.checkValidity();
                userCert.verify(Certificates.getCAcert().getPublicKey());

                this.sKey = sKey;

                this.user = username;

                // close LoginFrame and open PMFrame
                gui.dispose();
                gui = new PMFrame(this);
                gui.setVisible(true);

            } else {
                JOptionPane.showMessageDialog(gui, "Invalid Credentials.", "Fail", JOptionPane.ERROR_MESSAGE);
            }

        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException | IOException | KeyStoreException |
                 UnrecoverableKeyException | InvalidKeyException | SignatureException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {

            JOptionPane.showMessageDialog(gui, "Invalid Certificate", "Fail", JOptionPane.ERROR_MESSAGE);
        }
    }