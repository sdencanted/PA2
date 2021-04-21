import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.Socket;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Scanner;

import javax.crypto.Cipher;
import java.util.Arrays;

public class ClientCP1 {

	public static byte[] generateNonce() {
		SecureRandom secureRandom = new SecureRandom();
		StringBuilder stringBuilder = new StringBuilder();
		for (int i = 0; i < 15; i++) {
			stringBuilder.append(secureRandom.nextInt(10));
		}
		String randomNumber = stringBuilder.toString();
		return randomNumber.getBytes();
	}

	public static void main(String[] args) {

		String filename = null;

    	String serverAddress = "localhost";
    	if (args.length > 1) serverAddress = args[0];

    	int port = 4321;
    	if (args.length > 2) port = Integer.parseInt(args[1]);

		int numBytes = 0;
		byte[] encryptedNonce = null;
		String certFileName = null;

		Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;

    	FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;

		FileOutputStream fileOutputStream = null;
		BufferedOutputStream bufferedFileOutputStream = null;

		long timeStarted;

		try {

			System.out.println("Establishing connection to server...");

			// Connect to server and get the input and output streams
			clientSocket = new Socket(serverAddress, port);
			toServer = new DataOutputStream(clientSocket.getOutputStream());
			fromServer = new DataInputStream(clientSocket.getInputStream());

			// Send nonce
			System.out.println("Sending nonce...");
			toServer.writeInt(0);
			byte[] nonce = generateNonce();
			toServer.writeInt(nonce.length);
			toServer.write(nonce);
			System.out.println("Sent nonce:'" + new String(nonce, 0, nonce.length) + "'");
			// System.out.println(Arrays.toString(nonce));

			// wait for encrypted nonce
			while (true) {
				int packetType = fromServer.readInt();
				if (packetType == 0) {
					System.out.println("Receiving encrypted nonce...");
					numBytes = fromServer.readInt();
					encryptedNonce = new byte[numBytes];
					fromServer.readFully(encryptedNonce, 0, numBytes);
					break;
				}
			}

			// Send request for certificate
			System.out.println("Requesting for certificate...");
			System.out.println(fromServer.available());
			toServer.writeInt(1);

			// wait for certificate
			while (true) {

				// int packetType = fromServer.readInt();
				int packetType = fromServer.readInt();
				System.out.println(packetType);
				// Receiving certificate file name
				if (packetType == 1) {
					System.out.println("Receiving certificate file ...");
					numBytes = fromServer.readInt();
					byte[] certName = new byte[numBytes];
					fromServer.readFully(certName, 0, numBytes);

					certFileName = "recv_"+new String(certName, 0, numBytes);

					fileOutputStream = new FileOutputStream(certFileName);
					bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);
				}
				// Receiving certificate file chunk
				else if (packetType == 2) {

					numBytes = fromServer.readInt();

					byte [] block = new byte[numBytes];
					fromServer.readFully(block, 0, numBytes);
					System.out.println("numBytes");
					System.out.println(numBytes);

					if (numBytes > 0)
						bufferedFileOutputStream.write(block, 0, numBytes);

					if (numBytes < 117) {
						if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
						if (bufferedFileOutputStream != null) fileOutputStream.close();
						System.out.println("Certificate file received successfully");
						break;
					}
				}
			}

			// Verify identity
			System.out.println("Verifying identity...");

			InputStream fis = new FileInputStream("cacsertificate.crt");
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate CAcert =(X509Certificate)cf.generateCertificate(fis);
			PublicKey CAkey = CAcert.getPublicKey();

			InputStream fis2 = new FileInputStream(certFileName);
			X509Certificate serverCert =(X509Certificate)cf.generateCertificate(fis2);
			
			try {
                serverCert.checkValidity();
				serverCert.verify(CAkey);
                System.out.println("Certificate verification success!");
            } catch (Exception e) {
                System.out.println("Certificate verification fail!");
				return;
            }

			PublicKey serverPublicKey = serverCert.getPublicKey();

			// Decrypt and verify nonce
			System.out.println("Verifying nonce...");

			Cipher decCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            decCipher.init(Cipher.DECRYPT_MODE, serverPublicKey);

            byte[] decryptedNonce = decCipher.doFinal(encryptedNonce);
			
			if (new String(decryptedNonce).equals(new String(nonce))) {
                System.out.println("Authentication success!");
            }
			else {
                System.err.println("Authentification fail!");
                System.err.println(Arrays.toString(nonce));
                System.err.println(Arrays.toString(decryptedNonce));

                toServer.close();
                fromServer.close();
                clientSocket.close();
				return;
            }

			System.out.println("Ready to send file...");

			// Loop and wait for user to input file names
			while (true) {
				//file encoder
				Cipher encCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				encCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
				System.out.println("Enter file name to upload, or enter 'quit' to quit:");
				Scanner scanner = new Scanner(System.in);
				
				while (true) {
					if (scanner.hasNextLine()) {
                        filename = scanner.nextLine();
						break;
					}
				}

				// Quiting the session
				if (filename.equals("quit")) {
					System.out.println("Closing connection...");
					toServer.writeInt(3);
					toServer.close();
					fromServer.close();
					clientSocket.close();
					scanner.close();
					break;
				}
				
				try {
					timeStarted = System.nanoTime();
					// Open the file
					fileInputStream = new FileInputStream(filename);
					bufferedFileInputStream = new BufferedInputStream(fileInputStream);
					// toServer.writeInt(2);

					byte[] cipheredCmd = encCipher.doFinal("2".getBytes());
					System.out.println(cipheredCmd.length);
					// System.out.println("Pootis");
					toServer.write(cipheredCmd);

					// Send the filename
					cipheredCmd = encCipher.doFinal("0".getBytes());
					// System.out.println(cipheredCmd.length);
					toServer.write(cipheredCmd);
					
					cipheredCmd = encCipher.doFinal(String.valueOf(filename.getBytes().length).getBytes());
					// toServer.writeInt(filename.getBytes().length);
					toServer.write(cipheredCmd);



					// toServer.write(filename.getBytes());
					byte[] cipheredFile = encCipher.doFinal(filename.getBytes());

					byte[] cipheredFilelength= encCipher.doFinal(String.valueOf(cipheredFile.length).getBytes());

					toServer.write(cipheredFilelength);

					toServer.write(cipheredFile);

					byte [] fromFileBuffer = new byte[117];

					// Send the file
					for (boolean fileEnded = false; !fileEnded;) {
						numBytes = bufferedFileInputStream.read(fromFileBuffer);		
						fileEnded = numBytes < 117;

						// toServer.writeInt(1);
						cipheredCmd = encCipher.doFinal("1".getBytes());
						toServer.write(cipheredCmd);

						// toServer.writeInt(numBytes);
						cipheredCmd = encCipher.doFinal(String.valueOf(numBytes).getBytes());
						toServer.write(cipheredCmd);
						

						// toServer.write(fromFileBuffer);
						cipheredFile=encCipher.doFinal(fromFileBuffer);
						cipheredFilelength=encCipher.doFinal(String.valueOf(cipheredFile.length).getBytes());
						toServer.write(cipheredFilelength);
						toServer.write(cipheredFile);

						toServer.flush();
					}

					bufferedFileInputStream.close();
	        		fileInputStream.close();

					System.out.println("Successfully sent file: " + filename);
					long timeTaken = System.nanoTime() - timeStarted;
					System.out.println("File took: " + timeTaken/1000000.0 + "ms to send");

				} catch (Exception e) {
                    System.out.println("Invalid file name");
				}
			}
		} catch (Exception e) {e.printStackTrace();}
	}
}
