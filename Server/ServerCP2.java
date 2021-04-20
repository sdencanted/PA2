import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.sql.rowset.serial.SerialArray;
import java.util.Arrays;

public class ServerCP2 {

	public static void main(String[] args) {

    	int port = 4321;
    	if (args.length > 0) port = Integer.parseInt(args[0]);

		String certificateName = "server_cert.crt";

		PrivateKey privateKey = null;
		//PublicKey publicKey = null;
		Cipher encCipher = null;
		Cipher decCipher = null;
		Cipher symCipher = null;

		try {
			byte[] privateKeyBytes = Files.readAllBytes(Paths.get("private_key.der"));
			//byte[] publicKeyBytes = Files.readAllBytes(Paths.get("public_key.der"));
			PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(privateKeyBytes);
			//X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publicKeyBytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			privateKey = kf.generatePrivate(privateSpec);
			//publicKey = kf.generatePublic(publicSpec);
			encCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			encCipher.init(Cipher.ENCRYPT_MODE, privateKey);
			decCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			//decCipher.init(Cipher.DECRYPT_MODE, publicKey);
			decCipher.init(Cipher.DECRYPT_MODE, privateKey);
		} catch (Exception e) {e.printStackTrace();}

		SecretKey sessionKey = null;

		ServerSocket welcomeSocket = null;
		Socket connectionSocket = null;
		DataOutputStream toClient = null;
		DataInputStream fromClient = null;

		FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;

		FileOutputStream fileOutputStream = null;
		BufferedOutputStream bufferedFileOutputStream = null;

		int numBytes = 0;
		int numEncryptedBytes = 0;

		try {
			welcomeSocket = new ServerSocket(port);
			connectionSocket = welcomeSocket.accept();
			fromClient = new DataInputStream(connectionSocket.getInputStream());
			toClient = new DataOutputStream(connectionSocket.getOutputStream());
			while (!connectionSocket.isClosed()) {

				int packetType = fromClient.readInt();
				switch (packetType) {
				// packet for nonce and requesting for identity
				case 0:
					System.out.println("Receiving nonce and sending greeting...");
					// receive nonce
					numBytes = fromClient.readInt();
					byte [] nonce = new byte[numBytes];
					fromClient.readFully(nonce, 0, numBytes);
					// System.out.println(Arrays.toString(nonce));
					System.out.println("Received nonce: '" + new String(nonce,0,numBytes)+"'");

					// encrypt nonce with private key and send to client
					byte[] cipheredNonce = encCipher.doFinal(nonce);
					System.out.print("Sending encrypted nonce to client..." );
					// System.out.println(Arrays.toString(cipheredNonce));
					toClient.writeInt(0);
					toClient.writeInt(cipheredNonce.length);
					toClient.write(cipheredNonce);

					//predict expected decryption

					// byte[] decipheredNonce = decCipher.doFinal(cipheredNonce);
					// System.out.print("expected decipher: " );
					// System.out.println(decipheredNonce);
					

					break;

				// packet requesting for Certificate
				case 1:
					System.out.println("Received request for certificate, sending...");

					// Send the certificate file name
					toClient.writeInt(1);
					toClient.writeInt(certificateName.getBytes().length);
					toClient.write(certificateName.getBytes());

					// Open the certificate file
					fileInputStream = new FileInputStream(certificateName);
					bufferedFileInputStream = new BufferedInputStream(fileInputStream);

					byte[] fromFileBuffer = new byte[117];

					// Send the certificate file
					for (boolean fileEnded = false; !fileEnded;) {
						numBytes = bufferedFileInputStream.read(fromFileBuffer);
						fileEnded = numBytes < 117;
						fromFileBuffer = Arrays.copyOfRange(fromFileBuffer, 0, numBytes);

						toClient.writeInt(2);
						toClient.writeInt(numBytes);
						toClient.write(fromFileBuffer);
						toClient.flush();
					}

					bufferedFileInputStream.close();
					fileInputStream.close();
					System.out.println("Certificate sent successfully");

					break;

				// packet for symetric session key
				case 2:
					System.out.println("Receiving session key from client...");
					numBytes = fromClient.readInt();
					byte[] encryptSessionKey = new byte[numBytes];
					fromClient.readFully(encryptSessionKey, 0, numBytes);

					byte[] decryptedSessionKey = decCipher.doFinal(encryptSessionKey);
					sessionKey = new SecretKeySpec(decryptedSessionKey, 0, decryptedSessionKey.length, "AES");
					System.out.println("Received session key!");

					// init symmetric session key Cipher
					symCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
					symCipher.init(Cipher.DECRYPT_MODE, sessionKey);

					//fromClient.skipBytes(fromClient.available());
					break;
					
				// packet for transferring file
				case 3:
					while (true) {
						int packetType2 = fromClient.readInt();
						// packet for transferring file name
						if (packetType2 == 0) {
							numEncryptedBytes = fromClient.readInt();
							numBytes = fromClient.readInt();
							byte[] encryptedFilename = new byte[numEncryptedBytes];
							// Must use read fully!
							// See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
							fromClient.readFully(encryptedFilename, 0, numEncryptedBytes);

							// decrypt the filename
							byte[] filename = symCipher.doFinal(encryptedFilename);

							fileOutputStream = new FileOutputStream("recv_" + new String(filename, 0, numBytes));
							bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);
							System.out.println("Received filename:" + new String(filename, 0, numBytes));
						}
						// packet for transferring a chunk of the file
						else if (packetType2 == 1) {

							numEncryptedBytes = fromClient.readInt();
							numBytes = fromClient.readInt();
							byte [] encryptedBlock = new byte[numEncryptedBytes];
							System.out.println("new chunk");
							System.out.println(fromClient.available());
							System.out.println(numEncryptedBytes);
							fromClient.readFully(encryptedBlock, 0, numEncryptedBytes);

							// decrypt the file block
							byte[] block = symCipher.doFinal(encryptedBlock);

							if (numBytes > 0)
								bufferedFileOutputStream.write(block, 0, numBytes);
							
							if (numBytes < 128) {

								if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
								if (bufferedFileOutputStream != null) fileOutputStream.close();
								System.out.println("File received successfully");
								//System.out.println(fromClient.available());
								//fromClient.skipBytes(fromClient.available());
								break;
							}
						}
					}
					break;

				// packet for closing the session
				case 4:
					System.out.println("Closing connection...");
					fromClient.close();
					toClient.close();
					connectionSocket.close();
					break;

				default:
					break;
				}
			}
		} catch (Exception e) {e.printStackTrace();}

	}

}
