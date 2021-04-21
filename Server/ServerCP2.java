import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
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
			PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(privateKeyBytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			privateKey = kf.generatePrivate(privateSpec);
			encCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			encCipher.init(Cipher.ENCRYPT_MODE, privateKey);
			decCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
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

		ByteArrayOutputStream filenameOutputStream = new ByteArrayOutputStream();

		int numBytes = 0;
		boolean startDecrypt= false;

		try {
			welcomeSocket = new ServerSocket(port);
			connectionSocket = welcomeSocket.accept();
			fromClient = new DataInputStream(connectionSocket.getInputStream());
			toClient = new DataOutputStream(connectionSocket.getOutputStream());
			while (!connectionSocket.isClosed()) {
				if (!startDecrypt) {
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

						fromClient.skipBytes(fromClient.available());
						startDecrypt = true;
					break;
					}
				}
				else{
					byte[] encpacketType= new byte[16];
					fromClient.read(encpacketType);
					System.out.println(encpacketType);
					byte[] decpacketType = symCipher.doFinal(encpacketType);

					int packetType= Integer.parseInt(new String(decpacketType));
					// System.out.println(packetType);


					byte[] encpacket= new byte[16];
					byte[] encpacketPad = new byte[48];
					byte[] filename=null;
					byte [] tempfilename=null;
					switch (packetType) {
		
					// packet for transferring file
					case 3:
						while (true) {
							fromClient.read(encpacket);
							// System.out.println("pootis");
							byte[] decpacket=  symCipher.doFinal(encpacket);
							int packetType2 = Integer.parseInt(new String(decpacket));

							// packet for transferring file name
							if (packetType2 == 0) {
								fromClient.read(encpacket);
								decpacket=  symCipher.doFinal(encpacket);
								numBytes=Integer.parseInt(new String(decpacket));

								fromClient.read(encpacket);
								decpacket=  symCipher.doFinal(encpacket);
								int cipheredFilelength=Integer.parseInt(new String(decpacket));

								byte [] encfilename = new byte[cipheredFilelength];
								
								fromClient.readFully(encfilename, 0, cipheredFilelength);
								
								tempfilename = symCipher.doFinal(encfilename);
								if (numBytes > 0)
									if (numBytes>117)
										filenameOutputStream.write(tempfilename,0,117);
									else
										filenameOutputStream.write(tempfilename,0,numBytes);
								if (numBytes <= 117) {
									filename= filenameOutputStream.toByteArray();
									if (filenameOutputStream != null) filenameOutputStream.close();
									// System.out.println("File name");

									filenameOutputStream = new ByteArrayOutputStream();
									// fromClient.read(encpacket);
									// decpacket = symCipher.doFinal(encpacket);
									// filename = new String(decpacket);
									// fromClient.readFully(filename, 0, numBytes);
		
									System.out.println("Received filename:" + new String(filename));
									fileOutputStream = new FileOutputStream("recv_" + new String(filename, 0, numBytes));
									bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);
								}
							}
							// packet for transferring a chunk of the file
							else if (packetType2 == 1) {

								// numBytes = fromClient.readInt();
								fromClient.read(encpacket);
								decpacket=  symCipher.doFinal(encpacket);
								numBytes=Integer.parseInt(new String(decpacket));

								fromClient.read(encpacket);
								decpacket=  symCipher.doFinal(encpacket);
								int cipheredFilelength=Integer.parseInt(new String(decpacket));

								byte [] encblock = new byte[cipheredFilelength];

								// System.out.println("new chunk");
								// System.out.println(fromClient.available());
								// System.out.println(numBytes);
								fromClient.readFully(encblock, 0, cipheredFilelength);

								byte [] block = symCipher.doFinal(encblock);
	
								if (numBytes > 0)
									if (numBytes >117)
										bufferedFileOutputStream.write(block, 0, 117);
									else
										bufferedFileOutputStream.write(block, 0, numBytes);
								
								if (numBytes <= 117) {
	
									if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
									if (bufferedFileOutputStream != null) fileOutputStream.close();
									System.out.println("File received successfully");
									// System.out.println(fromClient.available());
									// fromClient.skipBytes(fromClient.available());
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
			}
		} catch (Exception e) {e.printStackTrace();}

	}

}
