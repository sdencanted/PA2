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
import javax.crypto.Cipher;
import javax.sql.rowset.serial.SerialArray;
import java.util.Arrays;
import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;

public class ServerCP1 {

	public static void main(String[] args) {

    	int port = 4321;
    	if (args.length > 0) port = Integer.parseInt(args[0]);

		String certificateName = "server_cert.crt";

		PrivateKey privateKey = null;
		// PublicKey publicKey = null;
		Cipher encCipher = null;
		Cipher decCipher = null;
		try {
			byte[] keyBytes = Files.readAllBytes(Paths.get("private_key.der"));
			PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			privateKey = kf.generatePrivate(spec);
			// publicKey = kf.generatePublic(spec);
			encCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			encCipher.init(Cipher.ENCRYPT_MODE, privateKey);
			decCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			decCipher.init(Cipher.DECRYPT_MODE, privateKey);
		} catch (Exception e) {e.printStackTrace();}

		ServerSocket welcomeSocket = null;
		Socket connectionSocket = null;
		DataOutputStream toClient = null;
		DataInputStream fromClient = null;

		FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;

		FileOutputStream fileOutputStream = null;
		BufferedOutputStream bufferedFileOutputStream = null;
		
		ByteArrayOutputStream FilenameOutputStream = new ByteArrayOutputStream();
		
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
		
								toClient.writeInt(2);
								toClient.writeInt(numBytes);
								toClient.write(fromFileBuffer);
								toClient.flush();
							}
		
							bufferedFileInputStream.close();
							fileInputStream.close();
							System.out.println("Certificate sent successfully");
							startDecrypt=true;
							break;
							
						// packet for transferring file
						case 2:
							while (true) {
								int packetType2 = fromClient.readInt();
								// packet for transferring file name
								if (packetType2 == 0) {
									numBytes = fromClient.readInt();
									byte [] filename = new byte[numBytes];
									// Must use read fully!
									// See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
									fromClient.readFully(filename, 0, numBytes);
		
									fileOutputStream = new FileOutputStream("recv_" + new String(filename, 0, numBytes));
									bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);
									System.out.println("Received filename:" + new String(filename, 0, numBytes));
								}
								// packet for transferring a chunk of the file
								else if (packetType2 == 1) {
		
									numBytes = fromClient.readInt();
									byte [] block = new byte[numBytes];
									// System.out.println("new chunk");
									// System.out.println(fromClient.available());
									// System.out.println(numBytes);
									fromClient.readFully(block, 0, numBytes);
		
									if (numBytes > 0)
										bufferedFileOutputStream.write(block, 0, numBytes);
									
									if (numBytes < 117) {
		
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
						case 3:
							System.out.println("Closing connection...");
							fromClient.close();
							toClient.close();
							connectionSocket.close();
							break;
		
						default:
							break;
						}
				}

				else{ 
					byte[] encpacketType= new byte[128];
					fromClient.read(encpacketType);
					byte[] decpacketType=  decCipher.doFinal(encpacketType);
					int packetType= Integer.parseInt(new String(decpacketType));
					// System.out.println(packetType);


					byte[] encpacket= new byte[128];
					byte[] filename=null;
					byte [] tempfilename=null;
					switch (packetType) {
						// packet for nonce and requesting for identity
						
						// packet for transferring file
						case 2:
							while (true) {
								fromClient.read(encpacket);
								byte[] decpacket=  decCipher.doFinal(encpacket);
								int packetType2=Integer.parseInt(new String(decpacket));
								// int packetType2 = fromClient.readInt();

								// packet for transferring file name
								if (packetType2 == 0) {
									// numBytes = fromClient.readInt();

									fromClient.read(encpacket);
									decpacket=  decCipher.doFinal(encpacket);
									numBytes=Integer.parseInt(new String(decpacket));

									fromClient.read(encpacket);
									decpacket=  decCipher.doFinal(encpacket);
									int cipheredFilelength=Integer.parseInt(new String(decpacket));
									System.out.println("pootis");
									System.out.println(cipheredFilelength);

									byte [] encfilename = new byte[cipheredFilelength];
									
									fromClient.readFully(encfilename, 0, cipheredFilelength);
									
									tempfilename = decCipher.doFinal(encfilename);
									if (numBytes > 0)
										if (numBytes>117)
											FilenameOutputStream.write(tempfilename,0,117);
										else
											FilenameOutputStream.write(tempfilename,0,numBytes);
									if (numBytes <= 117) {
										filename= FilenameOutputStream.toByteArray();
										if (FilenameOutputStream != null) FilenameOutputStream.close();
										// System.out.println("File name");

										FilenameOutputStream = new ByteArrayOutputStream();
										// fromClient.read(encpacket);
										// decpacket=  decCipher.doFinal(encpacket);
										// filename=new String(decpacket);
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
									decpacket=  decCipher.doFinal(encpacket);
									numBytes=Integer.parseInt(new String(decpacket));

									fromClient.read(encpacket);
									decpacket=  decCipher.doFinal(encpacket);
									int cipheredFilelength=Integer.parseInt(new String(decpacket));

									byte [] encblock = new byte[cipheredFilelength];


									// System.out.println("new chunk");
									// System.out.println(fromClient.available());
									// System.out.println(numBytes);
									fromClient.readFully(encblock, 0, cipheredFilelength);


									byte [] block = decCipher.doFinal(encblock);
		
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
						case 3:
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
