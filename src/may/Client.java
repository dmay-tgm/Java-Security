package may;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;

public class Client {

	private Socket socket;

	private DataInputStream input;
	private DataOutputStream output;

	private String ip;
	private int port;

	/**
	 * Prints the usage of this application and terminates the application.
	 */
	private static void helpMessage() {
		System.err.println("secureservice <ldap-ip:ldap-port> <service-ip> <service-port>");
		System.exit(1);
	}

	/**
	 * Saves the secure client and the server information.
	 * 
	 * @param sc
	 *            the secure client
	 * @param host
	 *            the host information
	 */
	public Client(String ip, String port) {
		this.ip = ip;
		try {
			this.port = Integer.parseInt(port);
		} catch (NumberFormatException e) {
			helpMessage();
		}
	}

	/**
	 * Connects with the server
	 */
	private void connect() {
		try {
			socket = new Socket(ip, port);
			input = new DataInputStream(socket.getInputStream());
			output = new DataOutputStream(socket.getOutputStream());
		} catch (IOException | SecurityException | IllegalArgumentException e) {
			System.err.println("Couldn't connect to the server: " + e.getMessage());
			System.exit(1);
		}
	}

	public byte[] read() {
		try {
			int length = this.input.readInt();
			if (length > 0) {
				byte[] message = new byte[length];
				this.input.readFully(message, 0, message.length);
				return message;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	public void send(byte[] bytes) {
		try {
			output.writeInt(bytes.length);
			output.write(bytes);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Closes the data streams and the socket.
	 */
	public void close() {
		try {
			output.close();
			input.close();
			socket.close();
		} catch (IOException e) {
			System.err.println("Couldn't properly terminate the application: " + e.getMessage());
			System.exit(1);
		}
	}

	/**
	 * Main function for starting the client
	 * 
	 * @param args
	 *            command line arguments
	 */
	public static void main(String[] args) {
		if (args.length != 3)
			helpMessage();
		SecureClient sc = new SecureClient(args[0]);
		Client c = new Client(args[1], args[2]);
		c.connect();
		c.send(sc.encryptSecretKey());
		System.out.println(sc.decryptMessage(c.read()));
		c.close();
	}
}