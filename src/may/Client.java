package may;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;

/**
 * Communication client via IPC.
 * 
 * @author Daniel May
 * @version 2016-10-16.1
 *
 */
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
		System.err.println("secureclient <ldap-ip:ldap-port> <service-ip> <service-port>");
		System.exit(1);
	}

	/**
	 * Saves the server information.
	 * 
	 * @param ip
	 *            IP address of the server
	 * @param port
	 *            port of the server
	 * 
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
	 * Connects to the server.
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

	/**
	 * Sends data with byte arrays.
	 * 
	 * @param bytes
	 *            the data to send
	 */
	private void send(byte[] bytes) {
		try {
			output.writeInt(bytes.length);
			output.write(bytes);
		} catch (IOException e) {
			System.err.println("Couldn't send data: " + e.getMessage());
			System.exit(1);
		}
	}

	/**
	 * Get data from the server.
	 * 
	 * @return the received data
	 */
	private byte[] read() {
		try {
			byte[] message = new byte[input.readInt()];
			input.readFully(message, 0, message.length);
			return message;
		} catch (IOException e) {
			System.err.println("Couldn't receive data: " + e.getMessage());
			System.exit(1);
			return null;
		}
	}

	/**
	 * Closes the data streams and the socket.
	 */
	private void close() {
		try {
			output.close();
			input.close();
			socket.close();
			System.out.println("Terminated.");
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
		// connect to the server
		c.connect();
		// send the encrypted secret key
		c.send(sc.encryptSecretKey());
		// print out the received encrypted message
		System.out.println(sc.decryptMessage(c.read()));
		c.close();
	}
}