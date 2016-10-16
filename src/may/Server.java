package may;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.channels.IllegalBlockingModeException;

/**
 * Communication server via IPC.
 * 
 * @author Daniel May
 * @version 2016-10-16.1
 *
 */
public class Server {
	private ServerSocket serverS;
	private Socket clientS;
	private DataInputStream input;
	private DataOutputStream output;

	/**
	 * Prints the usage of this application and terminates the application.
	 */
	private static void helpMessage() {
		System.err.println("secureservice <ldap-ip:ldap-port> <service-port>");
		System.exit(1);
	}

	/**
	 * Creates a new server socket with a specified port.
	 * 
	 * @param port
	 *            server socket port
	 */
	public Server(String port) {
		try {
			serverS = new ServerSocket(Integer.parseInt(port));
		} catch (IOException | SecurityException | IllegalArgumentException ioe) {
			System.err.println("Couldn't create server socket on port " + port + ": " + ioe.getMessage());
			System.exit(1);
		}
	}

	/**
	 * Starts the server and waits for a client. Can be terminated with [ENTER]
	 * in case of no client.
	 */
	private void start() {
		new Thread() {
			/*
			 * (non-Javadoc)
			 * 
			 * @see java.lang.Thread#run()
			 */
			@Override
			public void run() {
				try {
					while (System.in.read() != '\n')
						;
					System.out.println("Terminated.");
					System.exit(0);
				} catch (IOException e) {
					System.err.println("An I/O error occurred: " + e.getMessage());
				}
			}
		}.start();
		System.out.println("Waiting for client ...");
		System.out.println("Press [ENTER] to terminate.");
		try {
			clientS = serverS.accept();
			input = new DataInputStream(clientS.getInputStream());
			output = new DataOutputStream(clientS.getOutputStream());
		} catch (IOException | SecurityException | IllegalBlockingModeException e) {
			System.err.println("Couldn't start the connection: " + e.getMessage());
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
	 * Get data from the client.
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
	 * Closes all data streams and the socket connections.
	 */
	private void close() {
		try {
			output.close();
			input.close();
			clientS.close();
			serverS.close();
			System.out.println("Terminated.");
		} catch (IOException e) {
			System.err.println("Couldn't properly terminate the application: " + e.getMessage());
			System.exit(1);
		}
	}

	/**
	 * Main function for starting the server application.
	 * 
	 * @param args
	 *            command line arguments
	 */
	public static void main(String[] args) {
		if (args.length != 2)
			helpMessage();
		SecureService s = new SecureService(args[0]);
		Server uno = new Server(args[1]);
		// start listening for the client
		uno.start();
		// decrypt the received secret key
		s.decryptSecretKey(uno.read());
		// send an encrypted message
		uno.send(s.encryptMessage());
		// terminate
		uno.close();
		System.exit(0);
	}
}