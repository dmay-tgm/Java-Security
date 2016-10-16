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
	private SecureService s;
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
	 * Creates new server socket with a specified port.
	 * 
	 * @param port
	 *            server socket port
	 */
	public Server(SecureService s, String port) {
		try {
			this.s = s;
			serverS = new ServerSocket(Integer.parseInt(port));
		} catch (IOException | SecurityException | IllegalArgumentException ioe) {
			System.err.println("Couldn't create server socket on port " + port + ": " + ioe.getMessage());
			System.exit(1);
		}
	}

	/**
	 * Starts a server thread which accepts clients.
	 */
	public void start() {
		new Thread(() -> {
			try {
				clientS = serverS.accept();
				input = new DataInputStream(clientS.getInputStream());
				output = new DataOutputStream(clientS.getOutputStream());

				byte[] eSK = new byte[input.readInt()];
				input.readFully(eSK, 0, eSK.length);
				s.decryptSecretKey(eSK);
				byte[] msg = s.encryptMessage();
				output.writeInt(msg.length);
				output.write(msg);

				close();
			} catch (IOException | SecurityException | IllegalBlockingModeException e) {
				System.err.println("Couldn't start thread: " + e.getMessage());
			}
		}).start();
	}

	/**
	 * Closes all data streams and the client socket connection.
	 */
	public void close() {
		try {
			output.close();
			input.close();
			clientS.close();
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
		Server uno = new Server(new SecureService(args[0]), args[1]);
		uno.start();
	}
}