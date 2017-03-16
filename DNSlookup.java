
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;

/**
 * 
 */

/**
 * @author Donald Acton
 * This example is adapted from Kurose & Ross
 * Feel free to modify and rearrange code as you see fit
 */
public class DNSlookup {
    
    
    static final int MIN_PERMITTED_ARGUMENT_COUNT = 2;
    static final int MAX_PERMITTED_ARGUMENT_COUNT = 3;
	public static boolean tracingOn = false;
	public static boolean IPV6Query = false;
	private static String rootIP;
	private static int numberOfQuerries = 1;
	public static String urlToResolve;
	private static int TTL;
    /**
     * @param args
     */
    public static void main(String[] args) throws Exception {
    	try{
    		String fqdn;
    		
    		int argCount = args.length;

    		InetAddress rootNameServer;
    		
    		if (argCount < MIN_PERMITTED_ARGUMENT_COUNT || argCount > MAX_PERMITTED_ARGUMENT_COUNT) {
    		    usage();
    		    return;
    		}
    		rootIP = args[0];
    		rootNameServer = InetAddress.getByName(rootIP);
    		fqdn = args[1];
    		
    		if (argCount == 3) {  // option provided
    		    if (args[2].equals("-t"))
    			tracingOn = true;
    		    else if (args[2].equals("-6"))
    			IPV6Query = true;
    		    else if (args[2].equals("-t6")) {
    			tracingOn = true;
    			IPV6Query = true;
    		    } else  { // option present but wasn't valid option
    			usage();
    			return;
    		    }
    		}
    		urlToResolve = fqdn;
    		
    		formulateQuerry(rootIP,fqdn, IPV6Query, false);
    	}catch (IOException e){
    		System.out.println("-4: error");
    		System.exit(-4);
    	}
	
   }
    //Run the querry send it ipaddress with fqdn and also specify if it is a CName
    private static String formulateQuerry(String ipaddress, String fqdn, boolean IPV6, boolean isCname) throws IOException{
    	DNSResponse response;
    	boolean answer = false;
    	while(!answer && numberOfQuerries <  31){
    		response = sendQuerry(ipaddress,fqdn, IPV6);
    		RR[] answerResponses = response.answerResponse();
    		RR[] NS = response.getNameServers();
    		RR[] additionalInfo = response.getAdditionalInfo();
    		
    		if(response.authoritativeResonse() || answerResponses.length > 0){
    			if(answerResponses.length == 0){
    				System.out.format(" %-30s -6 A 0.0.0.0\n", urlToResolve);
    				return "0.0.0.0";
    			}else{
    				String lastAnswer = "";
    				//we have an answer extract it 
    				for(RR answerResponse:answerResponses){
    					if(answerResponse.getType().equals("CN")){
    						lastAnswer = formulateQuerry(rootIP,answerResponse.getRdata(), IPV6, false);
    					}else{
    						TTL = answerResponse.getTtl();
    						if(TTL == 0){
    							TTL = -6;
    						}
    						lastAnswer = answerResponse.getRdata();
    						
    						if(!isCname){
    							System.out.format(" %-30s %-10d %-4s %s\n", urlToResolve, TTL, answerResponse.getType(), answerResponse.getRdata());	
    						}
								
    						
    						
    					}
    				}
    				return lastAnswer;
     		 }
    						
    		}
    		    		
    			ipaddress = getIPofNS(NS[0].getRdata(),additionalInfo);
    		
    	
    		numberOfQuerries++;
    	}
    	
    	if(numberOfQuerries == 31){
    		System.out.println("-3: Too many queries are attempted without resolving the address.");
    		System.exit(-3);
    	}
    	return "---";
    }
    
    private static String getIPofNS(String nsName, RR[] additionalInfos) throws IOException{
    	for (RR additionalInfo : additionalInfos){
    		if(additionalInfo.getName().equals(nsName)){
    			return additionalInfo.getRdata();
    		}
    	}
    	return formulateQuerry(rootIP, nsName, false, true);
    }
    
    private static DNSResponse sendQuerry(String ipaddress, String fqdn, boolean IPV6) throws IOException{
    	try{
        	DNSResponse response; // Just to force compilation
        	DatagramSocket socket = new DatagramSocket();
        	byte[] buf = new byte[256];
        	buf = encodeURL(fqdn, IPV6);
            InetAddress rootNameServer = InetAddress.getByName(ipaddress);
            DatagramPacket packet = new DatagramPacket(buf, buf.length, rootNameServer, 53);
            //set time out
            socket.setSoTimeout(5000);
            socket.send(packet);
            
            buf = new byte[1024];
            packet = new DatagramPacket(buf, buf.length);
            socket.receive(packet);  
            response = new DNSResponse(buf, 1024, ipaddress);
            return response;
    		
    	}catch (SocketTimeoutException e){
    		System.out.format(" %-30s -6 A 0.0.0.0\n", urlToResolve);
    		System.out.println("-2 Time out the querry too long");
    		System.exit(-2);
    	}
    	return null;

    }
    
    static private byte[] encodeURL(String url, boolean IPV6Query){
    	
    	String[] splitURL = url.split("\\.");
        byte[] buf = new byte[128];
//use random number
        buf[0]  = 00;
        buf[1]  = 01;
//Flags 
        buf[2]  = 00;
        buf[3]  = 00;
//Number of questiosn
        buf[4]  = 00; 
        buf[5]  = 01;

        buf[6]  = 00; 
        buf[7]  = 00;
        buf[8]  = 00; 
        buf[9]  = 00;
        buf[10] = 00; 
        buf[11] = 00;
        
        int i = 12;
        //converte url to  bytes
        for(String domain: splitURL){
        	buf[i] = (byte) domain.length();
        	i++;
        	//copy character by character 
        	for(char c : domain.toCharArray()){
        		buf[i] = (byte) c;
        		i++;
        	}
//        	i++;
        }
        buf[i] = 00;
        //change this if the ipv6
        
        // qtype_a = 1 
        //qtype_ns = 2
        //qtype_cname = 5 
        //qtype_aaaa = 28
        if(IPV6Query){
	        buf[i+1] = 00;
	        buf[i+2] = 28;
	        buf[i+3] = 00;
	        buf[i+4] = 01;
	        i = i + 4;        	
        }else{
	        buf[i+1] = 00;
	        buf[i+2] = 01;
	        buf[i+3] = 00;
	        buf[i+4] = 01;
	        i = i + 4;
        }
        byte[] returnArray = new byte[i+1];
        for(int x = 0; x< i+1; x ++){
        	returnArray[x] = buf[x];
        }
        

        return returnArray;
    }
    
    private static void usage() {
	System.out.println("Usage: java -jar DNSlookup.jar rootDNS name [-6|-t|t6]");
	System.out.println("   where");
	System.out.println("       rootDNS - the IP address (in dotted form) of the root");
	System.out.println("                 DNS server you are to start your search at");
	System.out.println("       name    - fully qualified domain name to lookup");
	System.out.println("       -6      - return an IPV6 address");
	System.out.println("       -t      - trace the queries made and responses received");
	System.out.println("       -t6     - trace the queries made, responses received and return an IPV6 address");
    }

}


