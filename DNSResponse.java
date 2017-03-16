
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;



// Lots of the action associated with handling a DNS query is processing 
// the response. Although not required you might find the following skeleton of
// a DNSreponse helpful. The class below has bunch of instance data that typically needs to be 
// parsed from the response. If you decide to use this class keep in mind that it is just a 
// suggestion and feel free to add or delete methods to better suit your implementation as 
// well as instance variables.



public class DNSResponse {
	private byte[] data1;
    private int queryID;                  // this is for the response it must match the one in the request 
    private int answerCount = 0;          // number of answers  
    private boolean decoded = false;      // Was this response successfully decoded
    private int nsCount = 0;              // number of nscount response records
    private int additionalCount = 0;      // number of additional (alternate) response records
    private boolean authoritative = false;// Is this an authoritative record
    

    private int currentPosition = 0;
    //The resource responses
	private ArrayList<RR> answers = new ArrayList<RR>();
	private ArrayList<RR> nameServers = new ArrayList<RR>();
	private ArrayList<RR> additionalInfo = new ArrayList<RR>();
    private Querry querry;
    private String ipaddr;
    
    
    public RR[] answerResponse(){
    	RR[] answerResponse = new RR[answers.size()];
    	for(int i = 0; i < answers.size(); i++){
    		answerResponse[i] = answers.get(i);
    	}
    	return answerResponse;   
    }
    
    public boolean authoritativeResonse(){
    	return authoritative;
    }
    public RR[] getNameServers(){
    	RR[] nameServer = new RR[nameServers.size()];
    	for(int i = 0; i < nameServers.size(); i++){
    		nameServer[i] = nameServers.get(i);
    	}
    	return nameServer;    	
    }
    
    //return additionalinfo section
    public RR[] getAdditionalInfo(){
    	RR[] retAdditionalInfo = new RR[additionalInfo.size()];
    	for(int i = 0; i < additionalInfo.size(); i++){
    		retAdditionalInfo[i] = additionalInfo.get(i);
    	}
    	return retAdditionalInfo;    	
    }
    //print out the trace
    void dumpResponse() {
    	if(DNSlookup.tracingOn){
    		querry.printFormattedItems();
    		System.out.println("Response ID:\t"+ queryID+" Authoritative = " + authoritative);
    		System.out.println("Answers ("+answerCount+")");
    		for(RR answer: answers){
    			answer.printFormattedItems();
    		}
    		System.out.println("Nameservers ("+nsCount+")");
    		for(RR nameserver: nameServers){
    			nameserver.printFormattedItems();
    		}		
    		
    		System.out.println("Additional information ("+additionalCount+")");
    		for(RR additional: additionalInfo){
    			additional.printFormattedItems();
    		}	
    		System.out.println(""); 
    	}
    	
	}

    // The constructor: you may want to add additional parameters, but the two shown are 
    // probably the minimum that you need.

	public DNSResponse (byte[] data, int len, String address) {
		
		ipaddr = address;
		//First 0 to 1 is the id  
		// 2 byte is QR code, OPCode, and what kind of answer 
	    this.data1 = data;
	    // The following are probably some of the things 
	    // you will need to do.
	    // Extract the query ID
	    queryID = (data[0]*256)+(data[1]);
		long ques = data1[2] & 0b10000000; // check to see if a question or response		& 0b10000000

	    // Make sure the message is a query response and determine
	    // if it is an authoritative response or note
		
		long AAanswer = data[2] & 0b100; // if 0 it is not an AA answer if 0 then we know it is not 1 otherwise it is 1
	    // determine answer count
		// determine question count
		int questionCount = (data1[4]*256)+data1[5];
		// determin the answer count 
		answerCount = (data1[6]*256)+data1[7];
	    // determine NS Count
		nsCount = (data1[8]*256)+data1[9];
	    // determine additional record count
		additionalCount = (data1[10]*256)+data1[11];
		currentPosition = 11;
		
		long rcode = (data[3] & 0b1111);
		
		if(rcode == 3){
			System.out.println(DNSlookup.urlToResolve+ " -1   A 0.0.0.0");
			System.exit(0);
		}else if(rcode != 0){
			System.out.println("-4: Rcode not recognized");
			System.exit(3);	
		}
		
		if(AAanswer != 0){
			authoritative = true;
			//we know we have the answer 
		}
		if(ques == 0){
			System.out.println("-4: There was no question in the response. Exiting");
			System.exit(0);
		}
		
		querry = getQuestion();
	
		answers = new ArrayList<RR>();
		nameServers = new ArrayList<RR>();
		additionalInfo = new ArrayList<RR>();
		
		for(int i = 0; i<answerCount; i++){
			answers.add(getRR());
		}
		for(int i = 0; i<nsCount; i++){
			nameServers.add(getRR());
		}		
		
		for(int i = 0; i<additionalCount; i++){
			additionalInfo.add(getRR());
		}		
		dumpResponse();
	}
	
	private Querry getQuestion(){
		String queryName = extractFQDN(); //get the question name
		
		int qtype = (data1[++currentPosition]*256)+data1[++currentPosition];
		int qclass = (data1[++currentPosition]*256)+data1[++currentPosition];
		
		Querry query = new Querry(queryName,qtype, queryID); //String name, int type, long id
		return query;
	}
    
    
    
    //get the FQDN from hex to string
	private String extractFQDN(){
		
		int startingBit = data1[++currentPosition] &0xff;
		if((startingBit & 0xC0) > 0){ 
			int pointer = (((data1[currentPosition]&0xFF) & 0b00111111)*256);
			pointer += data1[++currentPosition]&0xFF;
			return getCompresedFQDN(pointer);
		}else{
			String fqdn = "";
			
			byte currentByte = (byte) (data1[currentPosition] & 0xFFFFFFFFL);
            //if currentByte is 0 we know we have reached the end
			while(currentByte != 0){

				++currentPosition;
				int offset = currentByte & 0xFF;
				ArrayList<Byte> byteList = new ArrayList<Byte>();
				for(int i = 0; i < offset; i++){
					currentByte = (byte) (data1[currentPosition]& 0xFF); 
					
					byteList.add(currentByte);
					++currentPosition;
				}
				byte[] result = new byte[byteList.size()];
				for(int i = 0; i < byteList.size(); i++) {
				    result[i] = byteList.get(i).byteValue();
				}
				if(fqdn.length() != 0){
					fqdn = fqdn + "."+ new String(result, StandardCharsets.UTF_8);
				}else{
					fqdn =  new String(result, StandardCharsets.UTF_8);
				}
				
				currentByte = data1[currentPosition];
			}
			return fqdn;
		}
	}
	
	private String getCompresedFQDN(int pointer){

		String fqdn = "";
        //where to jump to
		byte currentByte = data1[pointer];
	
		while(currentByte != 0){
			int offset = currentByte&0xFF;
			if(((currentByte & 0xC0) > 0)){

				int nextLocation = ((currentByte& 0b00111111)*256);
				nextLocation += data1[++pointer]&0xFF;
				if(fqdn.length() != 0){
                    //if the there is compressed string in compressed string
					fqdn = fqdn + "."+ getCompresedFQDN(nextLocation);
				}else{
					fqdn = getCompresedFQDN(nextLocation);
				}
				return fqdn;
				
			}else {
				ArrayList<Byte> byteList = new ArrayList<Byte>();
				for(int i = 0; i < offset; i++){
					currentByte = data1[++pointer];
					byteList.add(currentByte);
				}
				byte[] result = new byte[byteList.size()];
				for(int i = 0; i < byteList.size(); i++) {
				    result[i] = byteList.get(i).byteValue();
				}
				if(fqdn.length() != 0){
					fqdn = fqdn + "."+ new String(result, StandardCharsets.UTF_8);
				}else{
					fqdn = new String(result, StandardCharsets.UTF_8);
				}
			}
			
			currentByte = (byte) (data1[++pointer]&0xFF);
		}
		
		return fqdn;
	}
	
	private RR getRR(){
		String RRname = extractFQDN();
		int typeCode = ((data1[++currentPosition]&0xFF)*256)+(data1[++currentPosition]&0xFF);
		int clss = ((data1[++currentPosition]&0xFF)*256)+(data1[++currentPosition]&0xFF);
		
		int TTL = 0;
        //last 4 bits are the TTL convert it to string
		for (int i= 0; i < 4; i++) {
			TTL = TTL << 8;
			TTL |= (data1[++currentPosition] & 0xFF);
		}
		
		
		
		int rdLenght =  (data1[++currentPosition]*256)+data1[++currentPosition];
		byte[] byteArray = new byte[rdLenght];
		for (int i = 0; i < rdLenght; i++){
			byteArray[i] = (byte) (data1[++currentPosition]&0xFF);
		}
		return new RR(RRname,typeCode,clss,TTL, getRdata(typeCode,byteArray));
	}
	
	
	private String getRdata(int typeCode, byte[] rdata){
		switch (typeCode){
		case 1: { //normal 

			int rdLenght =  rdata.length;
			String ResourceData = "";
			for (int i = 0; i < rdLenght; i++){
				if(i == rdLenght-1){
					ResourceData += Long.toString((long)(rdata[i]&0xFF));
				}else{
					ResourceData += Long.toString((long)(rdata[i]&0xFF)) + ".";
				}			
			}
			
			return ResourceData;
		}
		case 2: { //Name server
			return parseName(rdata);
		}
		
		case 5: { //Cname
			return parseName(rdata);
			
		}
		case 28: { //IPV6
			byte ip6Addr[] = new byte[16];
			
			for (int i = 0; i < 16; i++) {
				ip6Addr[i] = rdata[i];
			}
			
			try {
				InetAddress.getByAddress(ip6Addr);
				return InetAddress.getByAddress(ip6Addr).getHostAddress();
			} catch (Exception e)  {
				System.out.println("AddressConversion failed");
			}
		}default: return "---";
	}
		
	}
//get the string from hex
	private String parseName(byte[] rdata){
		String fqdn = "";
		int currentLocation = 0;
		while(currentLocation < rdata.length){
			int offset = rdata[currentLocation]&0xFF;
			
			if((offset & 0xC0) > 0){
				//this is a compressed name
				int pointer = ((rdata[currentLocation] & 0b00111111)*256);
				
				pointer += (long)(rdata[++currentLocation]&0xFF);
				
				if(fqdn.length() != 0){
					fqdn = fqdn + "." + DNSResponse.this.getCompresedFQDN(pointer);
				}else{
					fqdn = DNSResponse.this.getCompresedFQDN(pointer);
				}
				
				currentLocation++;
			}else{

				ArrayList<Byte> resultArraylist = new ArrayList<Byte>();
				
				for(int y = currentLocation+1; y < currentLocation+offset+1;y++){
					resultArraylist.add(rdata[y]);
				}				
				//convert to byte array 
				byte[] result = new byte[resultArraylist.size()];
				for(int i = 0; i < resultArraylist.size(); i++) {
				    result[i] = resultArraylist.get(i).byteValue();
				}
				
				if(fqdn.length() != 0){
					if(result.length != 0){
						fqdn = fqdn +"."+ new String(result, StandardCharsets.UTF_8);
					}
				}else{
					fqdn = new String(result, StandardCharsets.UTF_8);
				}
				
				currentLocation = currentLocation + offset + 1;
			}
		}
		return fqdn;
	}
	private class Querry{
		private String name;
		private int typeCode;
		private long id;
		
		
		
		Querry(String name, int type, long id) {
			this.name = name;
			this.typeCode = type;
			this.id = id;
		}


		String getName() { return name; }
		int getType() { return typeCode; }

		InetAddress getIPaddress() {return null;}
		String getCNAME() { return null; }

		void printFormattedItems() {
			System.out.println("Query ID\t"+id+" "+ name+" "+DNSResponse.this.getType(typeCode)+" --> " + ipaddr);
		}
	  }
	
	private String getType(int typeCode){
        //qtype_a = 1 
		//qtype_ns = 2
		//qtype_cname = 5 
		//qtype_aaaa = 28
		switch (typeCode){
		case 1: return "A";
		case 2: return "NS";
		case 5: return "CNAME";
		case 28: return "AAAA";
		}
			
		return null;
	}
	
	
}


