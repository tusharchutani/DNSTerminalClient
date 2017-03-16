import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

public class RR {
		private String name;
		private int typeCode;
		private int rclass;
		private int ttl;
		private String rdata;
		
		RR(String name, int type, int rclass, int ttl, String rdata) {
			this.name = name;
			this.typeCode = type;
			this.rclass = rclass;
			this.ttl = ttl;
			this.rdata = rdata;
		}


		String getName() { return name; }
		String getType() { return getType(typeCode); }
		int getRclass() {return rclass; }
		int getTtl() {return ttl;}
		String getRdata() { return rdata; }
		String getCNAME() { return null; }

		void printFormattedItems() {
			
			System.out.format("       %-30s %-10d %-4s %s\n", name, ttl, getType(typeCode), rdata);
		}
		
		
		private String getType(int typeCode){
	        //qtype_a = 1 
			//qtype_ns = 2
			//qtype_cname = 5 
			//qtype_aaaa = 28
			switch (typeCode){
			case 1: return "A";
			case 2: return "NS";
			case 5: return "CN";
			case 28: return "AAAA";
			}
				
			return "6";
		}
		


}
	
