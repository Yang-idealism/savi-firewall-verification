#define MAX 3 /*ip count*/
#define MM 16  /*double of max*/
#define COUNT 2 /*interface count*/
#define N 2  /*count of client*/
#define REMOTE 2 /*start of remote ips*/
#define TCP 0
#define UDP 1
#define ICMP 2
#define PROS 3    
#define MAX_PORT 2
#define FT_SIZE 255
byte sw0_conn;
byte sw1_conn;
byte sending_flag;
typedef FLOW_TABLE_ENTRY          
{
	byte proto;
	byte src_ip;
	byte dst_ip;
	byte src_port;
	byte dst_port;
	byte fwd_int;
};
/*message type define*/
mtype={hello,feat_req,feat_rpl,ptdesc_req,ptdesc_rpl,fm01,fm02,fm03,data,pkt_in,pkt_out,flow_mod,pkt_drop};
mtype = {initial,ctrl_ready,localh_allow,rmt_allow}  
typedef MESSAGE{
	byte srcIP;
	byte dstIP;
	byte proto;
	int srcPort;
	int dstPort;
	byte RPL_pkt;            //repaly packtet
	byte Inside_FW;
	byte inport;
	byte fwdPort;            //forwarding port
};
byte trusted_IPs[MAX]     /*list of trusted IPs*/
chan l_s0[COUNT] = [MAX] of {mtype,MESSAGE};          //local host->switch0 
chan s0_l[COUNT] = [MAX] of {mtype,MESSAGE};          
chan s0_s1 = [MAX] of {mtype,MESSAGE};                //switch0->switch1
chan s1_s0 = [MAX] of {mtype,MESSAGE};                //switch1->switch0
chan r_s1[COUNT] = [MAX] of {mtype,MESSAGE};         //remote-> switch1
chan s1_r[COUNT] = [MAX] of {mtype,MESSAGE};        //switch1->remote 
chan c_s0 = [MAX] of {mtype,MESSAGE};            //client->switch0   client0->switch0  client1->switch0 
chan c_s1 = [MAX] of {mtype,MESSAGE};               // controller->switch0
chan s0_c = [MAX] of {mtype,MESSAGE};
chan s1_c = [MAX] of {mtype,MESSAGE};
/*client process*/
proctype localh(byte interfaceId){            
        byte IP = interfaceId;
        byte mtp;
	        MESSAGE sendmsg;
        sendmsg.srcIP = IP;
        MESSAGE recvmsg;
	byte remoteIP=REMOTE;
	if
	::sending_flag==localh_allow->  
		atomic{
		sendmsg.srcIP = IP;
		sendmsg.dstIP = remoteIP;
		sendmsg.proto = UDP;
		sendmsg.srcPort = 1;
		sendmsg.dstPort = 2;
		sendmsg.RPL_pkt = 0;
		sendmsg.Inside_FW = 1;
		l_s0[interfaceId]!data,sendmsg;
		}
	fi;
lreceive:
	do
	::s0_l[interfaceId]?mtp,recvmsg->     
	{
		assert(recvmsg.RPL_pkt != 0 || recvmsg.Inside_FW != 0);    
		sending_flag=rmt_allow;        
	}
	od;
endlocal:
skip;
}
proctype recvlocalh(byte interfaceId){  
        byte IP = interfaceId;
        byte mtp;
		byte protocol = 0;  
		byte port = 0;
        MESSAGE sendmsg;
        sendmsg.srcIP = IP;
        MESSAGE recvmsg;
lreceive:
	do
	::s0_l[interfaceId]?mtp,recvmsg->
		assert(recvmsg.Inside_FW != 0);
		sending_flag=rmt_allow;
	od;
endrecvlocalh:
skip;
}
proctype remote(byte interfaceId){    
        byte IP = interfaceId+REMOTE;  
        byte mtp; 
        byte remoteIP=N-1;  
	   byte protocol = 0;
	   byte port = 1;
        MESSAGE sendmsg;
        sendmsg.srcIP = IP;
        MESSAGE recvmsg;
		int i=1;
		int j=1;
		int k=0;
		int l=0;
rreceive:
	do
	::s1_r[interfaceId]?mtp,recvmsg->
		{
				atomic{
				sendmsg.dstIP = recvmsg.srcIP;
				sendmsg.proto = recvmsg.proto;
				sendmsg.srcPort = recvmsg.dstPort;
				sendmsg.dstPort = recvmsg.srcPort;
				sendmsg.RPL_pkt = 1;
				sendmsg.Inside_FW = 0;
				r_s1[interfaceId]!data,sendmsg;
				goto rsend;
				}
	od;
rsend:
			for(i:1..(MAX_PORT)){
				for(j:1..(MAX_PORT)){
					for(k:0..(PROS-1)){
						for(l:0..(N-1)){
							if
							::sending_flag==rmt_allow->
							atomic{
							sendmsg.dstIP = (N-1)-l;
							sendmsg.proto = k;
							sendmsg.srcPort = j;
							sendmsg.dstPort = i;
							sendmsg.RPL_pkt = 0;
							sendmsg.Inside_FW = 0;
							r_s1[interfaceId]!data,sendmsg;
							sending_flag=localh_allow;
							}
							fi;
						}
					}
				}
			}
			goto endremote;
endremote:
	skip;
}
proctype switch1(){    
            byte mtp;
        MESSAGE sendmsg;
        MESSAGE recvmsg;
	   FLOW_TABLE_ENTRY Flow_Table[FT_SIZE];
   	int i=0;
	int j=0;
	int flow_entry_cnt=0;
		if
	::sending_flag==ctrl_ready && sw1_conn==0->
		{
		s1_c!hello,sendmsg;
		do
		::c_s1?mtp,recvmsg->
			if
			::mtp==hello->
				skip;
			::mtp==feat_req->
				s1_c!feat_rpl,sendmsg;
			::mtp==ptdesc_req->
				s1_c!ptdesc_rpl,sendmsg;
			::mtp==fm01->
				skip;
			::mtp==fm02->
				skip;
			::mtp==fm03->
				atomic{
				sw1_conn=1;
				if
				::sw0_conn==1->
					sending_flag=localh_allow;
				::else
				fi;
				break;
				}
			fi;
		od;
		}
	fi;
	do
	::i<N->/*receive from localh(i)*/
		{
		if
		::r_s1[i]?mtp,recvmsg->
matchandfwd1:
				{
					if
					::flow_entry_cnt==0->
						atomic{/*no matching*/
						recvmsg.inport=i;
						s1_c!pkt_in,recvmsg;
						}
					::else->
					{
						for(j:0..(flow_entry_cnt-1)){
						if
						::Flow_Table[j].proto==recvmsg.proto && Flow_Table[j].src_ip==recvmsg.srcIP && Flow_Table[j].dst_ip==recvmsg.dstIP && Flow_Table[j].src_port==recvmsg.srcPort && Flow_Table[j].dst_port==recvmsg.dstPort ->
							atomic{
							if
							::Flow_Table[j].fwd_int<N->
								s1_r[Flow_Table[j].fwd_int]!data,recvmsg;
							::Flow_Table[j].fwd_int==N->
								s1_s0!data,recvmsg;
							::else
							fi;
							break;
							}
						::else
						fi;
						}
						if
						::j>(flow_entry_cnt-1)->
							atomic{/*no matching*/
							recvmsg.inport=i;
							s1_c!pkt_in,recvmsg;
							}
						::else
						fi;
					}
					fi;
				}
					::empty(r_s1[i])
		fi;
		i++;
		}
	::i==N->/*receive from switch1*/
		atomic{
		if
		::s0_s1?mtp,recvmsg->
			goto matchandfwd1;
		::empty(s0_s1)->i++;
		fi;
		}
	::i==N+1->/*receive from controller*/
		{
		do
		::c_s1?mtp,recvmsg->
			if
			::mtp==flow_mod->
				atomic{
				Flow_Table[flow_entry_cnt].proto=recvmsg.proto;
				Flow_Table[flow_entry_cnt].src_ip=recvmsg.srcIP;
				Flow_Table[flow_entry_cnt].dst_ip=recvmsg.dstIP;
				Flow_Table[flow_entry_cnt].src_port=recvmsg.srcPort;
				Flow_Table[flow_entry_cnt].dst_port=recvmsg.dstPort;
				Flow_Table[flow_entry_cnt].fwd_int=recvmsg.fwdPort;
				flow_entry_cnt++;
				}
			::mtp==pkt_out->
				atomic{
				if
				::recvmsg.fwdPort<N->
					s1_r[recvmsg.fwdPort]!data,recvmsg;
				::recvmsg.fwdPort==N->
					s1_s0!data,recvmsg;
				::else
				fi;
				}
			::mtp==pkt_drop->
				sending_flag=rmt_allow;
			fi;
		::empty(c_s1)->
			break;
		od;
		i=0;
		}
	od;
}
proctype switch0(){    
        byte mtp;
        MESSAGE sendmsg;
        MESSAGE recvmsg;
		FLOW_TABLE_ENTRY Flow_Table[FT_SIZE];
	int i=0;
	int j=0;
	int flow_entry_cnt=0;
	if
	::sending_flag==ctrl_ready && sw0_conn==0->
		{
		s0_c!hello,sendmsg;
		do
		::c_s0?mtp,recvmsg->
			if
			::mtp==hello->
				skip;
			::mtp==feat_req->
				s0_c!feat_rpl,sendmsg;
			::mtp==ptdesc_req->
				s0_c!ptdesc_rpl,sendmsg;
			::mtp==fm01->
				skip;
			::mtp==fm02->
				skip;
			::mtp==fm03->
				atomic{
				sw0_conn=1;
				if
				::sw1_conn==1->
					sending_flag=localh_allow;
				::else
				fi;
				break;
				}
			fi;
		od;
		}
	fi;
receive0:
	do
	::i<N->/*receive from localh(i)*/
		{
		if
		::l_s0[i]?mtp,recvmsg->
matchandfwd0:
			{
				{
					if
					::flow_entry_cnt==0->
						atomic{/*no matching*/
						recvmsg.inport=i;
						s0_c!pkt_in,recvmsg;
						}
					::else->
					{
					for(j:0..(flow_entry_cnt-1)){
					if
					::Flow_Table[j].proto==recvmsg.proto && Flow_Table[j].src_ip==recvmsg.srcIP && Flow_Table[j].dst_ip==recvmsg.dstIP && Flow_Table[j].src_port==recvmsg.srcPort && Flow_Table[j].dst_port==recvmsg.dstPort ->
						atomic{
						if
						::Flow_Table[j].fwd_int<N->
							s0_l[Flow_Table[j].fwd_int]!data,recvmsg;
						::Flow_Table[j].fwd_int==N->
							s0_s1!data,recvmsg;
						::else
						fi;
						break;
						}
					::else
					fi;
					}
					if
					::j>(flow_entry_cnt-1)->/*no matching*/
						atomic{
						recvmsg.inport=i;
						s0_c!pkt_in,recvmsg;
						}
					::else
					fi;
					}
					fi;
				}
			}
		::empty(l_s0[i])
		fi;
		i++;
		}
	::i==N->/*receive from switch1*/
		atomic{
		if
		::s1_s0?mtp,recvmsg->
			goto matchandfwd0;
		::empty(s1_s0)->i++;
		fi;
		}
	::i==N+1->/*receive from controller*/
		{
		do
		::c_s0?mtp,recvmsg->
			if
			::mtp==flow_mod->
				atomic{
				Flow_Table[flow_entry_cnt].proto=recvmsg.proto;
				Flow_Table[flow_entry_cnt].src_ip=recvmsg.srcIP;
				Flow_Table[flow_entry_cnt].dst_ip=recvmsg.dstIP;
				Flow_Table[flow_entry_cnt].src_port=recvmsg.srcPort;
				Flow_Table[flow_entry_cnt].dst_port=recvmsg.dstPort;
				Flow_Table[flow_entry_cnt].fwd_int=recvmsg.fwdPort;
				flow_entry_cnt++;
				}
			::mtp==pkt_out->
				atomic{
				if
				::recvmsg.fwdPort<N->
					s0_l[recvmsg.fwdPort]!data,recvmsg;
				::recvmsg.fwdPort==N->
					s0_s1!data,recvmsg;
				::else
				fi;
				}
			::mtp==pkt_drop->
				sending_flag=rmt_allow;
			fi;
		::empty(c_s0)->
			break;
		od;
		i=0;
		}
	od;
}
proctype controller(){    
        byte mtp;
        byte tmp;
        MESSAGE sendmsg;
        MESSAGE recvmsg;
	int i,j;
	for(i:0..(MAX-1)){
		if
		::i<N->
			trusted_IPs[i]=1;
		::else->
			trusted_IPs[i]=0;
		fi;
	}
	sending_flag=ctrl_ready;
	do
	::s0_c?mtp,recvmsg->
		if
		::mtp==hello->
			atomic{
			c_s0!hello,sendmsg;
			c_s0!feat_req,sendmsg;
			}
		::mtp==feat_rpl->
			c_s0!ptdesc_req,sendmsg;
		::mtp==ptdesc_rpl->
			atomic{
			c_s0!fm01,sendmsg;
			c_s0!fm02,sendmsg;
			c_s0!fm03,sendmsg;
			}
			fi;
	::s1_c?mtp,recvmsg->
		if
		::mtp==hello->
			atomic{
			c_s1!hello,sendmsg;
			c_s1!feat_req,sendmsg;
			}
		::mtp==feat_rpl->
			c_s1!ptdesc_req,sendmsg;
		::mtp==ptdesc_rpl->
			atomic{
			c_s1!fm01,sendmsg;
			c_s1!fm02,sendmsg;
			c_s1!fm03,sendmsg;
			}
			fi;
	::sending_flag==localh_allow->
		break;
	od;
creceive:
	do
	::s0_c?mtp,recvmsg->
		{
		if
		::recvmsg.srcIP<N && recvmsg.inport<N ->
			if
			::recvmsg.dstIP<N->
				atomic{
				recvmsg.fwdPort=recvmsg.dstIP;
				c_s0!flow_mod,recvmsg;
				c_s0!pkt_out,recvmsg;
				}
			::recvmsg.dstIP>=N->
				atomic{
				trusted_IPs[recvmsg.dstIP]=1;
				recvmsg.fwdPort=N;
				c_s0!flow_mod,recvmsg;
				c_s0!pkt_out,recvmsg;
				}
			::else
			fi;
		::recvmsg.srcIP>=N && recvmsg.inport==N ->
			if
			::recvmsg.dstIP<N->
				atomic{
				recvmsg.fwdPort=recvmsg.dstIP;
				c_s0!flow_mod,recvmsg;
				c_s0!pkt_out,recvmsg;
				}
			::else
			fi;
		::else
		fi;
			}
	::s1_c?mtp,recvmsg->
		{
		if
		::recvmsg.srcIP>=N && recvmsg.inport<N ->
			{
			if
			::recvmsg.dstIP>=N->
				atomic{
				recvmsg.fwdPort=recvmsg.dstIP-N;
				c_s1!flow_mod,recvmsg;
				c_s1!pkt_out,recvmsg;
				}
			::recvmsg.dstIP<N->
				if
				::trusted_IPs[recvmsg.srcIP]==1->
					atomic{
					recvmsg.fwdPort=N;
					c_s1!flow_mod,recvmsg;
					c_s1!pkt_out,recvmsg;
					}
				::else->
					c_s1!pkt_drop,recvmsg;
				fi;
			::else
			fi;
			}
		::recvmsg.srcIP<N && recvmsg.inport==N ->
			if
			::recvmsg.dstIP>=N->
				atomic{
				recvmsg.fwdPort=recvmsg.dstIP-N;
				c_s1!flow_mod,recvmsg;
				c_s1!pkt_out,recvmsg;
				}
			::else
			fi;
		::else
		fi;
				}
	od;
}
init{
	sending_flag=initial;   
	sw0_conn=0;
	sw1_conn=0;
	run localh(0);
	run recvlocalh(1);
	run remote(0);
	run controller();
	run switch0();
	run switch1();
}
