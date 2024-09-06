/*client<->savi<->server*/
#define MAX 8 /*ip count , [0-MAX]:global address,[MAX-2*MAX] link-local address*/
#define MM 16  /*double of max*/
#define N 4  /*savi interface count<->count of client(intruder includer)*/
#define a1 bounded[0]
#define a4 (assignedIpCount < MAX) 
#define conflict !(bounded[0]&&bounded[1]&&(boundedAddr[0]==boundedAddr[1]))
#define declineAttack (attackSuccess) 
bool bounded[N];
byte boundedAddr[N];
byte assignedIpCount;
bool attackSuccess = false;

/*message type define*/
mtype = {solicit,advertise,request,confirm,reply,release,decline};
mtype = {dad_ns,na,tt,notonlink,nobinding,ping,pingreply};
mtype = {begin,start,live,detection,bound,tobeDelete} /*states in savi*/

/*dhcp message*/
typedef MESSAGE{
	/*source mac,destination mac, source ipv6 address,desination ipv6 address ,target address*/
	byte srcMac; 
	byte dstMac;
	byte srcIp;
	byte dstIp;
	byte target; 	
}

/*binding state table*/
typedef BST{
	byte anc; 
	byte mac; 
	byte address;
	mtype state;
}

/*The binding table uses the port as the keyword, that is, the case where one port is bound to multiple IPs is not considered here*/
bit IPs[MAX] /*ip pool in dhcp server: global address*/
BST table[MM]; /*bst in savi，The first half records the global address, and the second half records the linklocal address*/

/*1~2Client,1server,1savi,1intruder(maybe)*/
/*chan:client<->savi server<->savi intrucer<->savi multichan*/

/*channel from client to savi is only one*/
chan c_sv = [MAX] of {mtype,MESSAGE,byte};
/*client->savi:type,msg,interfaceId:The information in MESSAGE can be forged, but interfaceId indicates which port savi is connected to, which is unforgeable information.*/
chan sv_c[N] = [2] of {mtype,MESSAGE,byte}; /*savi->client:the index of channel <-> interface number*/
chan sv_ss = [N] of {mtype,MESSAGE,byte}; /*savi-dhcpserver*/
chan ss_sv = [N] of {mtype,MESSAGE,byte}; /*server-savi*/
chan multichan = [N] of {mtype,MESSAGE,byte};/*multicast :dad_NS*/

/*client process*/
proctype client(byte interfaceId){    
    /*init msg:the value of mac,target = interfaceId*/
    atomic{
        byte mac = interfaceId;
        byte linklocaladdr =  MAX + interfaceId;
        byte globaladdr = interfaceId ;
        byte mtp; /*msg type*/
        byte tmp;
        MESSAGE sendmsg;
        sendmsg.srcMac = mac;
        MESSAGE recvmsg;
    }
newllip:
    linklocaladdr++;
    linklocaladdr = linklocaladdr % MAX + MAX ;
getlinklocal:
    atomic{
       sendmsg.srcIp = 0;/*全0*/ 
       /*The destination address and mac are the broadcast mac and dad_ns addresses, which are set to the default value 0.*/
       sendmsg.dstMac = 0;
       sendmsg.dstIp = 0;
       sendmsg.target = linklocaladdr;
       /*send dad_ns for link-local*/
       c_sv!dad_ns,sendmsg,interfaceId;       
    }
    /*relay*/
    tmp = 0;
    do
    ::tmp >4 ->break;
    ::else ->tmp++;
    od;
receive0:
    if
    ::sv_c[interfaceId]?mtp,recvmsg,_->
      if
      ::mtp == na && recvmsg.target == linklocaladdr ->goto  newllip;/*get a new linklocal addr*/
      fi;
    ::timeout->
      if
      ::multichan??[dad_ns,recvmsg,eval(interfaceId)]->multichan??dad_ns,recvmsg,eval(interfaceId);
      ::else->skip;
      fi;
      c_sv!tt,sendmsg,interfaceId;
    fi;
newgloabalIp:
    globaladdr++;
    globaladdr = globaladdr % MAX ;
getglobal:
    atomic{
       sendmsg.srcIp = linklocaladdr;/*link local*/ 
       sendmsg.dstMac = 0;/*servermac*/
       sendmsg.dstIp = 0; /*serverip*/ 
       sendmsg.target = globaladdr;  
       bounded[interfaceId] = false; 
       boundedAddr[interfaceId] = 255;
sendreq: if
       ::c_sv!request,sendmsg,interfaceId;  
       ::c_sv!confirm,sendmsg,interfaceId;
       fi;     
    }
receive1: /*wait for reply*/
    sv_c[interfaceId]?mtp,recvmsg,_;/*Do not consider timeout retransmission*/
    if
    ::mtp == reply && recvmsg.target == globaladdr->
      atomic{
       sendmsg.srcIp = 0;/*all 0*/ 
       /*The destination address and mac are the broadcast mac and dad_ns addresses, which are set to the default value 0.*/
       sendmsg.dstMac = 0;
       sendmsg.dstIp = 0;
       sendmsg.target = globaladdr;
       /*send dad_ns for globaladdr*/
       c_sv!dad_ns,sendmsg,interfaceId;       
      }
      /*relay*/   
      do	
      ::tmp > 4 -> goto receive2;
      ::else ->tmp++;
      od;
    ::mtp ==notonlink && recvmsg.target == globaladdr->
      goto newgloabalIp;
    ::else->goto receive1;
    fi;
receive2:
    if
    ::sv_c[interfaceId]?mtp,recvmsg,_->
      if
      :: mtp == na && recvmsg.target == globaladdr->
         atomic{
         sendmsg.srcIp = globaladdr;/*地址*/ 
         sendmsg.dstMac = 0;/*servermac*/
         sendmsg.dstIp = 0; /*serverip*/ 
         sendmsg.target = globaladdr;  
         c_sv!decline,sendmsg,interfaceId;
         goto dec;
         }
      ::else->goto receive2;
      fi;                
    ::timeout->
progress0:
      if
      ::multichan??dad_ns,recvmsg,eval(interfaceId)->skip;
      ::timeout->skip;
      fi;
      bounded[interfaceId] = true;
      boundedAddr[interfaceId] = globaladdr;
      c_sv!tt,sendmsg,interfaceId;/*告诉savi可以超时了*/      
      if
      ::goto using; /*release or using*/
      ::goto using;
      fi;    
    fi;
dec:
    sv_c[interfaceId]?mtp,recvmsg,_;  
    if
    ::mtp==reply&&recvmsg.target==globaladdr->goto newgloabalIp;
    ::mtp==nobinding&&recvmsg.target==globaladdr->goto newgloabalIp;
    ::else->goto dec;
    fi;	
rel:
    atomic{
    sendmsg.srcIp = globaladdr;/*addr*/ 
    sendmsg.dstMac = 0;/*servermac*/
    sendmsg.dstIp = 0; /*serverip*/ 
    sendmsg.target = globaladdr;  
    c_sv!release,sendmsg,interfaceId;  	
    }
relrecv: 
    sv_c[interfaceId]?mtp,recvmsg,_;
    if
    ::mtp==reply&&recvmsg.target==globaladdr->
      bounded[interfaceId] = false;   
      boundedAddr[interfaceId] = 255;
      if
      ::goto newgloabalIp;
      ::goto stop;
      fi;
    ::mtp==nobinding&&recvmsg.target==globaladdr->
      bounded[interfaceId] = false;   
      boundedAddr[interfaceId] = 255;
      goto newgloabalIp;
    ::else->goto relrecv;
    fi;
using:     	
    printf("client  %d is using %d\n",interfaceId,globaladdr);    
    if
    :: (bounded[interfaceId] &&  (IPs[globaladdr]==1))->attackSuccess=false;
    ::else->attackSuccess=true;
    fi;
endclient:
    atomic{
       sendmsg.srcIp = globaladdr;
    }
    c_sv!ping,sendmsg,interfaceId;
    /*relay*/
    tmp = 0;
    do
    ::tmp >4 ->break;
    ::else ->tmp++;
    od;
    sv_c[interfaceId]?mtp,recvmsg,_;
progressclient :        
    do
    ::multichan ?? <dad_ns,recvmsg,tmp>->  /*target*/
      if
      ::(recvmsg.target == globaladdr || recvmsg.target == linklocaladdr) && tmp != interfaceId->
        atomic{   
	multichan ?? dad_ns,recvmsg,eval(tmp);
        sendmsg.srcIp = recvmsg.target;
        sendmsg.srcMac = mac;
        sendmsg.target = recvmsg.target;
        sendmsg.dstMac = tmp; /*This field is used to record which client is performing duplicate address detection.*/
      	c_sv!na,sendmsg,interfaceId; /*send to savi*/
        }
      ::else->goto endclient;
      fi;
    ::sv_c[interfaceId]?mtp,recvmsg,_->printf("get a msg\n");goto endclient;
    ::timeout->goto endclient;
    od;
stop:   
    printf("end client process\n");  

}

/*server<->savi*/
proctype server(){    
    MESSAGE recvmsg;
    MESSAGE sendmsg;
    byte cid = 0; 
    byte mtp = 0;
    byte target = 0;
endserver:
do::
    sv_ss?mtp,recvmsg,cid;
    target = recvmsg.target; 
    if
    ::mtp == ping ->
      /*The server receives a data message, the source address of which must be bound*/
      if
      ::((table[recvmsg.srcIp].state == bound||table[recvmsg.srcIp].state == tobeDelete)  && table[recvmsg.srcIp].mac == recvmsg.srcMac && table[recvmsg.srcIp].anc== cid) ->
		attackSuccess = false;
      ::else->attackSuccess = true;
      fi;
      ss_sv!pingreply,recvmsg,cid;
    ::mtp == solicit->
      ss_sv!advertise,recvmsg,cid;
    ::mtp == request || mtp == confirm->
      if
      ::IPs[target]==1->ss_sv!notonlink,recvmsg,cid;
      ::IPs[target]==0->
        atomic{IPs[target]=1;ss_sv!reply,recvmsg,cid;assignedIpCount++;}
      fi; 
    ::mtp == decline->
      if
      ::IPs[target]==1->
	atomic{IPs[target]=0;
	   ss_sv!reply,recvmsg,cid;assignedIpCount--;
        }
      ::IPs[target]==0->ss_sv!nobinding,recvmsg,cid;
      fi;
    ::mtp == release->
      if
      ::IPs[target]==1->
	atomic{IPs[target]=0;
	   ss_sv!reply,recvmsg,cid;assignedIpCount--;
        }
      ::IPs[target]==0->ss_sv!nobinding,recvmsg,cid;
      fi;
    ::else->skip; 
    fi;  
od;            	     
}

proctype savi(){
    mtype mtp;
    MESSAGE recvmsg;
    byte anc,mac,ip;
    /*Enable filtering rules*/
endsavi:do
  ::c_sv?mtp,recvmsg,anc; /*Receive information from the client. If the address has been bound, two ports apply for the same address*/
    printf("first:the state of 2 is %e<->%d\n",table[2].state,table[2].state);
    mac = recvmsg.srcMac;
    ip = recvmsg.target;
    if
    ::mtp == ping->
      if
      ::table[recvmsg.srcIp].state == bound && table[recvmsg.srcIp].mac == mac && table[recvmsg.srcIp].anc== anc->skip;
      ::else->mtp=tt;goto fwd; /*Verification failed*/
      fi;
    ::mtp == request || mtp == confirm ->
      /*link local address must be bound*/
      if
      ::table[recvmsg.srcIp].state == bound && table[recvmsg.srcIp].mac == mac && table[recvmsg.srcIp].anc== anc->skip;/*Verification passed*/
      ::else->mtp=tt;goto fwd; /*Verification failed, tt means not forwarding*/
      fi;
      printf("the state of %d is %d\n",ip,table[ip].state);
      if
      ::table[ip].state !=0 && table[ip].state != begin && table[ip].anc != anc -> sv_c[anc]!notonlink,recvmsg,anc;mtp=tt;
      ::table[ip].state !=0 && table[ip].state != begin && table[ip].anc == anc -> mtp=tt; 
      ::else->       
     	atomic{
        table[ip].anc = anc;
        table[ip].mac = mac;
        table[ip].address = ip;
        table[ip].state = start;
        }
      fi;      
      printf("now the state of %d is %d\n",ip,table[ip].state);
    ::mtp == dad_ns->
      /*The source address must be all 0s. To reduce the state space*/
      atomic{
      table[ip].anc = anc;
      table[ip].mac = mac;
      table[ip].address = ip;
      table[ip].state = detection;
      multichan!mtp,recvmsg,anc; /*Broadcast the message*/
      }      
    ::mtp == tt ->
      if
      ::table[ip].state == detection -> 
        table[ip].state = bound;
        /*Consistency check: For global addresses: the client, savi and server IP addresses are consistent.*/
        if
        ::ip<MAX->
        assert(bounded[anc] && IPs[ip] && table[ip].mac == recvmsg.srcMac && table[ip].anc == anc);
        ::else->skip;
        fi;
      ::else->skip;
      fi;
    :: mtp == release->/*Simulate protocol specification settings: do not filter release and decline, do not filter delete binding*/
      table[ip].state = tobeDelete;      
    :: mtp == decline->
      table[ip].state = tobeDelete;
      printf("receive decline %e<->%d\n",table[ip].state,table[ip].state);
    ::mtp == na->
      if
      ::table[recvmsg.target].state == bound && table[recvmsg.target].mac == mac && table[recvmsg.target].anc== anc ->skip;
      ::else->goto fwd;
      fi;
      if
      ::table[ip].state == detection ->table[ip].state = begin;sv_c[recvmsg.dstMac]!mtp,recvmsg,recvmsg.dstMac;
      ::else->goto fwd;
      fi;      
    ::else->skip;
    fi;    
fwd:    if
    ::mtp != dad_ns && mtp != tt && mtp != na && mtp != notonlink ->sv_ss!mtp,recvmsg,anc; 
    ::else->skip;
    fi;
  ::ss_sv?mtp,recvmsg,anc;
    ip = recvmsg.target;
    if
    ::mtp == reply->
      if
      ::table[ip].state == start->table[ip].state = live;
      ::table[ip].state == tobeDelete -> table[ip].state = begin;
      fi;
    ::else->skip;
    fi;
    sv_c[anc]!mtp,recvmsg,anc;    
od;
}

/*The attacker process attacks under the condition of binding itself*/
proctype intruder(byte interfaceId){    
    /*init msg:the value of mac,target = interfaceId*/
    atomic{
        byte mac = interfaceId;
        byte linklocaladdr =  MAX + interfaceId;
        byte globaladdr = interfaceId ;
        byte mtp; /*msg type*/
        byte tmp,anc,lastTarget;
        MESSAGE sendmsg;
        sendmsg.srcMac = mac;
        MESSAGE recvmsg;
    }
  
newllip:
    linklocaladdr++;
    linklocaladdr = linklocaladdr % MAX + MAX ;
    /*Unbound source address, send a ping message*/
    sendmsg.srcIp = linklocaladdr;
    c_sv!ping,sendmsg,interfaceId;
getlinklocal:
    atomic{
       sendmsg.srcIp = 0;/*全0*/ 
       sendmsg.dstMac = 0;
       sendmsg.dstIp = 0;
       sendmsg.target = linklocaladdr;
       /*发送dad_ns for link-local*/
       c_sv!dad_ns,sendmsg,interfaceId;       
    }
    /*relay*/
    do
    ::tmp >4 ->break;
    ::else ->tmp++;
    od;
receive0:
    if
    ::sv_c[interfaceId]?mtp,recvmsg,_->
      if
      ::mtp == na && recvmsg.target == linklocaladdr ->goto  newllip;/*get a new linklocal addr*/
      fi;
    ::timeout->
      if
      ::multichan??[dad_ns,recvmsg,eval(interfaceId)]->multichan??dad_ns,recvmsg,eval(interfaceId);
      ::else->skip;
      fi;
      c_sv!tt,sendmsg,interfaceId;
    fi;
newgloabalIp:
    globaladdr++;
    globaladdr = globaladdr % MAX ;
getglobal:
    atomic{
       sendmsg.srcIp = linklocaladdr;/*local link*/ 
       sendmsg.dstMac = 0;/*servermac*/
       sendmsg.dstIp = 0; /*serverip*/ 
       sendmsg.target = globaladdr;   
       bounded[interfaceId] = false;   
       boundedAddr[interfaceId] = 255;
sendreq:c_sv!request,sendmsg,interfaceId;   
    }
receive1: /*wait for reply*/
    sv_c[interfaceId]?mtp,recvmsg,_;
    if
    ::mtp == reply && recvmsg.target == globaladdr->
      atomic{
       sendmsg.srcIp = 0;/*all 0*/ 
       /*The destination address and mac are the broadcast mac and dad_ns addresses, which are set to the default value 0.*/
       sendmsg.dstMac = 0;
       sendmsg.dstIp = 0;
       sendmsg.target = globaladdr;
       /*send dad_ns for globaladdr*/
       c_sv!dad_ns,sendmsg,interfaceId;       
      }
      /*relay*/   
      tmp = 0;
      do	
      ::tmp > 4 -> goto receive2;
      ::else ->tmp++;
      od;
    ::mtp ==notonlink && recvmsg.target == globaladdr->
      goto newgloabalIp;
    ::else->goto receive1;
    fi;
receive2:
    if
    ::sv_c[interfaceId]?mtp,recvmsg,_->
      if
      :: mtp == na && recvmsg.target == globaladdr->
         atomic{
         sendmsg.srcIp = globaladdr;/*addr*/ 
         sendmsg.dstMac = 0;/*servermac*/
         sendmsg.dstIp = 0; /*serverip*/ 
         sendmsg.target = globaladdr;  
         c_sv!decline,sendmsg,interfaceId;
         goto dec;
         }
      ::else->goto receive2;
      fi;                
    ::timeout->
progress0:
      if
      ::multichan??dad_ns,recvmsg,eval(interfaceId)->skip;
      ::timeout->skip;
      fi;
      atomic{
      bounded[interfaceId] = true;  
      boundedAddr[interfaceId] = globaladdr;   
      c_sv!tt,sendmsg,interfaceId;
      }
      if
      ::goto attack; /*release*/
      fi;    
    fi;
dec:
    sv_c[interfaceId]?mtp,recvmsg,_;  
    if
    ::mtp==reply&&recvmsg.target==globaladdr->goto newgloabalIp;
    ::mtp==nobinding&&recvmsg.target==globaladdr->goto newgloabalIp;
    ::else->goto dec;
    fi;
attack:	
    printf("intruder  %d is using %d,now to attack\n",interfaceId,globaladdr);  
    
    /*send ping*/
    sendmsg.srcIp = globaladdr;
    c_sv!ping,sendmsg,interfaceId;   
    sv_c[interfaceId]?pingreply,recvmsg,_;    
endintruder:  
  do /*Sniff messages sent by other clients*/
  ::c_sv?<request,recvmsg,anc> ->
    if
    ::lastTarget != request ->
      c_sv!notonlink,recvmsg,interfaceId; /*Pretend to be a server and declare that the address cannot be assigned*/      
      c_sv!decline,recvmsg,interfaceId;lastTarget = request;/*forge decline*/
    ::else->goto progress;
    fi;
  ::c_sv?<confirm,recvmsg,anc> ->
    if
    ::lastTarget != confirm -> 
      /*Forged source address to send data packets*/
      c_sv!ping,recvmsg,interfaceId;
      c_sv!decline,recvmsg,interfaceId;lastTarget = confirm;
    ::else->goto progress;
    fi;
  ::c_sv?<ping,recvmsg,anc> ->
    if
    ::lastTarget != ping -> 
      c_sv!ping,recvmsg,interfaceId;
      c_sv!decline,recvmsg,interfaceId;lastTarget = ping;
    ::else->goto progress;
    fi;
    ::multichan?<dad_ns,recvmsg,anc> ->
     if
    ::recvmsg.target < MAX->
        atomic{
        multichan?dad_ns,recvmsg,anc;   
        recvmsg.dstMac = anc; 
       
        c_sv!ping,recvmsg,interfaceId;
        c_sv!na,recvmsg,interfaceId;
        lastTarget = dad_ns;
        }
    fi;
  od;
progress:   
   goto endintruder;  
}




init{
 	
   run server();
   run savi();
   run intruder(2);
   run client(0);
   
  
}
