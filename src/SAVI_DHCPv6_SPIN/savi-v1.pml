/*client<->savi<->server*/
#define MAX 8 /*ip count , [0-MAX]:global address,[MAX-2*MAX] link-local address*/
#define MM 16  /*double of max*/
#define COUNT 4 /*savi interface count*/
#define N 2  /*count of client*/


/*message type define*/
mtype = {solicit,advertise,request,confirm,reply,release,decline};
mtype = {dad_ns,na,tt,notonlink,nobinding};  
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


bit IPs[MAX] /*ip pool in dhcp server: global address*/
BST table[MM]; 

/*1~2Client,1server,1savi,1intruder(maybe)*/
/*chan:client<->savi server<->savi intrucer<->savi multichan*/

/*channel from client to savi is only one*/
chan c_sv = [N] of {mtype,MESSAGE,byte}; /*client->savi:type,msg,clientid*/
chan sv_c[COUNT] = [N] of {mtype,MESSAGE,byte}; /*savi->client:the index of channel <-> interface number*/
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
       sendmsg.srcIp = 0;/*ȫ0*/ 
       sendmsg.dstMac = 0;
       sendmsg.dstIp = 0;
       sendmsg.target = linklocaladdr;
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
      multichan??dad_ns,recvmsg,eval(interfaceId);
      c_sv!tt,sendmsg,interfaceId;
    fi;
newgloabalIp:
    globaladdr++;
    globaladdr = globaladdr % MAX ;
getglobal:
    atomic{
       sendmsg.srcIp = linklocaladdr;
       sendmsg.dstMac = 0;/*servermac*/
       sendmsg.dstIp = 0; /*serverip*/ 
       sendmsg.target = globaladdr;     
sendreq: if
       ::c_sv!request,sendmsg,interfaceId;  
       ::c_sv!confirm,sendmsg,interfaceId;
       fi;     
    }
receive1: /*wait for reply*/
   if
   ::sv_c[interfaceId]?mtp,recvmsg,_;
    if
    ::mtp == reply && recvmsg.target == globaladdr->
      atomic{
       sendmsg.srcIp = 0;/*ȫ0*/ 
       sendmsg.dstMac = 0;
       sendmsg.dstIp = 0;
       sendmsg.target = globaladdr;
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
    ::timeout->goto sendreq; 
   fi;
receive2:
    if
    ::sv_c[interfaceId]?mtp,recvmsg,_->
      if
      :: mtp == na && recvmsg.target == globaladdr->
         atomic{
         sendmsg.srcIp = globaladdr; 
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
      c_sv!tt,sendmsg,interfaceId;
      if
      ::goto rel; /*release*/
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
    sendmsg.srcIp = globaladdr;
    sendmsg.dstMac = 0;/*servermac*/
    sendmsg.dstIp = 0; /*serverip*/ 
    sendmsg.target = globaladdr;  
    c_sv!release,sendmsg,interfaceId;  	
    }
relrecv: 
    sv_c[interfaceId]?mtp,recvmsg,_;
    if
    ::mtp==reply&&recvmsg.target==globaladdr->
      if
      ::goto newgloabalIp;
      ::goto stop;
      fi;
    ::mtp==nobinding&&recvmsg.target==globaladdr->goto newgloabalIp;
    ::else->goto relrecv;
    fi;
using:	
    printf("client  %d is using %d\n",interfaceId,globaladdr);  
endclient:
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
        sendmsg.dstMac = tmp; 
      	c_sv!na,sendmsg,interfaceId; 
        }
      ::else->skip;
      fi;
    ::sv_c[interfaceId]?mtp,recvmsg,_->printf("get a msg\n");
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
    ::mtp == solicit->
      ss_sv!advertise,recvmsg,cid;
    ::mtp == request || mtp == confirm->
      if
      ::IPs[target]==1->ss_sv!notonlink,recvmsg,cid;
      ::IPs[target]==0->
        atomic{IPs[target]=1;ss_sv!reply,recvmsg,cid;}
      fi; 
    ::mtp == decline->
      if
      ::IPs[target]==1->IPs[target]=1;/*to be or not  to be ,it is a problem*/
        ss_sv!reply,recvmsg,cid;
      ::IPs[target]==0->ss_sv!nobinding,recvmsg,cid;
      fi;
    ::mtp == release->
      if
      ::IPs[target]==1->
	atomic{IPs[target]=0;
	   ss_sv!reply,recvmsg,cid;
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
endsavi:do
  ::c_sv?mtp,recvmsg,anc; 
    printf("first:the state of 2 is %e<->%d\n",table[2].state,table[2].state);
    mac = recvmsg.srcMac;
    ip = recvmsg.target;
    if
    ::mtp == request || mtp == confirm->
      if
      ::table[recvmsg.srcIp].state == bound && table[recvmsg.srcIp].mac == mac && table[recvmsg.srcIp].anc== anc->skip;
      ::else->mtp=tt;goto fwd; 
      fi;
      printf("the state of %d is %d\n",ip,table[ip].state);
      if
      ::table[ip].state !=0 && table[ip].state != begin-> sv_c[anc]!notonlink,recvmsg,anc;mtp=tt;
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
      atomic{
      table[ip].anc = anc;
      table[ip].mac = mac;
      table[ip].address = ip;
      table[ip].state = detection;
      multichan!mtp,recvmsg,anc; 
      }      
    ::mtp == tt ->
      if
      ::table[ip].state == detection -> table[ip].state = bound;
      ::else->skip;
      fi;
    :: mtp == release->
      if
      ::table[recvmsg.srcIp].state == bound && table[recvmsg.srcIp].mac == mac && table[recvmsg.srcIp].anc== anc->table[ip].state = tobeDelete;
      ::else->mtp = tt;
      fi;
    :: mtp == decline->
      if
      ::table[ip].state !=0 && table[recvmsg.srcIp].state != begin && table[recvmsg.srcIp].mac == mac && table[recvmsg.srcIp].anc== anc->table[ip].state = tobeDelete;
      ::else->mtp = tt;
      fi;
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
    ::mtp != dad_ns && mtp != tt && mtp != na->sv_ss!mtp,recvmsg,anc; 
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


init{
   run server();
   run savi();
   run client(0);
   run client(1);
}
