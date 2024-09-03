/*client<->savi<->server*/
#define MAX 8 /*ip count , [0-MAX]:global address,[MAX-2*MAX] link-local address*/
#define MM 16  /*double of max*/
#define N 4  /*savi interface count<->count of client(intruder includer)*/
#define a1 bounded[0]
#define a4 (assignedIpCount < MAX) 
#define conflict !(bounded[0]&&bounded[1]&&(boundedAddr[0]==boundedAddr[1]))
bool bounded[N];
byte boundedAddr[N];
byte assignedIpCount;

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

bit IPs[MAX] /*ip pool in dhcp server: global address*/
BST table[MM];

/*1~2Client,1server,1savi,1intruder(maybe)*/
/*chan:client<->savi server<->savi intrucer<->savi multichan*/

/*channel from client to savi is only one*/
chan c_sv = [MAX] of {mtype,MESSAGE,byte};

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

       sendmsg.dstMac = 0;
       sendmsg.dstIp = 0;
       sendmsg.target = linklocaladdr;
       /*发送dad_ns for link-local*/
       c_sv!dad_ns,sendmsg,interfaceId;       
    }
    /*relay*/
    tmp = 0;
    do
    ::tmp >4 ->break;
    ::else ->tmp++;
    od;
    /*是否收到na*/
receive0:
    if
    ::sv_c[interfaceId]?mtp,recvmsg,_->
      if
      ::mtp == na && recvmsg.target == linklocaladdr ->goto  newllip;/*get a new linklocal addr*/
      fi;
    ::timeout->
      if
      ::multichan??[dad_ns,recvmsg,eval(interfaceId)]->multichan??dad_ns,recvmsg,eval(interfaceId);/*绑定了linklocal地址*/
      ::else->skip;
      fi;
      c_sv!tt,sendmsg,interfaceId;/*告诉savi可以超COUNT 时了*/
    fi;
/*开始global地址的绑定:request/reply/dadns过程，此处略去了solicit过程*/
newgloabalIp:
    globaladdr++;
    globaladdr = globaladdr % MAX ;
getglobal:
    atomic{
       sendmsg.srcIp = linklocaladdr;/*本地地址*/ 
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
    sv_c[interfaceId]?mtp,recvmsg,_;/*不考虑超时重发*/
    if
    ::mtp == reply && recvmsg.target == globaladdr->
      atomic{
       sendmsg.srcIp = 0;/*全0*/ 
       /*目的地址和mac是广播的mac和dad_ns地址，此处设为默认值0*/
       sendmsg.dstMac = 0;
       sendmsg.dstIp = 0;
       sendmsg.target = globaladdr;
       /*发送dad_ns for globaladdr*/
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
    sendmsg.srcIp = globaladdr;/*地址*/ 
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
endclient:
progressclient :  
    do
    ::multichan ?? <dad_ns,recvmsg,tmp>->  /*target*/
      if
      ::(recvmsg.target == globaladdr || recvmsg.target == linklocaladdr) && tmp != interfaceId->
        /*这里实现其实还是有点问题，在绑定全局地址后再监听linklocal地址的重复检测。但为了简便起见，设置如此*/
        atomic{   
	multichan ?? dad_ns,recvmsg,eval(tmp);
        sendmsg.srcIp = recvmsg.target;
        sendmsg.srcMac = mac;
        sendmsg.target = recvmsg.target;
        sendmsg.dstMac = tmp; /*这个字段用来记录是哪个客户端在进行重复地址检测*/
      	c_sv!na,sendmsg,interfaceId; /*发送给savi*/
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
    target = recvmsg.target; /*注意下标*/
    if
    ::mtp == ping ->
      /*服务器收到数据报文，该报文的源地址必须已绑定*/
      assert(table[recvmsg.srcIp].state == bound  && table[recvmsg.srcIp].mac == recvmsg.srcMac && table[recvmsg.srcIp].anc== cid);
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
      ::IPs[target]==1->IPs[target]=1;/*to be or not  to be ,it is a problem*/
        ss_sv!reply,recvmsg,cid;
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
    /*启动过滤规则*/
endsavi:do
  ::c_sv?mtp,recvmsg,anc; /*从客户端接受信息，如果地址已经绑定，两个端口申请同一个地址：先到先得？*/
    printf("first:the state of 2 is %e<->%d\n",table[2].state,table[2].state);
    mac = recvmsg.srcMac;
    ip = recvmsg.target;
    if
    ::mtp == ping->
      if
      ::table[recvmsg.srcIp].state == bound && table[recvmsg.srcIp].mac == mac && table[recvmsg.srcIp].anc== anc->skip;
      ::else->mtp=tt;goto fwd; /*验证不通过*/
      fi;
    ::mtp == request || mtp == confirm ->
      /*link local地址必须已经绑定*/
      if
      ::table[recvmsg.srcIp].state == bound && table[recvmsg.srcIp].mac == mac && table[recvmsg.srcIp].anc== anc->skip;/*验证通过*/
      ::else->mtp=tt;goto fwd; /*验证不通过*/
      fi;
      /*当要申请的地址已经被占用了，则直接告诉客户端换地址，虽然此处与实际稍微不符，但不影响正常的流程*/
      printf("the state of %d is %d\n",ip,table[ip].state);
      if
      ::table[ip].state !=0 && table[ip].state != begin && table[ip].anc != anc -> sv_c[anc]!notonlink,recvmsg,anc;mtp=tt;/*不让转发而已，无逻辑上的意义*/
      ::table[ip].state !=0 && table[ip].state != begin && table[ip].anc == anc -> mtp=tt; /*客户端重复发送相同的请求，忽略掉*/
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
      /*源地址必须为全0，为减少状态空间，此处暂时不加*/
      atomic{
      table[ip].anc = anc;
      table[ip].mac = mac;
      table[ip].address = ip;
      table[ip].state = detection;
      /*计算timeout不好设置，此处这样替代：让客户端来做，如果客户端发送dad_ns后没有收到na，则它发送一个timeout给savi?*/
      multichan!mtp,recvmsg,anc; /*将消息广播出去*/
      }      
    ::mtp == tt ->
      if
      ::table[ip].state == detection -> 
        table[ip].state = bound;
        /*一致性检测：对于global地址：客户端，savi与服务端的IP使用保持一致*/
        if
        ::ip<MAX->
        assert(bounded[anc] && IPs[ip] && table[ip].mac == recvmsg.srcMac && table[ip].anc == anc);
        ::else->skip;
        fi;
      ::else->skip;
      fi;
    :: mtp == release->/*绑定后才删*/
      if
      ::table[recvmsg.srcIp].state == bound && table[recvmsg.srcIp].mac == mac && table[recvmsg.srcIp].anc== anc->table[ip].state = tobeDelete;
      ::else->mtp = tt;/*验证不通过则丢掉*/
      fi;
    :: mtp == decline->/*任何时候都删*/
      if
      ::table[ip].state !=0 && table[recvmsg.srcIp].state != begin && table[recvmsg.srcIp].mac == mac && table[recvmsg.srcIp].anc== anc->table[ip].state = tobeDelete;
      ::else->mtp = tt;/*验证不通过则丢掉*/
      fi;
    ::mtp == na->
      /*na的target,源地址必须已经绑定*/
      if
      ::table[recvmsg.target].state == bound && table[recvmsg.target].mac == mac && table[recvmsg.target].anc== anc ->skip;
      ::else->goto fwd;
      fi;
      if
      ::table[ip].state == detection ->table[ip].state = begin;sv_c[recvmsg.dstMac]!mtp,recvmsg,recvmsg.dstMac;
      /*转发给客户端,注意，转发给哪个客户端的数值被发送na的写在recvmsg.dstMac位置上*/
      ::else->goto fwd;
      fi;      
    ::else->skip;
    fi;    
fwd:    if
    ::mtp != dad_ns && mtp != tt && mtp != na && mtp != notonlink ->sv_ss!mtp,recvmsg,anc; /*dad_ns,na和tt就不转发了*/
    ::else->skip;
    fi;
  ::ss_sv?mtp,recvmsg,anc;/*从服务端接收信息：trust口*/
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

/*攻击者进程,自身绑定的条件下进行攻击*/
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
  
    /*link-local无request/reply过程，所以在server中没有记录，global在dhcpserver有记录:省却solicit和advertise过程*/	
newllip:
    linklocaladdr++;
    linklocaladdr = linklocaladdr % MAX + MAX ;
    /*未绑定源地址，发一个ping报文*/
    sendmsg.srcIp = linklocaladdr;
    c_sv!ping,sendmsg,interfaceId;
getlinklocal:
    atomic{
       sendmsg.srcIp = 0;/*全0*/ COUNT 
       /*目的地址和mac是广播的mac和dad_ns地址，此处设为默认值0*/
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
    /*是否收到na*/
receive0:
    if
    ::sv_c[interfaceId]?mtp,recvmsg,_->
      if
      ::mtp == na && recvmsg.target == linklocaladdr ->goto  newllip;/*get a new linklocal addr*/
      fi;
    ::timeout->
      if
      ::multichan??[dad_ns,recvmsg,eval(interfaceId)]->multichan??dad_ns,recvmsg,eval(interfaceId);/*绑定了linklocal地址*/
      ::else->skip;
      fi;
      c_sv!tt,sendmsg,interfaceId;/*告诉savi可以超时了*/
    fi;
/*开始global地址的绑定:request/reply/dadns过程，此处略去了solicit过程*/
newgloabalIp:
    globaladdr++;
    globaladdr = globaladdr % MAX ;
getglobal:
    atomic{
       sendmsg.srcIp = linklocaladdr;/*本地地址*/ 
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
       sendmsg.srcIp = 0;/*全0*/ 
       /*目的地址和mac是广播的mac和dad_ns地址，此处设为默认值0*/
       sendmsg.dstMac = 0;
       sendmsg.dstIp = 0;
       sendmsg.target = globaladdr;
       /*发送dad_ns for globaladdr*/
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
      atomic{
      bounded[interfaceId] = true;  
      boundedAddr[interfaceId] = globaladdr;   
      c_sv!tt,sendmsg,interfaceId;/*告诉savi可以超时了*/
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
    
    /*发送ping报文*/
    sendmsg.srcIp = globaladdr;
    c_sv!ping,sendmsg,interfaceId;   
    sv_c[interfaceId]?pingreply,recvmsg,_;    
endintruder:  
  do /*嗅探其他客户端发送的消息*/
  ::c_sv?<request,recvmsg,anc> ->
    if
    ::lastTarget != recvmsg.target ->
      c_sv!notonlink,recvmsg,interfaceId; /*伪造成服务器，宣告该地址无法分配*/      
      c_sv!decline,recvmsg,interfaceId;lastTarget = recvmsg.target;/*伪造decline报文*/
    ::else->goto progress;
    fi;
  ::c_sv?<confirm,recvmsg,anc> ->
    if
    ::lastTarget != recvmsg.target -> 
      /*伪造源地址发送数据报文*/
      c_sv!ping,recvmsg,interfaceId;
      c_sv!decline,recvmsg,interfaceId;lastTarget = recvmsg.target;/*伪造decline报文*/
    ::else->goto progress;
    fi;
  ::multichan?<dad_ns,recvmsg,anc> ->
    atomic{
    multichan?dad_ns,recvmsg,anc;
    recvmsg.dstMac = anc; 
    /*伪造源地址发送数据报文*/
    c_sv!ping,recvmsg,interfaceId;
    c_sv!na,recvmsg,interfaceId;
    lastTarget = recvmsg.target;
    }
  od;
progress:   
   goto endintruder;  
}




init{
 	
   run server();
   run savi();
   run client(0);
   run intruder(1);
   
}
