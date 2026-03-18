#!/usr/bin/env python3
import struct, binascii
from .wifi import *
from Crypto.Cipher import AES, ARC4
from scapy.layers.dot11 import Dot11, Dot11CCMP, Dot11QoS
import zlib


def rsn_prf_sha1(key, label, B, numbytes):
	numbytes = 64
	output = b''
	for i in range(math.ceil(numbytes / 20)):
		data = label + b'\x00' + B + struct.pack("<B", i)
		hmacsha1 = hmac.new(key, data, hashlib.sha1)
		output += hmacsha1.digest()
	return output[:numbytes]


def aes_wrap_key(kek, plaintext, iv=0xa6a6a6a6a6a6a6a6):
	n = len(plaintext)//8
	R = [None]+[plaintext[i*8:i*8+8] for i in range(0, n)]
	A = iv
	encrypt = AES.new(kek, AES.MODE_ECB).encrypt
	for j in range(6):
		for i in range(1, n+1):
			B = encrypt(struct.pack(">Q", A) + R[i])
			A = struct.unpack(">Q", B[:8])[0] ^ (n*j + i)
			R[i] = B[8:]
	return struct.pack(">Q", A) + b"".join(R[1:])


def aes_wrap_key_withpad(kek, plaintext):
	num_padding = (8 - len(plaintext)) % 8
	log(STATUS, f"Number of padding bytes: {num_padding}")
	if num_padding >= 1:
		plaintext += b"\xdd"
		plaintext += b"\x00" * (num_padding - 1)
	return aes_wrap_key(kek, plaintext)


def pn2bytes(pn):
	pn_bytes = [0] * 6
	for i in range(6):
		pn_bytes[i] = pn & 0xFF
		pn >>= 8
	return pn_bytes


def pn2bin(pn):
	return struct.pack(">Q", pn)[2:]


def dot11ccmp_get_pn(p):
	pn = p.PN5
	pn = (pn << 8) | p.PN4
	pn = (pn << 8) | p.PN3
	pn = (pn << 8) | p.PN2
	pn = (pn << 8) | p.PN1
	pn = (pn << 8) | p.PN0
	return pn


def ccmp_get_nonce(priority, addr, pn):
	return struct.pack("B", priority) + addr2bin(addr) + pn2bin(pn)


def ccmp_get_aad(p, amsdu_spp=False):
	fc = raw(p)[:2]
	fc = struct.pack("<BB", fc[0] & 0x8f, fc[1] & 0xc7)
	sc = struct.pack("<H", p.SC & 0xf)
	addr1 = addr2bin(p.addr1)
	addr2 = addr2bin(p.addr2)
	addr3 = addr2bin(p.addr3)
	aad = fc + addr1 + addr2 + addr3 + sc
	if Dot11QoS in p:
		if not amsdu_spp:
			aad += struct.pack("<H", p[Dot11QoS].TID)
		else:
			aad += raw(p[Dot11QoS])[:2]
	return aad


def Raw(x):
	return x


def encrypt_ccmp(p, tk, pn, keyid=0, amsdu_spp=False):
	if len(tk) != 16:
		log(ERROR, f"encrypt_ccmp: key length is {len(tk)}, indicating CCMP isn't being used.")
		raise ValueError("CCMP requires a 16-byte key")
	p = p.copy()
	p.FCfield |= Dot11(FCfield="protected").FCfield
	if Dot11QoS in p:
		payload = raw(p[Dot11QoS].payload)
		p[Dot11QoS].remove_payload()
		if p[Dot11QoS].TID == None:
			p[Dot11QoS].TID = 0
		priority = p[Dot11QoS].TID
	else:
		payload = raw(p.payload)
		p.remove_payload()
		priority = 0
	newp = p/Dot11CCMP()
	pn_bytes = pn2bytes(pn)
	newp.PN0, newp.PN1, newp.PN2, newp.PN3, newp.PN4, newp.PN5 = pn_bytes
	newp.key_id = keyid
	newp.ext_iv = 1
	ccm_nonce = ccmp_get_nonce(priority, newp.addr2, pn)
	ccm_aad = ccmp_get_aad(newp, amsdu_spp)
	cipher = AES.new(tk, AES.MODE_CCM, ccm_nonce, mac_len=8)
	cipher.update(ccm_aad)
	ciphertext = cipher.encrypt(payload)
	digest = cipher.digest()
	newp = newp/Raw(ciphertext)
	newp = newp/Raw(digest)
	return newp


def decrypt_ccmp(p, tk, verify=True):
	p = p.copy()
	keyid = p.key_id
	priority = dot11_get_priority(p)
	pn = dot11ccmp_get_pn(p)
	fc = p.FCfield
	payload = get_ccmp_payload(p)
	if Dot11QoS in p:
		p[Dot11QoS].remove_payload()
	else:
		p.remove_payload()
	ccm_nonce = ccmp_get_nonce(priority, p.addr2, pn)
	ccm_aad = ccmp_get_aad(p)
	cipher = AES.new(tk, AES.MODE_CCM, ccm_nonce, mac_len=8)
	cipher.update(ccm_aad)
	plaintext = cipher.decrypt(payload[:-8])
	try:
		if verify:
			cipher.verify(payload[-8:])
	except ValueError:
		return None
	return p/LLC(plaintext)


def encrypt_wep(p, key, pn, keyid=0):
	p = p.copy()
	p.FCfield |= Dot11(FCfield="protected").FCfield
	if Dot11QoS in p:
		payload = raw(p[Dot11QoS].payload)
		p[Dot11QoS].remove_payload()
		if p[Dot11QoS].TID == None:
			p[Dot11QoS].TID = 0
		priority = p[Dot11QoS].TID
	else:
		payload = raw(p.payload)
		p.remove_payload()
		priority = 0
	payload += struct.pack("<I", zlib.crc32(payload) & 0xffffffff)
	iv = struct.pack(">I", pn)[1:]
	cipher = ARC4.new(iv + key)
	ciphertext = cipher.encrypt(payload)
	newp = p/iv/struct.pack("<B", keyid)/ciphertext
	return newp
